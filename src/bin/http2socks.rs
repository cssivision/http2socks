use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use async_pool::{Builder, ManageConnection, Pool};
use awak::net::{TcpListener, TcpStream};
use awak::time::timeout;
use awak::util::copy_bidirectional;
use base64::alphabet;
use base64::engine::general_purpose::PAD;
use base64::engine::GeneralPurpose;
use base64::Engine;
use bytes::Bytes;
use futures_util::io::{AsyncReadExt, AsyncWriteExt};
use futures_util::lock::Mutex;
use http_body_util::{combinators::BoxBody, BodyExt, Empty, Full};
use hyper::client::conn::http1::SendRequest;
use hyper::header::{HeaderValue, PROXY_AUTHORIZATION};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::upgrade::Upgraded;
use hyper::{Method, Request, Response};

use http2socks::args::parse_args;
use http2socks::rt::{HyperIo, HyperTimer};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);

fn other(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::Other, msg)
}

pub mod v5 {
    pub const VERSION: u8 = 5;
    pub const METH_NO_AUTH: u8 = 0;
    pub const CMD_CONNECT: u8 = 1;
    pub const TYPE_IPV4: u8 = 1;
    pub const TYPE_IPV6: u8 = 4;
    pub const TYPE_DOMAIN: u8 = 3;
    pub const REPLY_SUCESS: u8 = 0;
}

async fn handshake(conn: &mut TcpStream, dur: Duration, host: String, port: u16) -> io::Result<()> {
    let fut = async move {
        log::trace!("write socks5 version and auth method");
        let n_meth_auth: u8 = 1;
        conn.write_all(&[v5::VERSION, n_meth_auth, v5::METH_NO_AUTH])
            .await?;
        let buf1 = &mut [0u8; 2];

        log::trace!("read server socks version and mthod");
        conn.read_exact(buf1).await?;
        if buf1[0] != v5::VERSION {
            return Err(other("unknown version"));
        }
        if buf1[1] != v5::METH_NO_AUTH {
            return Err(other("unknow auth method"));
        }

        log::trace!("write socks5 version and command");
        conn.write_all(&[v5::VERSION, v5::CMD_CONNECT, 0u8]).await?;

        log::trace!("write address type and address");
        // write address
        let (address_type, mut address_bytes) = if let Ok(addr) = IpAddr::from_str(&host) {
            match addr {
                IpAddr::V4(v) => (v5::TYPE_IPV4, v.octets().to_vec()),
                IpAddr::V6(v) => (v5::TYPE_IPV6, v.octets().to_vec()),
            }
        } else {
            let domain_len = host.len() as u8;
            let mut domain_bytes = vec![domain_len];
            domain_bytes.extend_from_slice(&host.into_bytes());
            (v5::TYPE_DOMAIN, domain_bytes)
        };
        conn.write_all(&[address_type]).await?;
        address_bytes.extend_from_slice(&port.to_be_bytes());
        conn.write_all(&address_bytes).await?;

        log::trace!("read server response");
        let mut resp = vec![0u8; 4 + address_bytes.len()];
        conn.read_exact(&mut resp).await?;

        Ok(())
    };
    timeout(dur, fut).await?
}

// To try this example:
// 1. cargo run --example http_proxy
// 2. config http_proxy in command line
//    $ export http_proxy=http://127.0.0.1:8100
//    $ export https_proxy=http://127.0.0.1:8100
// 3. send requests
//    $ curl -i https://www.google.com/
fn main() -> io::Result<()> {
    env_logger::init();
    let config = parse_args("http2socks").unwrap();
    log::info!(
        "config: \n{}",
        toml::ser::to_string_pretty(&config).unwrap()
    );

    let local_addr: SocketAddr = config
        .local_addr
        .parse()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid local address"))?;
    let server_addr = config
        .server_addr
        .parse()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid server address"))?;

    let authorization = format!("{}:{}", config.username, config.password)
        .as_bytes()
        .to_vec();

    let client = Client::new();

    awak::block_on(async move {
        let listener = TcpListener::bind(&local_addr).await?;
        log::debug!("Listening on http://{}", local_addr);

        loop {
            let (stream, addr) = listener.accept().await?;
            log::debug!("accept stream from {:?}", addr);
            let io = HyperIo::new(stream);
            let authorization = authorization.clone();
            let client = client.clone();

            awak::spawn(async move {
                if let Err(err) = http1::Builder::new()
                    .preserve_header_case(true)
                    .title_case_headers(true)
                    .timer(HyperTimer::new())
                    .serve_connection(
                        io,
                        service_fn(|req| {
                            let authorization = authorization.clone();
                            let client = client.clone();
                            async move { proxy(client, req, server_addr, authorization).await }
                        }),
                    )
                    .with_upgrades()
                    .await
                {
                    log::error!("Failed to serve connection: {:?}", err);
                }
            })
            .detach();
        }
    })
}

fn proxy_authorization(authorization: &[u8], header_value: Option<&HeaderValue>) -> bool {
    if authorization == b":" {
        return true;
    }
    match header_value {
        Some(v) => match v.to_str().unwrap_or_default().strip_prefix("Basic ") {
            Some(v) => match GeneralPurpose::new(&alphabet::STANDARD, PAD).decode(v) {
                Ok(v) => v == authorization,
                Err(_) => false,
            },
            None => false,
        },
        None => false,
    }
}

fn empty() -> BoxBody<Bytes, hyper::Error> {
    Empty::<Bytes>::new()
        .map_err(|never| match never {})
        .boxed()
}

fn full<T: Into<Bytes>>(chunk: T) -> BoxBody<Bytes, hyper::Error> {
    Full::new(chunk.into())
        .map_err(|never| match never {})
        .boxed()
}

async fn proxy(
    client: Client,
    mut req: Request<hyper::body::Incoming>,
    server_addr: SocketAddr,
    authorization: Vec<u8>,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {
    log::debug!("req: {:?}", req);
    if !proxy_authorization(&authorization, req.headers().get(PROXY_AUTHORIZATION)) {
        log::error!("authorization fail");
        let mut resp = Response::new(empty());
        *resp.status_mut() = http::StatusCode::PROXY_AUTHENTICATION_REQUIRED;
        return Ok(resp);
    }
    let _ = req.headers_mut().remove(PROXY_AUTHORIZATION);

    if Method::CONNECT == req.method() {
        // Received an HTTP request like:
        // ```
        // CONNECT www.domain.com:443 HTTP/1.1
        // Host: www.domain.com:443
        // Proxy-Connection: Keep-Alive
        // ```
        //
        // When HTTP method is CONNECT we should return an empty body
        // then we can eventually upgrade the connection and talk a new protocol.
        //
        // Note: only after client received an empty body with STATUS_OK can the
        // connection be upgraded, so we can't return a response inside
        // `on_upgrade` future.
        if req.uri().authority().is_some() {
            let host = req.uri().host().map(|v| v.to_string()).unwrap_or_default();
            let port = req.uri().port_u16().unwrap_or(80);
            awak::spawn(async move {
                match hyper::upgrade::on(req).await {
                    Ok(upgraded) => {
                        if let Err(e) = tunnel(upgraded, host, port, server_addr).await {
                            log::error!("tunnel io error: {}", e);
                        };
                    }
                    Err(e) => log::error!("upgrade error: {}", e),
                }
            })
            .detach();
            Ok(Response::new(empty()))
        } else {
            log::error!("CONNECT host is not socket addr: {:?}", req.uri());
            let mut resp = Response::new(full("CONNECT must be to a socket address"));
            *resp.status_mut() = http::StatusCode::BAD_REQUEST;
            Ok(resp)
        }
    } else {
        match client.send_request(req, server_addr).await {
            Ok(res) => Ok(Response::new(res.boxed())),
            Err(e) => {
                let mut resp = Response::new(full(format!("proxy server interval error {:?}", e)));
                *resp.status_mut() = http::StatusCode::BAD_REQUEST;
                Ok(resp)
            }
        }
    }
}

// Create a TCP connection to host:port, build a tunnel between the connection and
// the upgraded connection
async fn tunnel(
    upgraded: Upgraded,
    host: String,
    port: u16,
    server_addr: SocketAddr,
) -> io::Result<()> {
    let mut upgraded = HyperIo::new(upgraded);
    let mut server = timeout(CONNECT_TIMEOUT, TcpStream::connect(server_addr)).await??;
    handshake(&mut server, CONNECT_TIMEOUT, host, port).await?;
    let (n1, n2) = copy_bidirectional(&mut upgraded, &mut server).await?;
    log::debug!("client wrote {} bytes and received {} bytes", n1, n2);
    Ok(())
}

struct SocksManager {
    addr: SocketAddr,
    host: String,
    port: u16,
}

impl ManageConnection for SocksManager {
    /// The connection type this manager deals with.
    type Connection = SendRequest<hyper::body::Incoming>;

    /// Attempts to create a new connection.
    async fn connect(&self) -> io::Result<Self::Connection> {
        let mut stream = timeout(CONNECT_TIMEOUT, TcpStream::connect(self.addr)).await??;
        handshake(&mut stream, CONNECT_TIMEOUT, self.host.clone(), self.port).await?;

        let (request_sender, connection) = hyper::client::conn::http1::Builder::new()
            .handshake(HyperIo::new(stream))
            .await
            .map_err(|e| other(&e.to_string()))?;

        awak::spawn(async move {
            if let Err(e) = connection.await {
                log::error!("Error in connection: {}", e);
            }
        })
        .detach();
        Ok(request_sender)
    }

    /// Check if the connection is still valid, check background every `check_interval`.
    ///
    /// A standard implementation would check if a simple query like `PING` succee,
    /// if the `Connection` is broken, error should return.
    async fn check(&self, _conn: &mut Self::Connection) -> io::Result<()> {
        Ok(())
    }
}

#[derive(Clone)]
struct Client {
    inner: Arc<Mutex<HashMap<SocketAddr, Pool<SocksManager>>>>,
}

impl Client {
    fn new() -> Client {
        Client {
            inner: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    // Create a TCP connection to host:port, build a tunnel between the connection and
    // the remote connection
    async fn send_request(
        &self,
        req: Request<hyper::body::Incoming>,
        addr: SocketAddr,
    ) -> io::Result<Response<hyper::body::Incoming>> {
        let host = req.uri().host().map(|v| v.to_string()).unwrap_or_default();
        let port = req.uri().port_u16().unwrap_or(80);
        log::debug!("proxy {}:{} to  {:?}", host, port, addr);

        let conn = SocksManager { addr, host, port };
        let mut inner = self.inner.lock().await;
        let pool = inner
            .entry(addr)
            .or_insert_with(|| Builder::new().build(conn))
            .clone();

        let mut request_sender = pool.get().await?;
        request_sender
            .send_request(req)
            .await
            .map_err(|e| other(&e.to_string()))
    }
}
