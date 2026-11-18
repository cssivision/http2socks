use std::future::poll_fn;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use std::task::{ready, Poll};
use std::time::Duration;

use async_pool::{Builder, ManageConnection, Pool};
use awak::net::{TcpListener, TcpStream};
use awak::time::timeout;
use awak::util::{copy_bidirectional_with_sizes, IdleTimeout};
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
use hyper::{Method, Request, Response};
use hyper_rt::{HyperIo, HyperTimer};
use lru_time_cache::LruCache;

use http2socks::args::parse_args;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
const DEFAULT_COPY_BUFFER_SIZE: usize = 8 * 1024;
const MAX_DESTINATION_POOLS: usize = 256;
const DESTINATION_POOL_TTL: Duration = Duration::from_secs(10 * 60);

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
            return Err(io::Error::other("unknown version"));
        }
        if buf1[1] != v5::METH_NO_AUTH {
            return Err(io::Error::other("unknow auth method"));
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
        // The reply is VER | REP | RSV | ATYP | BND.ADDR | BND.PORT.  The
        // reply's ATYP is chosen by the server and is independent of the
        // request's address type, so the number of bytes to read must be
        // derived from the reply itself, not from `address_bytes.len()`.
        let mut head = [0u8; 4];
        conn.read_exact(&mut head).await?;
        if head[0] != v5::VERSION {
            return Err(io::Error::other("unknown version"));
        }
        if head[1] != v5::REPLY_SUCESS {
            return Err(io::Error::other(format!(
                "socks5 connect failed with reply code {}",
                head[1]
            )));
        }

        let rest_len = match head[3] {
            v5::TYPE_IPV4 => 4 + 2,
            v5::TYPE_IPV6 => 16 + 2,
            v5::TYPE_DOMAIN => {
                let mut domain_len = [0u8; 1];
                conn.read_exact(&mut domain_len).await?;
                usize::from(domain_len[0]) + 2
            }
            address_type => {
                return Err(io::Error::other(format!(
                    "unknown address type {} in socks5 reply",
                    address_type
                )));
            }
        };
        let mut bnd_addr = vec![0u8; rest_len];
        conn.read_exact(&mut bnd_addr).await?;

        Ok(())
    };
    timeout(dur, fut).await?
}

// To try this:
// 1. cargo run -- -c config.toml
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

    let authorization = format!("{}:{}", config.username, config.password)
        .as_bytes()
        .to_vec();

    let socks_client = SocksClient::new(config.server_addr);

    let service = service_fn(move |mut req| {
        let authorization = authorization.clone();
        let socks_client = socks_client.clone();
        async move {
            log::debug!("req: {:?}", req);
            if !authorize(&authorization, req.headers().get(PROXY_AUTHORIZATION)) {
                log::error!("authorization fail");
                let mut resp = Response::new(empty());
                *resp.status_mut() = http::StatusCode::PROXY_AUTHENTICATION_REQUIRED;
                return Ok(resp);
            }
            let _ = req.headers_mut().remove(PROXY_AUTHORIZATION);
            socks_client.proxy(req).await
        }
    });

    awak::block_on(async {
        let local_addr: SocketAddr = config.local_addr;
        let listener = TcpListener::bind(&local_addr).await?;
        log::debug!("Listening on http://{}", local_addr);

        loop {
            let (stream, addr) = listener.accept().await?;
            log::debug!("accept stream from {:?}", addr);
            let _ = stream.set_nodelay(true);
            let io = HyperIo::new(stream);
            let service = service.clone();

            awak::spawn(async move {
                if let Err(err) = http1::Builder::new()
                    .preserve_header_case(true)
                    .title_case_headers(true)
                    .timer(HyperTimer::new())
                    .serve_connection(io, service)
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

fn authorize(authorization: &[u8], header_value: Option<&HeaderValue>) -> bool {
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

fn upstream_status(err: &io::Error) -> http::StatusCode {
    if err.kind() == io::ErrorKind::TimedOut {
        http::StatusCode::GATEWAY_TIMEOUT
    } else {
        http::StatusCode::BAD_GATEWAY
    }
}

fn upstream_error_response(err: &io::Error) -> Response<BoxBody<Bytes, hyper::Error>> {
    let status = upstream_status(err);
    let mut resp = Response::new(full(status.canonical_reason().unwrap_or("upstream error")));
    *resp.status_mut() = status;
    resp
}

struct SocksConnector {
    server_addr: SocketAddr,
    host: String,
    port: u16,
}

impl ManageConnection for SocksConnector {
    /// The connection type this manager deals with.
    type Connection = SendRequest<hyper::body::Incoming>;

    /// Attempts to create a new connection.
    async fn connect(&self) -> io::Result<Self::Connection> {
        log::debug!("create new connection to {:?}", self.server_addr);
        let mut stream = timeout(CONNECT_TIMEOUT, TcpStream::connect(self.server_addr)).await??;
        let _ = stream.set_nodelay(true);
        handshake(&mut stream, CONNECT_TIMEOUT, self.host.clone(), self.port).await?;

        let (request_sender, connection) = hyper::client::conn::http1::Builder::new()
            .handshake(HyperIo::new(stream))
            .await
            .map_err(io::Error::other)?;

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
    async fn check(&self, conn: &mut Self::Connection) -> io::Result<()> {
        poll_fn(|cx| {
            ready!(conn.poll_ready(cx)).map_err(io::Error::other)?;
            Poll::Ready(Ok(()))
        })
        .await
    }
}

#[derive(Clone)]
struct SocksClient {
    inner: Arc<Mutex<LruCache<String, Pool<SocksConnector>>>>,
    server_addr: SocketAddr,
}

impl SocksClient {
    fn new(server_addr: SocketAddr) -> Self {
        Self {
            inner: Arc::new(Mutex::new(LruCache::with_expiry_duration_and_capacity(
                DESTINATION_POOL_TTL,
                MAX_DESTINATION_POOLS,
            ))),
            server_addr,
        }
    }

    async fn proxy(
        self,
        req: Request<hyper::body::Incoming>,
    ) -> hyper::Result<Response<BoxBody<Bytes, hyper::Error>>> {
        if Method::CONNECT == req.method() {
            // Received an HTTP request like:
            // ```
            // CONNECT www.domain.com:443 HTTP/1.1
            // Host: www.domain.com:443
            // Proxy-Connection: Keep-Alive
            // ```
            //
            // Establish the upstream SOCKS5 connection before returning 200 so
            // that connect/handshake failures reach the client as 502/504
            // instead of a connection reset after a successful response.
            if req.uri().authority().is_none() {
                log::error!("CONNECT host is not socket addr: {:?}", req.uri());
                let mut resp = Response::new(full("CONNECT must be to a socket address"));
                *resp.status_mut() = http::StatusCode::BAD_REQUEST;
                return Ok(resp);
            }

            let host = req.uri().host().map(|v| v.to_string()).unwrap_or_default();
            let port = req.uri().port_u16().unwrap_or(80);
            let server = match connect_upstream(self.server_addr, host.clone(), port).await {
                Ok(server) => server,
                Err(e) => {
                    log::error!("connect upstream {}:{} failed: {}", host, port, e);
                    return Ok(upstream_error_response(&e));
                }
            };

            // The 200 has to be sent before hyper performs the upgrade, so the
            // copy loop runs in a detached task and waits on `on(req)`.
            awak::spawn(async move {
                if let Err(e) = tunnel(req, server).await {
                    log::error!("tunnel io error: {}", e);
                }
            })
            .detach();
            return Ok(Response::new(empty()));
        }

        match self.send_request(req).await {
            Ok(res) => Ok(Response::new(res.boxed())),
            Err(e) => {
                log::error!("proxy request failed: {}", e);
                Ok(upstream_error_response(&e))
            }
        }
    }

    // Create a TCP connection to host:port, build a tunnel between the connection and
    // the remote connection
    async fn send_request(
        &self,
        req: Request<hyper::body::Incoming>,
    ) -> io::Result<Response<hyper::body::Incoming>> {
        let host = req.uri().host().map(|v| v.to_string()).unwrap_or_default();
        let port = req.uri().port_u16().unwrap_or(80);
        log::debug!("proxy {}:{} to {:?}", host, port, self.server_addr);

        let conn = SocksConnector {
            server_addr: self.server_addr,
            host: host.clone(),
            port,
        };
        let pool = {
            let mut inner = self.inner.lock().await;
            let key = format!("{}:{}", host, port);
            match inner.get(&key) {
                Some(pool) => pool.clone(),
                None => {
                    let pool = Builder::new()
                        .build(conn);
                    inner.insert(key, pool.clone());
                    pool
                }
            }
        };

        let mut request_sender = pool.get().await?;
        request_sender
            .send_request(req)
            .await
            .map_err(io::Error::other)
    }
}

async fn connect_upstream(
    server_addr: SocketAddr,
    host: String,
    port: u16,
) -> io::Result<TcpStream> {
    let mut server = timeout(CONNECT_TIMEOUT, TcpStream::connect(server_addr)).await??;
    let _ = server.set_nodelay(true);
    handshake(&mut server, CONNECT_TIMEOUT, host, port).await?;
    Ok(server)
}

// Finish the tunnel once hyper has upgraded the client connection.
async fn tunnel(req: Request<hyper::body::Incoming>, mut server: TcpStream) -> io::Result<()> {
    let upgraded = hyper::upgrade::on(req)
        .await
        .map_err(|e| io::Error::other(format!("upgrade fail: {}", e)))?;

    let mut upgraded = HyperIo::new(upgraded);
    let (n1, n2) = IdleTimeout::new(
        copy_bidirectional_with_sizes(&mut upgraded, &mut server, DEFAULT_COPY_BUFFER_SIZE),
        Duration::from_secs(300),
        Duration::from_secs(5),
    )
    .await??;
    log::debug!("client wrote {} bytes and received {} bytes", n1, n2);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Runs `handshake` against a loopback peer that first sends `reply` and
    /// then stays silent.  `reply` must contain the method-selection reply
    /// followed by the CONNECT reply.
    async fn handshake_with_reply(reply: &[u8]) -> io::Result<()> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;

        // The TCP handshake completes via the listen backlog, so the client
        // can connect before the server calls accept().
        let mut client = TcpStream::connect(addr).await?;
        let (mut server, _) = listener.accept().await?;
        server.write_all(reply).await?;

        handshake(&mut client, CONNECT_TIMEOUT, "example.com".to_string(), 80).await
    }

    fn with_method_reply(connect_reply: &[u8]) -> Vec<u8> {
        let mut reply = vec![v5::VERSION, v5::METH_NO_AUTH];
        reply.extend_from_slice(connect_reply);
        reply
    }

    fn connect_reply(address_type: u8, address: &[u8]) -> Vec<u8> {
        let mut reply = vec![v5::VERSION, v5::REPLY_SUCESS, 0, address_type];
        reply.extend_from_slice(address);
        reply.extend_from_slice(&80u16.to_be_bytes());
        reply
    }

    #[test]
    fn handshake_reads_reply_address_from_reply_type() {
        awak::block_on(async {
            // Domain target, IPv4 BND.ADDR: what common SOCKS5 servers
            // (OpenSSH -D, sslocal, ...) return.  The reply is 10 bytes even
            // though the old code expected 18 bytes for this request.
            let ipv4 = connect_reply(v5::TYPE_IPV4, &[127, 0, 0, 1]);
            handshake_with_reply(&with_method_reply(&ipv4))
                .await
                .expect("domain target with IPv4 reply");

            // Domain target, IPv6 BND.ADDR (22-byte reply).
            let ipv6 = connect_reply(v5::TYPE_IPV6, &[0u8; 16]);
            handshake_with_reply(&with_method_reply(&ipv6))
                .await
                .expect("domain target with IPv6 reply");

            // Domain target, domain BND.ADDR.
            let mut address = vec![11u8];
            address.extend_from_slice(b"example.com");
            let domain = connect_reply(v5::TYPE_DOMAIN, &address);
            handshake_with_reply(&with_method_reply(&domain))
                .await
                .expect("domain target with domain reply");

            // A non-zero REP must be reported as an error instead of being
            // treated as a successful handshake.
            let mut failure = vec![v5::VERSION, 5, 0, v5::TYPE_IPV4];
            failure.extend_from_slice(&[0, 0, 0, 0]);
            failure.extend_from_slice(&80u16.to_be_bytes());
            let err = handshake_with_reply(&with_method_reply(&failure))
                .await
                .expect_err("failed reply must not be accepted");
            assert!(
                err.to_string().contains("socks5 connect failed"),
                "unexpected error: {}",
                err
            );
        });
    }

    #[test]
    fn maps_upstream_errors_to_gateway_status() {
        assert_eq!(
            upstream_status(&io::Error::from(io::ErrorKind::TimedOut)),
            http::StatusCode::GATEWAY_TIMEOUT
        );
        assert_eq!(
            upstream_status(&io::Error::from(io::ErrorKind::ConnectionRefused)),
            http::StatusCode::BAD_GATEWAY
        );
    }
}
