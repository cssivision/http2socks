use std::collections::LinkedList;
use std::fmt;
use std::io;
use std::marker::PhantomData;
use std::ops::{Add, Deref, DerefMut};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use awak::time::{delay_for, timeout};

/// A trait which provides connection-specific functionality.
#[trait_variant::make(ManageConnection: Send)]
pub trait LocalManageConnection: Send + Sync + 'static {
    /// The connection type this manager deals with.
    type Connection: Send + 'static;

    /// Attempts to create a new connection.
    async fn connect(&self) -> io::Result<Self::Connection>;

    /// Check if the connection is still valid, check background every `check_interval`.
    ///
    /// A standard implementation would check if a simple query like `PING` succee,
    /// if the `Connection` is broken, error should return.
    async fn check(&self, conn: &mut Self::Connection) -> io::Result<()>;
}

fn other(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::Other, msg)
}

/// A builder for a connection pool.
pub struct Builder<M>
where
    M: ManageConnection,
{
    pub max_lifetime: Option<Duration>,
    pub idle_timeout: Option<Duration>,
    pub connection_timeout: Option<Duration>,
    pub max_size: u32,
    pub check_interval: Option<Duration>,
    _pd: PhantomData<M>,
}

impl<M> fmt::Debug for Builder<M>
where
    M: ManageConnection,
{
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt.debug_struct("Builder")
            .field("max_size", &self.max_size)
            .field("max_lifetime", &self.max_lifetime)
            .field("idle_timeout", &self.idle_timeout)
            .field("connection_timeout", &self.connection_timeout)
            .finish()
    }
}

impl<M> Default for Builder<M>
where
    M: ManageConnection,
{
    fn default() -> Self {
        Builder {
            max_lifetime: Some(Duration::from_secs(60 * 30)),
            idle_timeout: Some(Duration::from_secs(3 * 60)),
            connection_timeout: Some(Duration::from_secs(3)),
            check_interval: Some(Duration::from_secs(3)),
            max_size: 0,
            _pd: PhantomData,
        }
    }
}

impl<M> Builder<M>
where
    M: ManageConnection,
{
    // Constructs a new `Builder`.
    ///
    /// Parameters are initialized with their default values.
    pub fn new() -> Self {
        Builder::default()
    }

    /// Sets the maximum lifetime of connections in the pool.
    ///
    /// If a connection reaches its maximum lifetime while checked out it will
    /// be closed when it is returned to the pool.
    ///
    /// Defaults to 30 minutes.
    ///
    /// use default if `max_lifetime` is the zero `Duration`.
    pub fn max_lifetime(mut self, max_lifetime: Option<Duration>) -> Self {
        if max_lifetime == Some(Duration::from_secs(0)) {
            self
        } else {
            self.max_lifetime = max_lifetime;
            self
        }
    }

    /// Sets the idle timeout used by the pool.
    ///
    /// If set, connections will be closed after exceed idle time.
    ///
    /// Defaults to 3 minutes.
    ///
    /// use default if `idle_timeout` is the zero `Duration`.
    pub fn idle_timeout(mut self, idle_timeout: Option<Duration>) -> Self {
        if idle_timeout == Some(Duration::from_secs(0)) {
            self
        } else {
            self.idle_timeout = idle_timeout;
            self
        }
    }

    /// Sets the connection timeout used by the pool.
    ///
    /// Calls to `Pool::get` will wait this long for a connection to become
    /// available before returning an error.
    ///
    /// Defaults to 3 seconds.
    /// don't timeout if `connection_timeout` is the zero duration
    pub fn connection_timeout(mut self, connection_timeout: Option<Duration>) -> Self {
        if connection_timeout == Some(Duration::from_secs(0)) {
            self
        } else {
            self.connection_timeout = connection_timeout;
            self
        }
    }

    /// Sets the maximum number of connections managed by the pool.
    ///
    /// Defaults to 10.
    ///
    /// no limited if `max_size` is 0.
    pub fn max_size(mut self, max_size: u32) -> Self {
        self.max_size = max_size;
        self
    }

    /// Sets the check interval of connections managed by the pool use the `ManageConnection::check`.
    ///
    /// Defaults to 3s.
    pub fn check_interval(mut self, interval: Option<Duration>) -> Self {
        self.check_interval = interval;
        self
    }

    /// Consumes the builder, returning a new, initialized pool.
    pub fn build(&self, manager: M) -> Pool<M>
    where
        M: ManageConnection,
    {
        let intervals = PoolInternals {
            conns: LinkedList::new(),
            active: 0,
        };

        let shared = SharedPool {
            intervals: Mutex::new(intervals),
            max_lifetime: self.max_lifetime,
            idle_timeout: self.idle_timeout,
            connection_timeout: self.connection_timeout,
            max_size: self.max_size,
            check_interval: self.check_interval,
            manager,
        };

        let pool = Pool(Arc::new(shared));
        awak::spawn(pool.clone().check()).detach();
        pool
    }
}

/// A smart pointer wrapping a connection.
pub struct Connection<M>
where
    M: ManageConnection,
{
    conn: Option<IdleConn<M::Connection>>,
    pool: Pool<M>,
}

impl<M> Drop for Connection<M>
where
    M: ManageConnection,
{
    fn drop(&mut self) {
        if self.conn.is_some() {
            self.pool.put(self.conn.take().unwrap());
        }
    }
}

impl<M> Deref for Connection<M>
where
    M: ManageConnection,
{
    type Target = M::Connection;

    fn deref(&self) -> &M::Connection {
        &self.conn.as_ref().unwrap().conn
    }
}

impl<M> DerefMut for Connection<M>
where
    M: ManageConnection,
{
    fn deref_mut(&mut self) -> &mut M::Connection {
        &mut self.conn.as_mut().unwrap().conn
    }
}

/// A generic connection pool.
pub struct Pool<M>(Arc<SharedPool<M>>)
where
    M: ManageConnection;

impl<M> Clone for Pool<M>
where
    M: ManageConnection,
{
    fn clone(&self) -> Pool<M> {
        Pool(self.0.clone())
    }
}

impl<M> Pool<M>
where
    M: ManageConnection,
{
    /// Creates a new connection pool with a default configuration.
    pub fn new(manager: M) -> Pool<M> {
        Pool::builder().build(manager)
    }

    /// Returns a builder type to configure a new pool.
    pub fn builder() -> Builder<M> {
        Builder::new()
    }

    fn interval<'a>(&'a self) -> MutexGuard<'a, PoolInternals<M::Connection>> {
        self.0.intervals.lock().unwrap()
    }

    fn idle_count(&self) -> usize {
        self.interval().conns.len()
    }

    fn incr_active(&self) {
        self.interval().active += 1;
    }

    fn decr_active(&self) {
        self.interval().active -= 1;
    }

    fn pop_front(&self) -> Option<IdleConn<M::Connection>> {
        self.interval().conns.pop_front()
    }

    fn push_back(&mut self, conn: IdleConn<M::Connection>) {
        self.interval().conns.push_back(conn);
    }

    fn exceed_idle_timeout(&self, conn: &IdleConn<M::Connection>) -> bool {
        if let Some(idle_timeout) = self.0.idle_timeout {
            if idle_timeout.as_micros() > 0 && conn.last_visited.add(idle_timeout) < Instant::now()
            {
                return true;
            }
        }

        false
    }

    fn exceed_max_lifetime(&self, conn: &IdleConn<M::Connection>) -> bool {
        if let Some(max_lifetime) = self.0.max_lifetime {
            if max_lifetime.as_micros() > 0 && conn.created.add(max_lifetime) < Instant::now() {
                return true;
            }
        }

        false
    }

    async fn check(mut self) {
        if let Some(interval) = self.0.check_interval {
            loop {
                delay_for(interval).await;
                let n = self.idle_count();
                for _ in 0..n {
                    if let Some(mut conn) = self.pop_front() {
                        if self.exceed_idle_timeout(&conn) || self.exceed_max_lifetime(&conn) {
                            self.decr_active();
                            continue;
                        }
                        match self.0.manager.check(&mut conn.conn).await {
                            Ok(_) => {
                                self.push_back(conn);
                                continue;
                            }
                            Err(_) => {
                                self.decr_active();
                            }
                        }
                        continue;
                    }
                    break;
                }
            }
        }
    }

    fn exceed_limit(&self) -> bool {
        let max_size = self.0.max_size;
        if max_size > 0 && self.interval().active > max_size {
            true
        } else {
            false
        }
    }

    /// Retrieves a connection from the pool.
    ///
    /// Waits for at most the connection timeout before returning an error.
    pub async fn get_timeout(
        &self,
        connection_timeout: Option<Duration>,
    ) -> io::Result<M::Connection> {
        if let Some(connection_timeout) = connection_timeout {
            let conn = match timeout(connection_timeout, self.0.manager.connect()).await {
                Ok(s) => match s {
                    Ok(s) => s,
                    Err(e) => {
                        return Err(other(&e.to_string()));
                    }
                },
                Err(e) => {
                    return Err(other(&e.to_string()));
                }
            };

            Ok(conn)
        } else {
            let conn = self.0.manager.connect().await?;
            Ok(conn)
        }
    }

    /// Retrieves a connection from the pool.
    ///
    /// Waits for at most the configured connection timeout before returning an
    /// error.
    pub async fn get(&self) -> io::Result<Connection<M>> {
        if let Some(conn) = self.pop_front() {
            return Ok(Connection {
                conn: Some(conn),
                pool: self.clone(),
            });
        }

        self.incr_active();
        if self.exceed_limit() {
            self.decr_active();
            return Err(other("exceed limit"));
        }

        let conn = self
            .get_timeout(self.0.connection_timeout)
            .await
            .map_err(|e| {
                self.decr_active();
                e
            })?;

        return Ok(Connection {
            conn: Some(IdleConn {
                conn,
                last_visited: Instant::now(),
                created: Instant::now(),
            }),
            pool: self.clone(),
        });
    }

    fn put(&mut self, mut conn: IdleConn<M::Connection>) {
        conn.last_visited = Instant::now();
        self.push_back(conn);
    }
}

struct SharedPool<M>
where
    M: ManageConnection,
{
    intervals: Mutex<PoolInternals<M::Connection>>,
    max_lifetime: Option<Duration>,
    idle_timeout: Option<Duration>,
    connection_timeout: Option<Duration>,
    max_size: u32,
    check_interval: Option<Duration>,
    manager: M,
}

struct IdleConn<C> {
    conn: C,
    last_visited: Instant,
    created: Instant,
}

struct PoolInternals<C> {
    conns: LinkedList<IdleConn<C>>,
    active: u32,
}
