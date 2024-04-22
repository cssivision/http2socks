use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{ready, Context, Poll};
use std::time::{Duration, Instant};

use futures_util::io::{AsyncRead, AsyncWrite};
use hyper::rt::{Executor, Sleep, Timer};
use pin_project_lite::pin_project;

/// Future executor that utilises `awak` threads.
#[non_exhaustive]
#[derive(Default, Debug, Clone)]
pub struct HyperExecutor {}

pin_project! {
    /// A wrapper that implements IO traits for an inner type that
    /// implements hyper's IO traits, or vice versa (implements hyper's IO
    /// traits for a type that implements IO traits).
    #[derive(Debug)]
    pub struct HyperIo<T> {
        #[pin]
        inner: T,
    }
}

/// A Timer that uses the awak runtime.
#[non_exhaustive]
#[derive(Default, Clone, Debug)]
pub struct HyperTimer;

// Use HyperSleep to get awak::time::Sleep to implement Unpin.
pin_project! {
    struct HyperSleep {
        #[pin]
        inner: awak::time::Delay,
    }
}

// ===== impl HyperExecutor =====

impl<Fut> Executor<Fut> for HyperExecutor
where
    Fut: Future + Send + 'static,
    Fut::Output: Send + 'static,
{
    fn execute(&self, fut: Fut) {
        awak::spawn(fut).detach();
    }
}

impl HyperExecutor {
    /// Create new executor that relies on [`awak::spawn`] to execute futures.
    pub fn new() -> Self {
        Self {}
    }
}

// ==== impl HyperIo =====

impl<T> HyperIo<T> {
    /// Wrap a type implementing hyper's IO traits.
    pub fn new(inner: T) -> Self {
        Self { inner }
    }

    /// Borrow the inner type.
    pub fn inner(&self) -> &T {
        &self.inner
    }

    /// Mut borrow the inner type.
    pub fn inner_mut(&mut self) -> &mut T {
        &mut self.inner
    }

    /// Consume this wrapper and get the inner type.
    pub fn into_inner(self) -> T {
        self.inner
    }
}

impl<T> hyper::rt::Read for HyperIo<T>
where
    T: AsyncRead,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        mut buf: hyper::rt::ReadBufCursor<'_>,
    ) -> Poll<io::Result<()>> {
        let tbuf = unsafe { &mut *(buf.as_mut() as *mut _ as *mut [u8]) };
        let n = ready!(self.project().inner.poll_read(cx, tbuf))?;
        unsafe {
            buf.advance(n);
        }
        Poll::Ready(Ok(()))
    }
}

impl<T> hyper::rt::Write for HyperIo<T>
where
    T: AsyncWrite,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.project().inner.poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.project().inner.poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.project().inner.poll_close(cx)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        self.project().inner.poll_write_vectored(cx, bufs)
    }
}

impl<T> AsyncRead for HyperIo<T>
where
    T: hyper::rt::Read,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        tbuf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        let mut buf = hyper::rt::ReadBuf::new(tbuf);
        ready!(self.project().inner.poll_read(cx, buf.unfilled()))?;
        Poll::Ready(Ok(buf.filled().len()))
    }
}

impl<T> AsyncWrite for HyperIo<T>
where
    T: hyper::rt::Write,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        hyper::rt::Write::poll_write(self.project().inner, cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        hyper::rt::Write::poll_flush(self.project().inner, cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        hyper::rt::Write::poll_shutdown(self.project().inner, cx)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<Result<usize, io::Error>> {
        hyper::rt::Write::poll_write_vectored(self.project().inner, cx, bufs)
    }
}

// ==== impl HyperTimer =====

impl Timer for HyperTimer {
    fn sleep(&self, duration: Duration) -> Pin<Box<dyn Sleep>> {
        Box::pin(HyperSleep {
            inner: awak::time::delay_for(duration),
        })
    }

    fn sleep_until(&self, deadline: Instant) -> Pin<Box<dyn Sleep>> {
        Box::pin(HyperSleep {
            inner: awak::time::delay_until(deadline),
        })
    }

    fn reset(&self, sleep: &mut Pin<Box<dyn Sleep>>, new_deadline: Instant) {
        if let Some(sleep) = sleep.as_mut().downcast_mut_pin::<HyperSleep>() {
            sleep.reset(new_deadline)
        }
    }
}

impl HyperTimer {
    /// Create a new HyperTimer
    pub fn new() -> Self {
        Self {}
    }
}

impl Future for HyperSleep {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.project().inner.poll(cx)
    }
}

impl Sleep for HyperSleep {}

impl HyperSleep {
    fn reset(self: Pin<&mut Self>, deadline: Instant) {
        self.project().inner.as_mut().reset(deadline);
    }
}
