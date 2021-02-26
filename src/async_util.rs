use futures::{AsyncRead, AsyncWrite};
use pin_project::pin_project;
use tokio::io::{AsyncRead as TokioAsyncRead, AsyncWrite as TokioAsyncWrite};

/// Wrapper for converting between tokio and futures async read types
#[pin_project]
pub(crate) struct Compat<T>(#[pin] pub T);

impl<T> Compat<T> {
    pub fn into_inner(self) -> T {
        self.0
    }
}

impl<T: AsyncRead> TokioAsyncRead for Compat<T> {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        self.project()
            .0
            .poll_read(cx, buf.initialize_unfilled())
            .map(|r| r.map(|n| buf.set_filled(n)))
    }
}

impl<T: AsyncWrite> TokioAsyncWrite for Compat<T> {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        self.project().0.poll_write(cx, buf)
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        self.project().0.poll_flush(cx)
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        self.project().0.poll_close(cx)
    }
}

pub(crate) trait CompatExt<T>: Sized {
    fn compat(self) -> Compat<Self> {
        Compat(self)
    }

    fn compat_mut(&mut self) -> Compat<&mut Self> {
        Compat(self)
    }
}

impl<T: AsyncRead> CompatExt<T> for T {}
// We can't also implement for AsyncWrite without specialization :(
