// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

//! One client connection of the HTTP server, served under the limits of `[server]` (C61).
//!
//! hyper has one timer for a request head and starts it whenever the connection waits for
//! a head, also on an idle keep-alive connection, so with only hyper's setting the header
//! timeout would be the idle timeout too: 30 s would close idle connections that a reverse
//! proxy still means to reuse (traefik keeps them 90 s), and a larger value would let a
//! slow client hold a connection that long. [`HeadTimer`] is the timer hyper is given: the
//! first head of a connection gets `header_read_timeout` from the accept; a later one gets
//! `keep_alive_timeout` while no byte of it has arrived, then `header_read_timeout` from
//! its first byte. Bytes are counted by [`CountingIo`] under the connection's stream.
//!
//! A client may also speak HTTP/2 from its first byte (prior knowledge, as before: axum's
//! server took both). The first bytes are read here, under the header timeout, until they
//! show the HTTP/2 preface or not; an HTTP/2 connection is served with keep-alive pings, so
//! a peer that stops answering them is closed.

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use axum::extract::ConnectInfo;
use axum::Router;
use hyper::body::Incoming;
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;

/// Limits on the server's client connections, from `[server]`.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ConnLimits {
    /// Time a client has to send a complete request head: the first head of a connection
    /// from the accept, a later one from its first byte.
    pub header_read_timeout: Duration,
    /// Time an idle keep-alive connection waits for the first byte of its next request.
    pub keep_alive_timeout: Duration,
    /// Open connections at most; past it new ones wait in the listen backlog.
    pub max_connections: usize,
}

impl ConnLimits {
    pub fn from_config(server: &crate::config::ServerConfig) -> Self {
        Self {
            header_read_timeout: Duration::from_secs(server.header_read_timeout),
            keep_alive_timeout: Duration::from_secs(server.keep_alive_timeout),
            max_connections: server.max_connections,
        }
    }
}

/// Serve the requests of one connection with `app` until the client closes it, a limit
/// closes it, or `stop` turns true (then the requests in flight finish and it closes).
pub(crate) async fn serve_connection(
    mut stream: TcpStream,
    remote: SocketAddr,
    app: Router,
    limits: ConnLimits,
    stop: tokio::sync::watch::Receiver<bool>,
) {
    let clock = Arc::new(HeadClock::new(tokio::time::Instant::now()));
    // CANCEL-SAFETY: on timeout the bytes read so far are dropped with the connection.
    let preface =
        match tokio::time::timeout(limits.header_read_timeout, read_preface(&mut stream)).await {
            Ok(Ok(Some(preface))) => preface,
            // Closed, failed, or silent past the header timeout.
            _ => return,
        };
    let is_h2 = preface.is_h2;
    let io = TokioIo::new(CountingIo {
        inner: stream,
        replay: preface.bytes,
        replayed: 0,
        clock: Arc::clone(&clock),
    });
    let service = hyper::service::service_fn(move |mut request: hyper::Request<Incoming>| {
        use tower::ServiceExt;
        // What `into_make_service_with_connect_info` gave handlers: the peer address.
        request.extensions_mut().insert(ConnectInfo(remote));
        app.clone().oneshot(request.map(axum::body::Body::new))
    });
    if is_h2 {
        let mut builder =
            hyper::server::conn::http2::Builder::new(hyper_util::rt::TokioExecutor::new());
        builder
            .timer(hyper_util::rt::TokioTimer::new())
            .keep_alive_interval(limits.keep_alive_timeout)
            .keep_alive_timeout(limits.header_read_timeout);
        drive(builder.serve_connection(io, service), stop, remote).await;
    } else {
        let mut builder = hyper::server::conn::http1::Builder::new();
        builder
            .timer(HeadTimer { clock, limits })
            .header_read_timeout(limits.header_read_timeout)
            .keep_alive(true);
        drive(builder.serve_connection(io, service), stop, remote).await;
    }
}

/// Run `connection` to its end, shutting it down gracefully once `stop` turns true.
async fn drive<C>(connection: C, mut stop: tokio::sync::watch::Receiver<bool>, remote: SocketAddr)
where
    C: hyper_util::server::graceful::GracefulConnection,
    C::Error: std::fmt::Display,
{
    tokio::pin!(connection);
    // CANCEL-SAFETY: the connection future stays pinned here and is polled to its end in
    // both arms; `stopped` holds nothing.
    let served = tokio::select! {
        served = connection.as_mut() => served,
        () = stopped(&mut stop) => {
            connection.as_mut().graceful_shutdown();
            connection.await
        }
    };
    if let Err(e) = served {
        tracing::debug!(error = %e, peer = %remote, "connection ended with an error");
    }
}

/// Resolves once `stop` turns true or its sender is gone. The guard `wait_for` returns is
/// dropped here, so it is not held across the shutdown that follows.
async fn stopped(stop: &mut tokio::sync::watch::Receiver<bool>) {
    let _ = stop.wait_for(|stop| *stop).await;
}

/// The connection preface of HTTP/2 (RFC 9113 §3.4).
const H2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// The first bytes of a connection, and whether they are the HTTP/2 preface.
struct Preface {
    bytes: Vec<u8>,
    is_h2: bool,
}

/// Read the first bytes of a connection until they are the HTTP/2 preface or cannot be
/// (any HTTP/1 request differs from it by its second byte at the latest). `None` when the
/// client closes first.
async fn read_preface(stream: &mut TcpStream) -> io::Result<Option<Preface>> {
    use tokio::io::AsyncReadExt;
    let mut bytes = Vec::with_capacity(H2_PREFACE.len());
    let mut buf = [0u8; 24];
    loop {
        let read = stream
            .read(&mut buf[..H2_PREFACE.len() - bytes.len()])
            .await?;
        if read == 0 {
            return Ok(None);
        }
        bytes.extend_from_slice(&buf[..read]);
        if !H2_PREFACE.starts_with(&bytes) {
            return Ok(Some(Preface {
                bytes,
                is_h2: false,
            }));
        }
        if bytes.len() == H2_PREFACE.len() {
            return Ok(Some(Preface { bytes, is_h2: true }));
        }
    }
}

/// What a connection's stream and its head timer share.
struct HeadClock {
    /// When the connection was accepted.
    accepted: tokio::time::Instant,
    /// Bytes read from the client so far.
    bytes_read: AtomicU64,
    /// Whether a head timer was armed on this connection before.
    armed_before: AtomicBool,
}

impl HeadClock {
    fn new(accepted: tokio::time::Instant) -> Self {
        Self {
            accepted,
            bytes_read: AtomicU64::new(0),
            armed_before: AtomicBool::new(false),
        }
    }
}

/// The connection's stream: first the bytes [`read_preface`] took, then the socket;
/// counting the bytes read for [`HeadTimer`].
struct CountingIo {
    inner: TcpStream,
    replay: Vec<u8>,
    replayed: usize,
    clock: Arc<HeadClock>,
}

impl AsyncRead for CountingIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;
        let before = buf.filled().len();
        let polled = if this.replayed < this.replay.len() {
            let take = buf.remaining().min(this.replay.len() - this.replayed);
            buf.put_slice(&this.replay[this.replayed..this.replayed + take]);
            this.replayed += take;
            Poll::Ready(Ok(()))
        } else {
            Pin::new(&mut this.inner).poll_read(cx, buf)
        };
        if let Poll::Ready(Ok(())) = polled {
            let read = (buf.filled().len() - before) as u64;
            this.clock.bytes_read.fetch_add(read, Ordering::Relaxed);
        }
        polled
    }
}

impl AsyncWrite for CountingIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// The timer hyper's HTTP/1 connection gets. hyper arms it, with a deadline of
/// `header_read_timeout` from now, each time the connection starts waiting for a head,
/// and uses it for nothing else.
struct HeadTimer {
    clock: Arc<HeadClock>,
    limits: ConnLimits,
}

impl hyper::rt::Timer for HeadTimer {
    fn sleep(&self, duration: Duration) -> Pin<Box<dyn hyper::rt::Sleep>> {
        Box::pin(HeadSleep::fixed(tokio::time::Instant::now() + duration))
    }

    fn sleep_until(&self, deadline: std::time::Instant) -> Pin<Box<dyn hyper::rt::Sleep>> {
        let deadline = tokio::time::Instant::from_std(deadline);
        if !self.clock.armed_before.swap(true, Ordering::Relaxed) {
            // The first head of the connection: the header timeout runs from the accept.
            let from_accept = self.clock.accepted + self.limits.header_read_timeout;
            return Box::pin(HeadSleep::fixed(deadline.min(from_accept)));
        }
        // A later head, none of it read yet: the connection is idle until its first byte.
        let armed = deadline
            .checked_sub(self.limits.header_read_timeout)
            .unwrap_or_else(tokio::time::Instant::now);
        Box::pin(HeadSleep {
            sleep: Box::pin(tokio::time::sleep_until(
                armed + self.limits.keep_alive_timeout,
            )),
            idle: Some(Idle {
                clock: Arc::clone(&self.clock),
                bytes_at_arm: self.clock.bytes_read.load(Ordering::Relaxed),
                header_read_timeout: self.limits.header_read_timeout,
            }),
        })
    }
}

/// A head deadline. While `idle` is set it is the keep-alive deadline, and the first byte
/// read after arming moves it to `header_read_timeout` from then.
struct HeadSleep {
    sleep: Pin<Box<tokio::time::Sleep>>,
    idle: Option<Idle>,
}

struct Idle {
    clock: Arc<HeadClock>,
    bytes_at_arm: u64,
    header_read_timeout: Duration,
}

impl HeadSleep {
    fn fixed(deadline: tokio::time::Instant) -> Self {
        Self {
            sleep: Box::pin(tokio::time::sleep_until(deadline)),
            idle: None,
        }
    }
}

impl Future for HeadSleep {
    type Output = ();

    // hyper polls this each time a read leaves the head incomplete, so the first byte of a
    // later head is seen on the poll right after it is read.
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        let this = &mut *self;
        if let Some(idle) = &this.idle {
            if idle.clock.bytes_read.load(Ordering::Relaxed) > idle.bytes_at_arm {
                let deadline = tokio::time::Instant::now() + idle.header_read_timeout;
                this.sleep.as_mut().reset(deadline);
                this.idle = None;
            }
        }
        this.sleep.as_mut().poll(cx)
    }
}

impl hyper::rt::Sleep for HeadSleep {}
