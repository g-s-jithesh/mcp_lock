//! Server-side transports. The proxy only ever talks to a server through [`Transport`],
//! so new transports (e.g. Streamable HTTP) slot in without touching the proxy logic.

pub mod stdio;

use std::io;
use tokio::io::{AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

/// A connection to an MCP server that moves whole JSON-RPC messages.
///
/// Messages are raw bytes without framing (no trailing newline), so the proxy can forward
/// them byte-for-byte when it has nothing to change.
//
// `async fn` in a public trait triggers a lint because callers can't require the returned
// future to be `Send`. We run on a single-threaded runtime, so that doesn't matter here.
#[allow(async_fn_in_trait)]
pub trait Transport {
    /// Queue one message for the server. Never waits for the server to read it.
    fn send(&mut self, msg: Vec<u8>) -> io::Result<()>;

    /// Next message from the server, or `None` once it has closed.
    /// Must be cancel-safe: it is used inside `tokio::select!`.
    async fn recv(&mut self) -> io::Result<Option<Vec<u8>>>;

    /// Tell the server no more messages are coming (e.g. close the child's stdin).
    fn close(&mut self);
}

/// Spawn a task that writes queued messages to `w`, one per line, flushing after each.
///
/// Returns the queue's sender and the task handle. Dropping the sender ends the task,
/// which drops (and so closes) `w`.
// ponytail: unbounded queue, memory grows if a peer stops reading; bound it if that bites.
pub(crate) fn line_writer<W>(
    mut w: W,
) -> (mpsc::UnboundedSender<Vec<u8>>, JoinHandle<io::Result<()>>)
where
    W: AsyncWrite + Unpin + Send + 'static,
{
    let (tx, mut rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let task = tokio::spawn(async move {
        while let Some(mut msg) = rx.recv().await {
            msg.push(b'\n');
            w.write_all(&msg).await?;
            w.flush().await?;
        }
        Ok(())
    });
    (tx, task)
}
