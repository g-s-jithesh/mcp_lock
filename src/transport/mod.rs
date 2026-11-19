//! Server-side transports. The proxy only ever talks to a server through [`Transport`],
//! so new transports (e.g. Streamable HTTP) slot in without touching the proxy logic.
//!
//! Also holds the newline-delimited framing helpers shared by the stdio transport and the
//! client side of the proxy, with limits so a misbehaving peer can't exhaust memory.

pub mod stdio;

use std::io;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

/// Largest single JSON-RPC message we accept. Generous, because tool results can carry
/// base64 files, but finite.
pub const MAX_MESSAGE_BYTES: usize = 64 * 1024 * 1024;

/// Most bytes we queue for a peer that isn't reading before giving up on the session.
pub const MAX_QUEUED_BYTES: usize = 4 * MAX_MESSAGE_BYTES;

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
    /// Fails with [`io::ErrorKind::OutOfMemory`] if too much is already queued.
    fn send(&mut self, msg: Vec<u8>) -> io::Result<()>;

    /// Next message from the server, or `None` once it has closed.
    /// Must be cancel-safe: it is used inside `tokio::select!`.
    async fn recv(&mut self) -> io::Result<Option<Vec<u8>>>;

    /// Tell the server no more messages are coming (e.g. close the child's stdin).
    fn close(&mut self);
}

/// Reads newline-delimited messages with a size limit.
///
/// Cancel-safe: a partly read line is kept in `self.line`, and bytes are only consumed
/// from the buffer after they've been copied, with no `.await` in between.
pub(crate) struct LineReader<R> {
    inner: BufReader<R>,
    line: Vec<u8>,
    max: usize,
}

impl<R: AsyncRead + Unpin> LineReader<R> {
    pub(crate) fn new(reader: R, max: usize) -> Self {
        Self {
            inner: BufReader::new(reader),
            line: Vec::new(),
            max,
        }
    }

    /// Next line without its `\n`, or `None` at end of input. A final line without a
    /// newline is still returned. A line longer than the limit is an error.
    pub(crate) async fn next_line(&mut self) -> io::Result<Option<Vec<u8>>> {
        loop {
            let buf = self.inner.fill_buf().await?;
            if buf.is_empty() {
                let rest = std::mem::take(&mut self.line);
                return Ok((!rest.is_empty()).then_some(rest));
            }
            let newline = buf.iter().position(|&b| b == b'\n');
            let chunk = &buf[..newline.unwrap_or(buf.len())];
            if self.line.len() + chunk.len() > self.max {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("message longer than {} bytes", self.max),
                ));
            }
            self.line.extend_from_slice(chunk);
            let used = chunk.len() + usize::from(newline.is_some());
            self.inner.consume(used);
            if newline.is_some() {
                return Ok(Some(std::mem::take(&mut self.line)));
            }
        }
    }
}

/// Sending half of [`line_writer`]: queues messages, refusing once too many bytes are
/// waiting for a peer that isn't reading.
//
// Why not a bounded channel? Waiting for space would stop the proxy reading the other
// side, and if that side is blocked writing to us, both wait forever. Failing is safer.
pub(crate) struct LineSender {
    tx: mpsc::UnboundedSender<Vec<u8>>,
    queued: Arc<AtomicUsize>,
    max: usize,
}

impl LineSender {
    pub(crate) fn send(&self, msg: Vec<u8>) -> io::Result<()> {
        let len = msg.len();
        if self.queued.fetch_add(len, Ordering::SeqCst) + len > self.max {
            self.queued.fetch_sub(len, Ordering::SeqCst);
            return Err(io::Error::new(
                io::ErrorKind::OutOfMemory,
                format!("peer is not reading: more than {} bytes queued", self.max),
            ));
        }
        self.tx.send(msg).map_err(|_| {
            self.queued.fetch_sub(len, Ordering::SeqCst);
            io::Error::new(io::ErrorKind::BrokenPipe, "output is closed")
        })
    }
}

/// Spawn a task that writes queued messages to `w`, one per line, flushing after each.
/// At most `max_queued` bytes may wait to be written.
///
/// Returns the queue's sender and the task handle. Dropping the sender ends the task,
/// which drops (and so closes) `w`.
pub(crate) fn line_writer<W>(
    mut w: W,
    max_queued: usize,
) -> (LineSender, JoinHandle<io::Result<()>>)
where
    W: AsyncWrite + Unpin + Send + 'static,
{
    let (tx, mut rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let queued = Arc::new(AtomicUsize::new(0));
    let task_queued = Arc::clone(&queued);
    let task = tokio::spawn(async move {
        while let Some(mut msg) = rx.recv().await {
            let len = msg.len();
            msg.push(b'\n');
            w.write_all(&msg).await?;
            w.flush().await?;
            task_queued.fetch_sub(len, Ordering::SeqCst);
        }
        Ok(())
    });
    let sender = LineSender {
        tx,
        queued,
        max: max_queued,
    };
    (sender, task)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn reads_lines_including_a_final_unterminated_one() {
        let mut r = LineReader::new(&b"one\n\ntwo\nthree"[..], 100);
        assert_eq!(r.next_line().await.ok().flatten(), Some(b"one".to_vec()));
        assert_eq!(r.next_line().await.ok().flatten(), Some(b"".to_vec()));
        assert_eq!(r.next_line().await.ok().flatten(), Some(b"two".to_vec()));
        assert_eq!(r.next_line().await.ok().flatten(), Some(b"three".to_vec()));
        assert_eq!(r.next_line().await.ok().flatten(), None);
    }

    #[tokio::test]
    async fn rejects_lines_over_the_limit() {
        // Issue #8.1: a peer that never sends a newline must not grow memory forever.
        let mut r = LineReader::new(&b"short\nmuch too long without a newline"[..], 8);
        assert_eq!(r.next_line().await.ok().flatten(), Some(b"short".to_vec()));
        let err = r.next_line().await.expect_err("too long");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn refuses_to_queue_past_the_cap_for_a_stalled_peer() {
        // Issue #8.2: nobody reads `_peer`, so the writer task stalls after 1 byte.
        let (stalled, _peer) = tokio::io::duplex(1);
        let (tx, _task) = line_writer(stalled, 10);
        assert!(tx.send(b"12345".to_vec()).is_ok());
        assert!(tx.send(b"12345".to_vec()).is_ok());
        let err = tx.send(b"1".to_vec()).expect_err("over the cap");
        assert_eq!(err.kind(), io::ErrorKind::OutOfMemory);
    }
}
