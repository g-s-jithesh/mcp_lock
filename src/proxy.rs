//! The message pump between the MCP client and the server.
//!
//! For now every message is forwarded unchanged, byte for byte. Later quests inspect
//! messages here (via the interceptor) before forwarding.

use crate::transport::{line_writer, Transport};
use std::io;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, BufReader};

/// Pump messages between a client (`client_in`/`client_out`) and `server` until the
/// server closes. When the client closes its side, the server's input is closed too and
/// we keep draining the server's remaining output.
pub async fn run<T, R, W>(server: &mut T, client_in: R, client_out: W) -> io::Result<()>
where
    T: Transport,
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let mut from_client = BufReader::new(client_in).split(b'\n');
    let (to_client, client_writer) = line_writer(client_out);
    let mut client_open = true;

    loop {
        // `select!` waits on both sides at once and runs the branch that's ready first.
        // The other branch's future is dropped, which is why both reads must be cancel-safe.
        tokio::select! {
            msg = from_client.next_segment(), if client_open => match msg? {
                Some(msg) => {
                    if let Err(e) = server.send(msg) {
                        tracing::warn!("dropping client message: {e}");
                    }
                }
                None => {
                    tracing::debug!("client closed input; closing server input");
                    client_open = false;
                    server.close();
                }
            },
            msg = server.recv() => match msg? {
                Some(msg) => {
                    if to_client.send(msg).is_err() {
                        tracing::warn!("client output closed; dropping server message");
                    }
                }
                None => break,
            },
        }
    }

    // Dropping the sender lets the writer task finish flushing, then we wait for it.
    drop(to_client);
    client_writer.await.map_err(io::Error::other)?
}
