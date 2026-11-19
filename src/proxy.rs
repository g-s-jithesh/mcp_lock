//! The message pump between the MCP client and the server.
//!
//! Every message is shown to the [`Interceptor`]. Messages it doesn't change are forwarded
//! as the original bytes, so a session with no drift is byte-for-byte transparent.

use crate::interceptor::{Action, Interceptor};
use crate::transport::{line_writer, Transport};
use serde_json::Value;
use std::io;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, BufReader};

/// Pump messages between a client (`client_in`/`client_out`) and `server` until the
/// server closes. When the client closes its side, the server's input is closed too and
/// we keep draining the server's remaining output.
pub async fn run<T, R, W>(
    server: &mut T,
    interceptor: &mut Interceptor,
    client_in: R,
    client_out: W,
) -> io::Result<()>
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
                Some(msg) => match decide(&msg, |v| interceptor.on_client(v)) {
                    Action::Forward => send_to_server(server, msg),
                    Action::Replace(v) => send_to_server(server, v.to_string().into_bytes()),
                    Action::Reply(v) => send_to_client(&to_client, v.to_string().into_bytes()),
                    Action::Drop => {}
                },
                None => {
                    tracing::debug!("client closed input; closing server input");
                    client_open = false;
                    server.close();
                }
            },
            msg = server.recv() => match msg? {
                Some(msg) => match decide(&msg, |v| interceptor.on_server(v)) {
                    Action::Forward => send_to_client(&to_client, msg),
                    Action::Replace(v) => send_to_client(&to_client, v.to_string().into_bytes()),
                    // The interceptor never answers the server itself; treat as dropped.
                    Action::Reply(_) | Action::Drop => {}
                },
                None => break,
            },
        }
    }

    // Dropping the sender lets the writer task finish flushing, then we wait for it.
    drop(to_client);
    client_writer.await.map_err(io::Error::other)?
}

/// Parse `raw` and ask the interceptor. Lines that aren't JSON are forwarded untouched.
fn decide(raw: &[u8], inspect: impl FnOnce(&Value) -> Action) -> Action {
    match serde_json::from_slice::<Value>(raw) {
        Ok(value) => inspect(&value),
        Err(_) => Action::Forward,
    }
}

fn send_to_server<T: Transport>(server: &mut T, msg: Vec<u8>) {
    if let Err(e) = server.send(msg) {
        tracing::warn!("dropping client message: {e}");
    }
}

fn send_to_client(to_client: &tokio::sync::mpsc::UnboundedSender<Vec<u8>>, msg: Vec<u8>) {
    if to_client.send(msg).is_err() {
        tracing::warn!("client output closed; dropping message");
    }
}
