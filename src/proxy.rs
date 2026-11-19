//! The message pump between the MCP client and the server.
//!
//! Every message is shown to the [`Interceptor`]. Messages it doesn't change are forwarded
//! as the original bytes, so a session with no drift is byte-for-byte transparent.

use crate::interceptor::{Action, Interceptor};
use crate::transport::{
    line_writer, LineReader, LineSender, Transport, MAX_MESSAGE_BYTES, MAX_QUEUED_BYTES,
};
use serde_json::Value;
use std::io;
use tokio::io::{AsyncRead, AsyncWrite};

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
    let mut from_client = LineReader::new(client_in, MAX_MESSAGE_BYTES);
    let (to_client, client_writer) = line_writer(client_out, MAX_QUEUED_BYTES);
    let mut client_open = true;

    loop {
        // `select!` waits on both sides at once and runs the branch that's ready first.
        // The other branch's future is dropped, which is why both reads must be cancel-safe.
        tokio::select! {
            msg = from_client.next_line(), if client_open => match msg? {
                Some(msg) => match decide(&msg, |v| interceptor.on_client(v)) {
                    Action::Forward => send_to_server(server, msg)?,
                    Action::Replace(v) => send_to_server(server, v.to_string().into_bytes())?,
                    Action::Reply(v) => send_to_client(&to_client, v.to_string().into_bytes())?,
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
                    Action::Forward => send_to_client(&to_client, msg)?,
                    Action::Replace(v) => send_to_client(&to_client, v.to_string().into_bytes())?,
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

/// Parse `raw` and ask the interceptor.
///
/// Lines we can't parse are dropped, never forwarded: serde_json is stricter than some
/// peers (e.g. JavaScript accepts lone surrogates and deeper nesting), so forwarding them
/// would let a message the peer *can* parse skip every check. Fail closed.
fn decide(raw: &[u8], inspect: impl FnOnce(&Value) -> Action) -> Action {
    match serde_json::from_slice::<Value>(raw) {
        Ok(value) => inspect(&value),
        Err(e) => {
            if !raw.iter().all(u8::is_ascii_whitespace) {
                tracing::warn!("dropping a line that is not valid JSON ({e})");
            }
            Action::Drop
        }
    }
}

/// Queue a message for the server. A closed server input is only logged (the server is
/// going away, and the end of its output ends the session); a stalled server is fatal.
fn send_to_server<T: Transport>(server: &mut T, msg: Vec<u8>) -> io::Result<()> {
    match server.send(msg) {
        Err(e) if e.kind() == io::ErrorKind::OutOfMemory => Err(e),
        Err(e) => {
            tracing::warn!("dropping client message: {e}");
            Ok(())
        }
        Ok(()) => Ok(()),
    }
}

/// Queue a message for the client. Same rules as [`send_to_server`].
fn send_to_client(to_client: &LineSender, msg: Vec<u8>) -> io::Result<()> {
    match to_client.send(msg) {
        Err(e) if e.kind() == io::ErrorKind::OutOfMemory => Err(e),
        Err(e) => {
            tracing::warn!("dropping message for the client: {e}");
            Ok(())
        }
        Ok(()) => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unparseable_lines_are_dropped_not_forwarded() {
        // JavaScript's JSON.parse accepts a lone surrogate; serde_json does not. Forwarding
        // it would let a poisoned tools/list reach the client unchecked (issue #1).
        let lone_surrogate =
            br#"{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"x","description":"\ud800"}]}}"#;
        let deep = format!("{}{}", "[".repeat(200), "]".repeat(200));
        for raw in [&lone_surrogate[..], deep.as_bytes(), b"not json", b""] {
            assert_eq!(decide(raw, |_| Action::Forward), Action::Drop, "{raw:?}");
        }
    }

    #[test]
    fn parseable_lines_go_to_the_interceptor() {
        assert_eq!(
            decide(br#"{"jsonrpc":"2.0"}"#, |_| Action::Forward),
            Action::Forward
        );
    }
}
