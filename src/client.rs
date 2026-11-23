//! A minimal MCP client, used by `status` and `approve` to ask a server what tools it has.
//! It never calls tools: it only sends `initialize` and `tools/list`.

use crate::interceptor::id_key;
use crate::transport::Transport;
use serde_json::{json, Value};
use std::io;

/// Protocol version we offer in `initialize`. Servers may answer with another they support;
/// `tools/list` looks the same in every version so far.
const PROTOCOL_VERSION: &str = "2025-06-18";

/// Stop following `nextCursor` after this many pages, in case a server loops forever.
const MAX_PAGES: u32 = 100;

/// JSON-RPC "method not found".
const METHOD_NOT_FOUND: i64 = -32601;

/// What a server advertised.
#[derive(Debug)]
pub struct Snapshot {
    /// `serverInfo.name` from the `initialize` result, if given.
    pub server_name: Option<String>,
    /// Every tool from every `tools/list` page, in the order received.
    pub tools: Vec<Value>,
    /// The server's `instructions` from the `initialize` result, if it sent a string.
    pub instructions: Option<String>,
}

/// Why listing a server's tools failed.
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("i/o error talking to the server: {0}")]
    Io(#[from] io::Error),
    #[error("server closed the connection before answering `{0}`")]
    Closed(&'static str),
    #[error("server returned an error for `{method}`: {error}")]
    Rpc { method: &'static str, error: Value },
    #[error("`tools/list` result has no `tools` array")]
    NoToolsArray,
    #[error("server sent more than {MAX_PAGES} pages of tools")]
    TooManyPages,
}

/// Initialize a session over `transport` and collect every tool, following pagination.
pub async fn list_tools<T: Transport>(transport: &mut T) -> Result<Snapshot, ClientError> {
    let init = request(
        transport,
        1,
        "initialize",
        json!({
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {"name": "mcp-lock", "version": env!("CARGO_PKG_VERSION")},
        }),
    )
    .await?;
    send(
        transport,
        json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
    )?;

    let mut tools = Vec::new();
    let mut cursor: Option<Value> = None;
    for page in 0..MAX_PAGES {
        let params = match &cursor {
            Some(c) => json!({ "cursor": c }),
            None => json!({}),
        };
        let mut result = request(transport, 2 + u64::from(page), "tools/list", params).await?;
        match result["tools"].take() {
            Value::Array(page_tools) => tools.extend(page_tools),
            _ => return Err(ClientError::NoToolsArray),
        }
        // Missing, null and "" all end the listing ("" is falsy to JavaScript clients).
        cursor = result
            .get("nextCursor")
            .filter(|c| !c.is_null() && c.as_str() != Some(""))
            .cloned();
        if cursor.is_none() {
            let server_name = init["serverInfo"]["name"].as_str().map(str::to_owned);
            let instructions = init["instructions"].as_str().map(str::to_owned);
            return Ok(Snapshot {
                server_name,
                tools,
                instructions,
            });
        }
    }
    Err(ClientError::TooManyPages)
}

fn send<T: Transport>(transport: &mut T, msg: Value) -> io::Result<()> {
    transport.send(msg.to_string().into_bytes())
}

/// Send a request and wait for the response with the same id. Anything else the server
/// sends meanwhile (logs, notifications, unparseable lines) is skipped.
async fn request<T: Transport>(
    transport: &mut T,
    id: u64,
    method: &'static str,
    params: Value,
) -> Result<Value, ClientError> {
    send(
        transport,
        json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}),
    )?;
    loop {
        let line = transport.recv().await?.ok_or(ClientError::Closed(method))?;
        let Ok(mut msg) = serde_json::from_slice::<Value>(&line) else {
            tracing::debug!("skipping non-JSON line from server");
            continue;
        };
        // A string `method` means a request or notification *from* the server. Answer
        // requests, so a server that waits for a reply doesn't stall us until the timeout.
        if let Some(server_method) = msg["method"].as_str() {
            if let Some(server_id) = msg.get("id") {
                answer_server_request(transport, server_id, server_method)?;
            }
            continue;
        }
        // Otherwise it's a response; match ids the way the proxy does (1 == 1.0).
        if id_key(&msg["id"]) != id_key(&json!(id)) {
            continue;
        }
        if let Some(error) = msg.get("error") {
            return Err(ClientError::Rpc {
                method,
                error: error.clone(),
            });
        }
        return Ok(msg["result"].take());
    }
}

/// Reply to a request the server sent us. We only list tools, so we answer `ping` and turn
/// everything else (roots, sampling, elicitation, ...) down with "method not found".
fn answer_server_request<T: Transport>(
    transport: &mut T,
    id: &Value,
    method: &str,
) -> io::Result<()> {
    let reply = if method == "ping" {
        json!({"jsonrpc": "2.0", "id": id, "result": {}})
    } else {
        json!({"jsonrpc": "2.0", "id": id, "error": {
            "code": METHOD_NOT_FOUND,
            "message": "mcp-lock only lists tools and does not support this request",
        }})
    };
    send(transport, reply)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    /// Replies with canned messages in order, and records what the client sends.
    struct Scripted {
        replies: VecDeque<Value>,
        sent: Vec<Value>,
    }

    impl Scripted {
        fn new(replies: impl IntoIterator<Item = Value>) -> Self {
            Self {
                replies: replies.into_iter().collect(),
                sent: Vec::new(),
            }
        }
    }

    impl Transport for Scripted {
        fn send(&mut self, msg: Vec<u8>) -> io::Result<()> {
            self.sent
                .push(serde_json::from_slice(&msg).map_err(io::Error::other)?);
            Ok(())
        }
        async fn recv(&mut self) -> io::Result<Option<Vec<u8>>> {
            Ok(self.replies.pop_front().map(|v| v.to_string().into_bytes()))
        }
        fn close(&mut self) {}
    }

    fn init_ok(id: Value) -> Value {
        json!({"jsonrpc": "2.0", "id": id, "result": {"serverInfo": {"name": "s"}}})
    }

    fn one_page(id: Value) -> Value {
        json!({"jsonrpc": "2.0", "id": id, "result": {"tools": [{"name": "a"}]}})
    }

    #[tokio::test]
    async fn empty_next_cursor_ends_the_listing() {
        // Issue #12.2: `""` used to be followed as a cursor, looping until TooManyPages.
        let mut server = Scripted::new([
            init_ok(json!(1)),
            json!({"jsonrpc": "2.0", "id": 2, "result": {"tools": [{"name": "a"}], "nextCursor": ""}}),
        ]);
        let snapshot = list_tools(&mut server).await.expect("one page");
        assert_eq!(snapshot.tools.len(), 1);
    }

    #[tokio::test]
    async fn ids_match_by_value_and_method_null_is_a_response() {
        // Same rules as the proxy's interceptor: 1.0 is id 1; `"method": null` is absent.
        let mut page = one_page(json!(2.0));
        page["method"] = Value::Null;
        let mut server = Scripted::new([init_ok(json!(1.0)), page]);
        let snapshot = list_tools(&mut server).await.expect("listed");
        assert_eq!(snapshot.tools.len(), 1);
    }

    #[tokio::test]
    async fn requests_from_the_server_are_answered() {
        // A server may ping, or ask for roots, before it answers us. Unanswered, it would
        // wait until our 60 s timeout.
        let mut server = Scripted::new([
            json!({"jsonrpc": "2.0", "id": "p1", "method": "ping"}),
            json!({"jsonrpc": "2.0", "id": 7, "method": "roots/list"}),
            json!({"jsonrpc": "2.0", "method": "notifications/message", "params": {}}),
            init_ok(json!(1)),
            one_page(json!(2)),
        ]);
        list_tools(&mut server).await.expect("listed");
        let reply_to = |id: Value| server.sent.iter().find(|m| m["id"] == id).cloned();
        assert_eq!(
            reply_to(json!("p1")).map(|m| m["result"].clone()),
            Some(json!({}))
        );
        assert_eq!(
            reply_to(json!(7)).map(|m| m["error"]["code"].clone()),
            Some(json!(-32601))
        );
        // Nothing is sent in reply to a notification.
        assert_eq!(server.sent.len(), 5, "{:?}", server.sent);
    }
}
