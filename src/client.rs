//! A minimal MCP client, used by `status` and `approve` to ask a server what tools it has.
//! It never calls tools: it only sends `initialize` and `tools/list`.

use crate::transport::Transport;
use serde_json::{json, Value};
use std::io;

/// Protocol version we offer in `initialize`. Servers may answer with another they support;
/// `tools/list` looks the same in every version so far.
const PROTOCOL_VERSION: &str = "2025-06-18";

/// Stop following `nextCursor` after this many pages, in case a server loops forever.
const MAX_PAGES: u32 = 100;

/// What a server advertised.
#[derive(Debug)]
pub struct Snapshot {
    /// `serverInfo.name` from the `initialize` result, if given.
    pub server_name: Option<String>,
    /// Every tool from every `tools/list` page, in the order received.
    pub tools: Vec<Value>,
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
        cursor = result.get("nextCursor").filter(|c| !c.is_null()).cloned();
        if cursor.is_none() {
            let server_name = init["serverInfo"]["name"].as_str().map(str::to_owned);
            return Ok(Snapshot { server_name, tools });
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
        // A response has our id and no `method` (a request from the server could reuse ids).
        if msg["id"] != json!(id) || msg.get("method").is_some() {
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
