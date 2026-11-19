"""Tiny fake MCP server for tests: newline-delimited JSON-RPC over stdio.

Answers initialize, tools/list, tools/call and ping; ignores notifications.
Set FAKE_DESCRIPTION to override the `echo` tool's description, so tests can simulate a
server changing a tool between runs (an env var, so the command line and server id stay put).
"""
import json
import os
import sys

# UTF-8 and no \r\n translation, whatever the platform's pipe defaults are.
sys.stdin.reconfigure(encoding="utf-8")
sys.stdout.reconfigure(encoding="utf-8", newline="\n")

DESCRIPTION = os.environ.get("FAKE_DESCRIPTION", "Echo the input text back.")

TOOLS = [
    {
        # Deliberately unsorted keys and non-ASCII text: the proxy must not alter either.
        "name": "echo",
        "description": DESCRIPTION,
        "inputSchema": {
            "type": "object",
            "required": ["text"],
            "properties": {"text": {"type": "string", "description": "Text — any text ✓"}},
        },
        "annotations": {"readOnlyHint": True},
    }
]


def result(method, params):
    if method == "initialize":
        return {
            "protocolVersion": params.get("protocolVersion", "2025-06-18"),
            "capabilities": {"tools": {"listChanged": True}},
            "serverInfo": {"name": "fake-server", "version": "0.0.1"},
        }
    if method == "tools/list":
        return {"tools": TOOLS}
    if method == "tools/call":
        text = params.get("arguments", {}).get("text", "")
        return {"content": [{"type": "text", "text": text}]}
    if method == "ping":
        return {}
    return None


for line in sys.stdin:
    msg = json.loads(line)
    if "id" not in msg:
        continue  # notification
    res = result(msg.get("method"), msg.get("params", {}))
    if res is None:
        reply = {"jsonrpc": "2.0", "id": msg["id"], "error": {"code": -32601, "message": "Method not found"}}
    else:
        reply = {"jsonrpc": "2.0", "id": msg["id"], "result": res}
    print("fake-server handled", msg.get("method"), file=sys.stderr)
    sys.stdout.write(json.dumps(reply, ensure_ascii=False) + "\n")
    sys.stdout.flush()

# A misbehaving server that keeps running after its stdin closes (issue #9).
if os.environ.get("FAKE_IGNORE_EOF"):
    import time

    time.sleep(30)  # long enough to outlast the proxy's drain timeout; short if a test fails
