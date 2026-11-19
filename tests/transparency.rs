//! Proxy transparency: with no drift, the client must see exactly the bytes it would get
//! from talking to the server directly.

use std::io::Write;
use std::process::{Command, Output, Stdio};

const SESSION: &str = concat!(
    r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"test","version":"0"}}}"#,
    "\n",
    r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
    "\n",
    r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#,
    "\n",
    r#"{"jsonrpc":"2.0","id":"three","method":"tools/call","params":{"name":"echo","arguments":{"text":"héllo"}}}"#,
    "\n",
    r#"{"jsonrpc":"2.0","id":4,"method":"ping"}"#,
    "\n",
);

fn python() -> &'static str {
    if cfg!(windows) {
        "python"
    } else {
        "python3"
    }
}

fn fake_server() -> String {
    format!("{}/tests/fake_server.py", env!("CARGO_MANIFEST_DIR"))
}

/// Run `cmd`, feed it `SESSION` on stdin, close stdin, and collect its output.
fn run_session(cmd: &mut Command) -> Output {
    let mut child = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(SESSION.as_bytes())
        .expect("write session");
    child.wait_with_output().expect("wait")
}

#[test]
fn proxied_session_is_byte_identical_to_direct() {
    let direct = run_session(Command::new(python()).arg(fake_server()));
    let proxied = run_session(
        Command::new(env!("CARGO_BIN_EXE_mcp-lock"))
            .args(["run", "--", python()])
            .arg(fake_server()),
    );

    assert!(direct.status.success(), "fake server failed: {direct:?}");
    assert!(proxied.status.success(), "proxy failed: {proxied:?}");
    assert_eq!(String::from_utf8_lossy(&direct.stdout).lines().count(), 4);
    assert_eq!(
        String::from_utf8_lossy(&proxied.stdout),
        String::from_utf8_lossy(&direct.stdout)
    );
    // Server logs still reach the client's stderr through the proxy.
    assert!(String::from_utf8_lossy(&proxied.stderr).contains("fake-server handled tools/list"));
}
