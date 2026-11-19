//! Proxy transparency: with no drift, the client must see exactly the bytes it would get
//! from talking to the server directly (once its tools are approved).

use std::io::{BufRead, BufReader, Read, Write};
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

/// Run `cmd` and play `SESSION` like a real client: after each request, wait for its
/// response before sending the next line. Returns the output, with every stdout byte.
fn run_session(cmd: &mut Command) -> Output {
    let mut child = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn");
    let mut stdin = child.stdin.take().expect("stdin");
    let mut stdout = BufReader::new(child.stdout.take().expect("stdout"));
    let mut received = Vec::new();
    for line in SESSION.lines() {
        writeln!(stdin, "{line}").expect("write");
        if line.contains(r#""id":"#) {
            stdout
                .read_until(b'\n', &mut received)
                .expect("read response");
        }
    }
    drop(stdin);
    stdout.read_to_end(&mut received).expect("read rest");
    let mut out = child.wait_with_output().expect("wait");
    out.stdout = received;
    out
}

#[test]
fn proxied_session_is_byte_identical_to_direct() {
    let dir = std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join("transparency");
    std::fs::create_dir_all(&dir).expect("temp dir");
    let lock = dir.join("mcp.lock");
    let _ = std::fs::remove_file(&lock);
    let mcp_lock = |subcommand: &str| {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_mcp-lock"));
        cmd.args([subcommand, "--lock"])
            .arg(&lock)
            .args(["--", python()])
            .arg(fake_server())
            .env_remove("FAKE_DESCRIPTION");
        cmd
    };
    // "No drift" means the server's tools are approved first.
    assert!(mcp_lock("approve").status().expect("approve").success());

    let direct = run_session(
        Command::new(python())
            .arg(fake_server())
            .env_remove("FAKE_DESCRIPTION"),
    );
    let proxied = run_session(&mut mcp_lock("run"));

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
