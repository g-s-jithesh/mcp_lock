//! Stdio transport: spawn the server as a child process and exchange newline-delimited
//! JSON-RPC over its stdin/stdout. The child's stderr is inherited, so its logs reach ours.

use super::{line_writer, LineReader, LineSender, Transport, MAX_MESSAGE_BYTES, MAX_QUEUED_BYTES};
use std::io;
use std::process::{ExitStatus, Stdio};
use tokio::process::{Child, ChildStdout, Command};
use tokio::task::JoinHandle;

/// A spawned MCP server speaking JSON-RPC over stdio.
pub struct StdioTransport {
    child: Child,
    /// `None` after [`Transport::close`]; dropping the sender closes the child's stdin.
    to_server: Option<LineSender>,
    writer: JoinHandle<io::Result<()>>,
    from_server: LineReader<ChildStdout>,
}

impl StdioTransport {
    /// Spawn `program args...` with piped stdin/stdout.
    pub fn spawn(program: &str, args: &[String]) -> io::Result<Self> {
        let mut child = Command::new(resolve_program(program))
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .kill_on_drop(true)
            .spawn()?;
        // `take()` moves the pipe out of the `Child`, leaving `None`; we just spawned it with
        // piped stdio, so both are present.
        let stdin = child.stdin.take().ok_or_else(|| missing("stdin"))?;
        let stdout = child.stdout.take().ok_or_else(|| missing("stdout"))?;
        let (to_server, writer) = line_writer(stdin, MAX_QUEUED_BYTES);
        Ok(Self {
            child,
            to_server: Some(to_server),
            writer,
            from_server: LineReader::new(stdout, MAX_MESSAGE_BYTES),
        })
    }

    /// Close stdin (if still open) and wait for the server to exit.
    pub async fn wait(mut self) -> io::Result<ExitStatus> {
        self.close();
        if let Ok(Err(e)) = (&mut self.writer).await {
            tracing::debug!("server stdin writer ended with: {e}");
        }
        self.child.wait().await
    }
}

impl Transport for StdioTransport {
    fn send(&mut self, msg: Vec<u8>) -> io::Result<()> {
        self.to_server.as_ref().ok_or_else(closed)?.send(msg)
    }

    async fn recv(&mut self) -> io::Result<Option<Vec<u8>>> {
        // `LineReader::next_line` is cancel-safe, as `Transport::recv` requires.
        self.from_server.next_line().await
    }

    fn close(&mut self) {
        self.to_server = None;
    }
}

/// On Windows, `Command` only finds `.exe` files on PATH, but MCP configs say `npx`, which is
/// `npx.cmd`. Look the name up with each `PATHEXT` extension and use the first hit. Paths and
/// names that already have an extension are left alone. Std escapes `.cmd` arguments safely.
#[cfg(windows)]
fn resolve_program(program: &str) -> std::path::PathBuf {
    use std::path::Path;
    let as_given = Path::new(program).to_path_buf();
    if as_given.extension().is_some() || as_given.components().count() > 1 {
        return as_given;
    }
    let (Some(path), Some(exts)) = (std::env::var_os("PATH"), std::env::var_os("PATHEXT")) else {
        return as_given;
    };
    let exts = exts.to_string_lossy().into_owned();
    std::env::split_paths(&path)
        .flat_map(|dir| {
            exts.split(';')
                .map(move |ext| dir.join(format!("{program}{ext}")))
        })
        .find(|candidate| candidate.is_file())
        .unwrap_or(as_given)
}

#[cfg(not(windows))]
fn resolve_program(program: &str) -> &str {
    program
}

fn missing(pipe: &str) -> io::Error {
    io::Error::other(format!("child {pipe} was not piped"))
}

fn closed() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "server stdin is closed")
}
