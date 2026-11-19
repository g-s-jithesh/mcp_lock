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
/// `npx.cmd`. Resolve the name ourselves using `PATHEXT`. Std escapes `.cmd` arguments safely.
#[cfg(windows)]
fn resolve_program(program: &str) -> std::path::PathBuf {
    resolve_with(
        program,
        std::env::var_os("PATH").as_deref(),
        std::env::var_os("PATHEXT").as_deref(),
    )
}

#[cfg(not(windows))]
fn resolve_program(program: &str) -> &str {
    program
}

/// The Windows lookup, as a pure function of `PATH` and `PATHEXT` so it can be tested on
/// any OS:
/// - a name whose extension is already in `PATHEXT` (`server.exe`) is used as given;
/// - otherwise each `PATHEXT` extension is *appended* (so `python3.12` -> `python3.12.exe`,
///   where `set_extension` would give `python3.exe`);
/// - a path with a directory part (`.\node_modules\.bin\mcp-server`) is tried as is,
///   relative to the working directory; a bare name is searched for on `PATH`;
/// - empty `PATHEXT` entries are skipped: an extensionless file is never picked, because on
///   Windows that is usually a POSIX shell script that can't be run (OS error 193).
#[cfg(any(windows, test))]
fn resolve_with(
    program: &str,
    path: Option<&std::ffi::OsStr>,
    pathext: Option<&std::ffi::OsStr>,
) -> std::path::PathBuf {
    use std::path::PathBuf;
    let given = PathBuf::from(program);
    let mut exts: Vec<String> = pathext
        .map(|e| e.to_string_lossy().into_owned())
        .unwrap_or_default()
        .split(';')
        .map(str::trim)
        .filter(|e| !e.is_empty())
        .map(str::to_owned)
        .collect();
    if exts.is_empty() {
        exts = [".COM", ".EXE", ".BAT", ".CMD"].map(String::from).to_vec();
    }

    let has_known_ext = given.extension().is_some_and(|e| {
        let e = e.to_string_lossy();
        exts.iter()
            .any(|x| x.trim_start_matches('.').eq_ignore_ascii_case(&e))
    });
    if has_known_ext {
        return given;
    }
    let with_exts = |base: PathBuf| {
        exts.iter().map(move |ext| {
            let mut name = base.clone().into_os_string();
            name.push(ext);
            PathBuf::from(name)
        })
    };
    let found = if given.components().count() > 1 {
        with_exts(given.clone()).find(|c| c.is_file())
    } else {
        path.into_iter()
            .flat_map(std::env::split_paths)
            .flat_map(|dir| with_exts(dir.join(program)))
            .find(|c| c.is_file())
    };
    found.unwrap_or(given)
}

fn missing(pipe: &str) -> io::Error {
    io::Error::other(format!("child {pipe} was not piped"))
}

fn closed() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "server stdin is closed")
}

#[cfg(test)]
mod tests {
    use super::resolve_with;
    use std::ffi::OsString;
    use std::path::{Path, PathBuf};

    /// A fresh temp dir containing empty files with the given relative names.
    fn dir_with(name: &str, files: &[&str]) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("mcp-lock-resolve-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        for file in files {
            let path = dir.join(file);
            std::fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
            std::fs::write(path, "").expect("touch");
        }
        dir
    }

    fn path_of(dirs: &[&Path]) -> OsString {
        std::env::join_paths(dirs).expect("join PATH")
    }

    #[test]
    fn trailing_semicolon_never_picks_an_extensionless_script() {
        // Issue #11.3: `npx` (POSIX script) in an earlier dir, `npx.cmd` in a later one.
        let first = dir_with("posix", &["npx"]);
        let second = dir_with("cmd", &["npx.cmd"]);
        let resolved = resolve_with(
            "npx",
            Some(&path_of(&[&first, &second])),
            Some(".exe;.cmd;".as_ref()),
        );
        assert_eq!(resolved, second.join("npx.cmd"));
    }

    #[test]
    fn dotted_names_get_an_extension_appended() {
        // Issue #11.2: `python3.12` has an "extension" of `12`, which isn't executable.
        let dir = dir_with("dotted", &["python3.12.exe"]);
        let resolved = resolve_with(
            "python3.12",
            Some(&path_of(&[&dir])),
            Some(".exe;.cmd".as_ref()),
        );
        assert_eq!(resolved, dir.join("python3.12.exe"));
    }

    #[test]
    fn paths_with_a_directory_part_are_resolved_too() {
        // Issue #11.1: a relative or absolute path to a `.cmd` wrapper.
        let dir = dir_with("relative", &["node_modules/.bin/mcp-server.cmd"]);
        let program = dir.join("node_modules").join(".bin").join("mcp-server");
        let resolved = resolve_with(&program.to_string_lossy(), None, Some(".exe;.cmd".as_ref()));
        assert_eq!(
            resolved,
            dir.join("node_modules").join(".bin").join("mcp-server.cmd")
        );
    }

    #[test]
    fn known_extensions_and_misses_are_left_as_given() {
        let dir = dir_with("known", &["tool.exe"]);
        let path = path_of(&[&dir]);
        assert_eq!(
            resolve_with("tool.exe", Some(&path), Some(".exe".as_ref())),
            PathBuf::from("tool.exe")
        );
        assert_eq!(
            resolve_with("missing", Some(&path), Some(".exe".as_ref())),
            PathBuf::from("missing")
        );
    }
}
