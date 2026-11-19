use anyhow::Context;
use clap::{Parser, Subcommand};
use mcp_lock::transport::stdio::StdioTransport;
use std::process::ExitCode;

#[derive(Parser)]
#[command(version, about)]
struct Cli {
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run as a proxy in front of a stdio MCP server: `mcp-lock run -- <server cmd> [args...]`
    Run {
        /// The server command and its arguments.
        #[arg(required = true, trailing_var_arg = true, allow_hyphen_values = true)]
        server: Vec<String>,
    },
}

// Single-threaded runtime: the proxy is I/O bound and this keeps futures free of `Send` rules.
#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<ExitCode> {
    // Logs go to stderr: in stdio mode stdout is the protocol channel.
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .init();

    match Cli::parse().command {
        Cmd::Run { server } => {
            let (program, args) = server.split_first().context("missing server command")?;
            let mut transport = StdioTransport::spawn(program, args)
                .with_context(|| format!("failed to start server `{program}`"))?;
            mcp_lock::proxy::run(&mut transport, tokio::io::stdin(), tokio::io::stdout()).await?;
            let status = transport.wait().await?;
            // Propagate the server's exit code; 1 if it was killed by a signal.
            Ok(ExitCode::from(status.code().unwrap_or(1) as u8))
        }
    }
}
