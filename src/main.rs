//! tightbeam: private peer-to-peer tunnels over the bifrost overlay.
//!
//! Expose a local service by key on one machine; reach it as a local port on another. `ssh -L` /
//! cloudflared shaped, but p2p and pubkey-addressed. See DECISIONS.md for the design; the two
//! subcommands are stubbed pending design review.

use clap::{Parser, Subcommand};

/// Private peer-to-peer tunnels over the bifrost overlay.
#[derive(Debug, Parser)]
#[command(name = "tightbeam", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Expose a local service to peers who hold this node's key.
    Expose {
        /// The local address inbound streams are forwarded to, e.g. `127.0.0.1:22`.
        local_addr: String,
    },
    /// Reach a peer's exposed service and bind it to a local port.
    Connect {
        /// The node id to dial.
        node: String,
        /// The local port to listen on and forward to the peer.
        #[arg(long)]
        to: u16,
    },
}

#[tokio::main]
async fn main() -> eyre::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Expose { local_addr } => {
            eyre::bail!("expose {local_addr}: not yet implemented (design in DECISIONS.md)")
        }
        Command::Connect { node, to } => {
            eyre::bail!(
                "connect {node} -> 127.0.0.1:{to}: not yet implemented (design in DECISIONS.md)"
            )
        }
    }
}
