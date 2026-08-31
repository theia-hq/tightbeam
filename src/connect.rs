//! `tightbeam connect`: the clap surface for binding a peer's exposed service to a local port or piping it
//! over stdin/stdout, by node id or by capability link.
//!
//! The `Args` struct + its `Target` parse type + the `connector` resolver live here; the driving body
//! (forward a port or pipe stdio) is `main.rs` glue over the library [`Connector`], so tightbeam's CLI is a
//! thin adapter symmetric with swoosh's.

use core::str::FromStr;

use bifrost::NodeId;
use clap::{ArgGroup, Args};
use nauthy::{Cap, SCHEME};

use crate::tunnel::Connector;

/// Reach a peer's exposed service and bind it to a local port, or pipe it over stdin/stdout.
#[derive(Debug, Args)]
#[command(group = ArgGroup::new("dest").required(true).args(["to", "stdio"]))]
pub struct ConnectCmd {
    /// who to reach: a raw node id, or a `sheer:` capability link
    #[arg(value_name = "peer")]
    pub target: Target,
    /// local port to forward to the peer
    #[arg(long, value_name = "port")]
    pub to: Option<u16>,
    /// pipe the peer's service over stdin/stdout instead of a local port (for ssh ProxyCommand)
    #[arg(long)]
    pub stdio: bool,
    /// which exposed service to reach
    #[arg(long, value_name = "service", default_value = "default")]
    pub service: String,
    /// present a capability link alongside a raw node id
    #[arg(long, value_name = "link")]
    pub present: Option<String>,
}

/// What `connect` was pointed at: a bare identity, or a capability link.
///
/// A capability link supersedes the identity path entirely: it names the node to dial (the cap's root)
/// and the service it grants, and it presents the token. A bare node id is the pre-capability path, gated
/// on the proven identity alone.
#[derive(Debug, Clone)]
pub enum Target {
    /// A raw node id to dial; the host gates on the proven identity (open/strict/paired).
    Node(NodeId),
    /// A capability link (`sheer:…`) to present to a `cap`-gated host.
    Capability(String),
}

impl FromStr for Target {
    type Err = eyre::Error;

    fn from_str(text: &str) -> eyre::Result<Self> {
        if text.starts_with(SCHEME) {
            // Parse it now so a malformed link fails fast at the CLI boundary, not mid-connect. The
            // owned string is re-parsed at use so the token travels whole to the host.
            Cap::parse(text)?;
            Ok(Target::Capability(text.to_owned()))
        } else {
            Ok(Target::Node(text.parse::<NodeId>()?))
        }
    }
}

impl ConnectCmd {
    /// Resolve the target into a [`Connector`]: a raw node id (optionally presenting a link) or a link that
    /// supplies both the node to dial and the token. The driving (`preflight`+`run`/`pipe_stdio`, chosen
    /// by `--to`/`--stdio`) is `main.rs` glue over the returned connector.
    pub fn connector(&self) -> eyre::Result<Connector> {
        let service = String::clone(&self.service);
        match &self.target {
            Target::Node(node) => Ok(Connector::to_node(*node, service, self.present.clone())),
            Target::Capability(link) => Connector::from_link(link, service),
        }
    }
}
