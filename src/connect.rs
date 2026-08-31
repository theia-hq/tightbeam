//! `tightbeam connect`: the clap surface for binding a peer's exposed service to a local port, streaming
//! it to stdout, or (reserved) a local unix-socket listener, by node id or by capability link.
//!
//! The `Args` struct + its `Target` parse type + the `connector` resolver live here; the driving body
//! (forward a port or stream stdout) is `main.rs` glue over the library [`Connector`], so tightbeam's CLI
//! is a thin adapter symmetric with swoosh's. The single `--to` selector ([`To`]) replaces the old
//! `--to`/`--stdio` pair, so "which local sink" is one unambiguous, unrepresentable-when-wrong choice.

use core::str::FromStr;
use std::path::PathBuf;

use bifrost::NodeId;
use clap::Args;
use nauthy::{Cap, SCHEME};

use crate::tunnel::Connector;

/// Where a reached service's bytes go locally: the one `--to` selector, parsed to a closed enum so the
/// three sinks are disjoint and "two sinks at once" is unrepresentable (no `ArgGroup`, no two-bool trap).
///
/// The arms are distinguished by a prefix test BEFORE any numeric parse, so `unix:` can never collide with
/// a port, `-` can never collide with a path, and a bare path can never masquerade as either:
///
/// - `unix:<path>` -> [`To::UnixListener`] (everything after the prefix is the path, verbatim); reserved.
/// - `-` -> [`To::Stdout`] (the universal Unix idiom: stream the single service to this process's stdout).
/// - a `u16` in `1..=65535` -> [`To::Port`] (bind `127.0.0.1:<port>`, a local TCP listener).
///
/// Anything else (a bare path, `fifo:`, `file:`, `0`, `70000`) is a hard parse error naming the three
/// legal forms, so a bare path is never a silent anything.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum To {
    /// Bind `127.0.0.1:<port>` and forward each accepted connection to the peer's service (`ssh -L` shaped).
    Port(u16),
    /// Stream the single service to this process's stdout (composes with the shell: `> file`, `| mpv -`).
    Stdout,
    /// Bind a local `AF_UNIX` listener at `<path>` (the unix-domain analog of a port). RESERVED: parsing
    /// recognizes it so a `unix:` target is never a silent misparse, but the listener is not yet built.
    UnixListener(PathBuf),
}

impl FromStr for To {
    type Err = eyre::Error;

    fn from_str(text: &str) -> eyre::Result<Self> {
        // Prefix-test `unix:` first, then `-`, then a port: the arms are disjoint by their first token, so
        // there is never a "which did you mean" case (see the type docs).
        if let Some(path) = text.strip_prefix("unix:") {
            return Ok(To::UnixListener(PathBuf::from(path)));
        }
        if text == "-" {
            return Ok(To::Stdout);
        }
        match text.parse::<u16>() {
            Ok(port) if port != 0 => Ok(To::Port(port)),
            _ => eyre::bail!(
                "`{text}` is not a valid --to target. Use a port (1..=65535), `-` for stdout (compose \
                 with the shell, e.g. `--to - > out`), or `unix:<path>` for a local socket listener"
            ),
        }
    }
}

/// Reach a peer's exposed service and bind it to a local port, stream it to stdout, or a unix listener.
#[derive(Debug, Args)]
pub struct ConnectCmd {
    /// who to reach: a raw node id, or a `sheer:` capability link
    #[arg(value_name = "peer")]
    pub target: Target,
    /// where to put the stream: a local port, `-` for stdout, or `unix:<path>`
    #[arg(long, value_name = "port | - | unix:PATH")]
    pub to: To,
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
    /// supplies both the node to dial and the token. The driving (`preflight`+`run` for a port, `pipe_stdio`
    /// for `-`, chosen by [`To`]) is `main.rs` glue over the returned connector.
    pub fn connector(&self) -> eyre::Result<Connector> {
        let service = String::clone(&self.service);
        match &self.target {
            Target::Node(node) => Ok(Connector::to_node(*node, service, self.present.clone())),
            Target::Capability(link) => Connector::from_link(link, service),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::To;

    #[test]
    fn to_parses_each_of_the_three_forms_and_rejects_the_rest() {
        assert_eq!("5432".parse::<To>().expect("a port parses"), To::Port(5432));
        assert_eq!("-".parse::<To>().expect("stdout parses"), To::Stdout);
        assert_eq!(
            "unix:/run/x.sock".parse::<To>().expect("unix parses"),
            To::UnixListener("/run/x.sock".into())
        );
        // A bare path, a source-only scheme, and out-of-range ports are hard errors, never a silent
        // misparse (a bare path must never look like a port, `fifo:`/`file:` are the shell's job).
        for bad in [
            "/tmp/out",
            "fifo:/tmp/x",
            "file:out",
            "0",
            "70000",
            "web",
            "",
        ] {
            assert!(bad.parse::<To>().is_err(), "`{bad}` must be rejected");
        }
    }
}
