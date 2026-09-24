//! `tightbeam connect`: bind a peer's exposed service to a local port, stream it to stdout, or (reserved) a
//! local unix-socket listener, by node id or by capability link.
//!
//! The `Args` struct, its `Target` parse type, and the driving body ([`ConnectCmd::run`]) live here, a thin
//! adapter over the library [`Connector`] symmetric with any richer consumer's. The single `--to` selector ([`To`])
//! replaces the old `--to`/`--stdio` pair, so "which local sink" is one unambiguous,
//! unrepresentable-when-wrong choice.

use core::str::FromStr;
use std::path::PathBuf;

use bifrost::{Node, NodeId, Transport};
use clap::Args;
use eyre::WrapErr as _;
use nauthy::{Link, Service};
use tightbeam::tunnel::Connector;

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
    /// who to reach: a raw node id, or a capability link (`<key>.<token>`)
    #[arg(value_name = "peer")]
    pub target: Target,
    /// where to put the stream: a local port, `-` for stdout, or `unix:<path>`
    #[arg(long, value_name = "port | - | unix:PATH")]
    pub to: To,
    /// which exposed service to reach
    // REQUIRED, with no default. It defaulted to `default`, which stopped being a real name when the
    // default service name was dropped from the host side (`44bc974`), and the single-service leniency
    // cannot stand in for it whenever a host exposes more than one. So an omitted `--service` dialed a
    // name nothing answers to and the far gate refused with a message that named nothing. Naming the
    // service is now clap's own "required argument" error, before a single packet leaves.
    #[arg(long, value_name = "service")]
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
    /// A capability link (`<key>.<token>`) to present to a `cap`-gated host.
    Capability(String),
}

impl FromStr for Target {
    type Err = eyre::Error;

    fn from_str(text: &str) -> eyre::Result<Self> {
        // A key holds no `.` and a link holds exactly one, so the shape alone says which was given.
        if text.contains('.') {
            // Parse it now so a malformed link fails fast at the CLI boundary, not mid-connect: the
            // connector reparses the validated text so the token travels whole to the host.
            text.parse::<Link>()?;
            Ok(Target::Capability(text.to_owned()))
        } else {
            Ok(Target::Node(text.parse::<NodeId>()?))
        }
    }
}

impl ConnectCmd {
    /// tightbeam's `connect` adapter: resolve the target into a library [`Connector`], then drive the sink
    /// the single `--to` selector names -- bind a local port and forward each accepted connection, stream the
    /// service to stdout (`--to -`, a ProxyCommand-shaped stdio bridge), or a reserved unix listener. [`To`] is one
    /// closed enum, so the sink is unambiguous with no arg group and no missing-means-stdio inference.
    pub async fn run<T: Transport, D: bifrost::Discovery>(
        self,
        node: &Node<T, D>,
    ) -> eyre::Result<()> {
        let connector = self.connector()?;
        match self.to {
            To::Port(port) => {
                // Prove the gate admits us BEFORE announcing readiness: `preflight` reaches, probes
                // admission, and binds the port, returning an error (with the host's reason) on refusal.
                // Only past it is "forwarding …" true, so an unauthorized forward fails loudly here, never
                // a fake success then a silent reset.
                let (dial, service) = (connector.dial(), Service::clone(connector.service()));
                let forward = connector.preflight(node, port).await?;
                println!("forwarding 127.0.0.1:{port} to {dial} ({service})");
                forward.run().await
            }
            To::Stdout => connector.pipe_stdio(node).await,
            To::UnixListener(path) => eyre::bail!(
                "--to unix:{} is reserved, not yet built (bind a port and connect to it, or use `--to -`)",
                path.display()
            ),
        }
    }

    /// Resolve the target into a [`Connector`]: a raw node id (optionally presenting a link) or a link that
    /// supplies both the node to dial and the token.
    fn connector(&self) -> eyre::Result<Connector> {
        let service = self
            .service
            .parse::<Service>()
            .wrap_err_with(|| format!("`{}` is not a valid service name", self.service))?;
        match &self.target {
            Target::Node(node) => {
                let present = self
                    .present
                    .as_ref()
                    .map(|text| text.parse::<Link>())
                    .transpose()?;
                Ok(Connector::to_node(*node, service, present))
            }
            Target::Capability(text) => Ok(Connector::from_link(&text.parse::<Link>()?, service)),
        }
    }
}

#[cfg(test)]
mod tests {
    use clap::Parser as _;

    use super::{Target, To};

    /// `--service` is REQUIRED: there is no `default` to fall back on, so a dial names the service or
    /// does not leave. This fails the moment a `default_value` comes back, which is the point: the
    /// phantom default shipped for a year and turned every zero-flag dial into a refusal the host could
    /// not explain.
    #[test]
    fn connect_requires_the_service_name() {
        let peer = bifrost::NodeId::from_ed25519_secret(&[3u8; 32]).to_string();
        crate::Cli::try_parse_from([
            "tightbeam",
            "connect",
            &peer,
            "--service",
            "web",
            "--to",
            "-",
        ])
        .expect("a named service parses");
        assert!(
            crate::Cli::try_parse_from(["tightbeam", "connect", &peer, "--to", "-"]).is_err(),
            "a dial with no --service must be refused at the parser, not at the far gate"
        );
    }

    /// A peer is a key or a link, told apart by the `.` a link carries and a key never does: the link
    /// text nauthy prints dials and presents with no prefix, and a key dials on its own.
    #[test]
    fn connect_takes_a_key_or_a_link_by_shape() {
        let identity = nauthy::Identity::from_secret(&[3u8; 32]).expect("valid secret");
        let service = "web".parse::<nauthy::Service>().expect("a service name");
        let link = nauthy::Link::mint(&identity, &service, core::time::Duration::from_secs(60))
            .expect("mint a link")
            .to_string();
        assert!(
            matches!(link.parse::<Target>().expect("a link parses"), Target::Capability(text) if text == link),
            "the minted link text is a capability target: {link}"
        );
        let key = bifrost::NodeId::from_ed25519_secret(&[3u8; 32]);
        assert!(
            matches!(key.to_string().parse::<Target>().expect("a key parses"), Target::Node(node) if node == key),
            "a key is a node target"
        );
        assert!(
            format!("app:{link}").parse::<Target>().is_err(),
            "anything before the key fails to parse"
        );
    }

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
