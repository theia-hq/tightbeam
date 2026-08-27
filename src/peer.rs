//! Direct address hints + the composed discovery, so a local peer is reached WITHOUT the internet.
//!
//! tightbeam binds iroh, which self-discovers a remote peer via n0. But for a peer on the same LAN or at
//! a known address (a container on the same Docker network, say), going out to n0 is needless latency and
//! an internet dependency. This layers explicit `--peer <key>=<addr>` hints over LAN mDNS: a hinted or
//! heard peer is reached directly, and n0 stays the fallback for a remote peer with no local hint. Mirrors
//! swoosh's seam. (mDNS does not cross a Docker bridge, so in containers `--peer` is the mechanism.)

use core::net::SocketAddr;
use core::str::FromStr;

use bifrost::{Layered, NodeId, StaticDiscovery, Transport};
use bifrost_mdns::MdnsDiscovery;
use eyre::WrapErr as _;

/// The discovery tightbeam composes: explicit `--peer` hints layered over LAN mDNS (iroh keeps n0 as the
/// fallback for a remote peer no hint named).
pub type Discovery = Layered<StaticDiscovery, MdnsDiscovery>;

/// A direct address hint for one peer: its [`NodeId`] mapped to a reachable [`SocketAddr`]. Parsed at the
/// clap boundary from `<key>=<socketaddr>`, so a handler receives an already-valid value.
#[derive(Debug, Clone, Copy)]
pub struct Peer {
    node: NodeId,
    addr: SocketAddr,
}

impl Peer {
    /// Compose the discovery for a freshly bound transport: the `--peer` hints layered over an mDNS
    /// resolver that advertises this node locally and browses the LAN. Degrades to hints-only if mDNS
    /// cannot start (multicast blocked), rather than failing the command.
    pub fn discovery<T: Transport>(
        transport: &T,
        peers: impl IntoIterator<Item = Self>,
    ) -> Discovery {
        let mut hints = StaticDiscovery::new();
        for Self { node, addr } in peers {
            hints.insert(node, vec![addr]);
        }
        let local = transport.local_addr();
        let mdns = match MdnsDiscovery::advertise(local.node, local.hints) {
            Ok(mdns) => mdns,
            Err(err) => {
                tracing::warn!(error = %err, "mDNS discovery unavailable; using --peer hints only");
                MdnsDiscovery::disabled()
            }
        };
        Layered::new(hints, mdns)
    }
}

impl FromStr for Peer {
    type Err = eyre::Report;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let (key, addr) = text
            .split_once('=')
            .ok_or_else(|| eyre::eyre!("expected <key>=<socketaddr>"))?;
        let node = key.parse().wrap_err("invalid peer key")?;
        let addr = addr.parse().wrap_err("invalid peer address")?;
        Ok(Self { node, addr })
    }
}
