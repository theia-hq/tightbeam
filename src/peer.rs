//! Direct address hints + the composed discovery, so a local peer is reached WITHOUT the internet.
//!
//! tightbeam binds iroh, which self-discovers a remote peer via n0. But for a peer on the same LAN or at
//! a known address (a container on the same Docker network, say), going out to n0 is needless latency and
//! an internet dependency. This layers explicit peer-address hints (the [`Peer`] inputs, `<key>=<addr>`)
//! over LAN mDNS: a hinted or heard peer is reached directly, and n0 stays the fallback for a remote peer
//! with no local hint. (mDNS does not cross a Docker bridge, so in containers an
//! explicit [`Peer`] hint is the mechanism.)

use core::net::SocketAddr;
use core::str::FromStr;
use std::net::ToSocketAddrs;

use bifrost::{Layered, NodeId, StaticDiscovery, Transport};
use bifrost_mdns::MdnsDiscovery;
use eyre::WrapErr as _;

/// The discovery tightbeam composes: explicit [`Peer`] hints layered over LAN mDNS (iroh keeps n0 as the
/// fallback for a remote peer no hint named).
pub type Discovery = Layered<StaticDiscovery, MdnsDiscovery>;

/// A direct hint for one peer: its [`NodeId`] mapped to reachable addresses. Parsed from `<key>=<host:port>`,
/// where the host may be an IP OR a DNS name (a Docker service name, a LAN host): it is resolved via the
/// system resolver at parse time, so a readable `<key>=nodea:9000` reaches a container by name
/// through the network's own DNS.
#[derive(Debug, Clone)]
pub struct Peer {
    node: NodeId,
    addrs: Vec<SocketAddr>,
}

impl Peer {
    /// Compose the discovery for a freshly bound transport: the [`Peer`] hints layered over an mDNS
    /// resolver that advertises this node locally and browses the LAN. Degrades to hints-only if mDNS
    /// cannot start (multicast blocked), rather than failing the command.
    pub fn discovery<T: Transport>(
        transport: &T,
        peers: impl IntoIterator<Item = Self>,
    ) -> Discovery {
        let mut hints = StaticDiscovery::new();
        for Self { node, addrs } in peers {
            hints.insert(node, addrs);
        }
        let local = transport.local_addr();
        let mdns = match MdnsDiscovery::advertise(local.node, local.hints) {
            Ok(mdns) => mdns,
            Err(err) => {
                tracing::warn!(error = %err, "mDNS discovery unavailable; using explicit peer hints only");
                MdnsDiscovery::disabled()
            }
        };
        Layered::new(hints, mdns)
    }
}

impl FromStr for Peer {
    type Err = eyre::Report;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let (key, host) = text
            .split_once('=')
            .ok_or_else(|| eyre::eyre!("expected <key>=<host:port>"))?;
        let node = key.parse().wrap_err("invalid peer key")?;
        // An IP passes through; a DNS name (Docker service, LAN host) resolves via the system resolver.
        let addrs: Vec<SocketAddr> = host
            .to_socket_addrs()
            .wrap_err_with(|| format!("could not resolve peer address {host:?}"))?
            .collect();
        if addrs.is_empty() {
            eyre::bail!("peer address {host:?} resolved to no addresses");
        }
        Ok(Self { node, addrs })
    }
}
