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
use bifrost_mdns::{Advertising, MdnsDiscovery, MdnsError, Started};
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

/// Which side of a conversation a bound node is on, and so what of it goes on the LAN.
///
/// A serving node is dialled by its key, so it publishes a record naming that key and its bind. A
/// dialling node reaches out to a key it already holds: nobody needs to find it, and a record would
/// tell every host on the LAN which key is running here, so it publishes none and only browses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// Accepts dials: advertises its key and bind over mDNS.
    Serving,
    /// Only dials: browses mDNS, advertises nothing.
    Dialing,
}

impl Role {
    /// The sockets this role hands to the mDNS advertisement.
    ///
    /// Bind truth for a serving node, never `local_addr`'s hints: the hints rewrite an unspecified
    /// bind to loopback, so handing them over would advertise `127.0.0.1` for a node bound to every
    /// interface and make every LAN dialer reach its own machine. Discovery owns what of the bind is
    /// publishable. A dialling node hands over nothing, so the key never goes on the wire.
    pub fn advertised<T: Transport>(self, transport: &T) -> Vec<SocketAddr> {
        match self {
            Self::Serving => transport.bound_sockets(),
            Self::Dialing => Vec::new(),
        }
    }
}

impl Peer {
    /// Compose the discovery for a freshly bound transport: the [`Peer`] hints layered over an mDNS
    /// resolver that browses the LAN and, for a [`Role::Serving`] node, advertises this node's bind.
    /// Degrades to hints-only if mDNS cannot start (multicast blocked), rather than failing the
    /// command.
    pub fn discovery<T: Transport>(
        transport: &T,
        peers: impl IntoIterator<Item = Self>,
        role: Role,
    ) -> Discovery {
        let mut hints = StaticDiscovery::new();
        for Self { node, addrs } in peers {
            hints.insert(node, addrs);
        }
        let mdns = match MdnsDiscovery::advertise(transport.node_id(), role.advertised(transport)) {
            Ok(Started {
                discovery,
                advertising,
            }) => {
                report(role, &advertising);
                discovery
            }
            Err(err) => {
                tracing::warn!(error = %err, "mDNS discovery unavailable; using explicit peer hints only");
                MdnsDiscovery::disabled()
            }
        };
        Layered::new(hints, mdns)
    }
}

/// Log how far the started advertisement actually reaches.
///
/// The composed [`Discovery`] cannot be asked: a node publishing nothing, a node publishing only
/// loopback, and a node on the LAN all resolve peers identically, and the two degraded ones are
/// invisible to every other host while looking live from the inside. Each arm names its own reach, so
/// a run that cannot be found says why instead of leaving the operator to guess. A dialling node
/// publishing nothing is the intended state, not a degraded one, and says so.
fn report(role: Role, advertising: &Advertising) {
    match (role, advertising) {
        (Role::Dialing, Advertising::BrowseOnly(MdnsError::NoAddrs)) => tracing::debug!(
            "browsing the LAN over mDNS; a dialling node advertises nothing, so no record names its key"
        ),
        (_, Advertising::OnLan(advertised)) => tracing::debug!(
            port = advertised.port(),
            addrs = advertised.addrs().len(),
            "advertising this node on the LAN over mDNS"
        ),
        (_, Advertising::LoopbackOnly(advertised)) => tracing::debug!(
            port = advertised.port(),
            "advertising this node over mDNS on loopback only; a peer on another host needs a direct address hint"
        ),
        (_, Advertising::BrowseOnly(cause)) => tracing::debug!(
            error = %cause,
            "browsing the LAN over mDNS without advertising this node; a peer on another host needs a direct address hint"
        ),
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
