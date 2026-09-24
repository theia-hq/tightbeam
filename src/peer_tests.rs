//! What the composed discovery reads off its transport: bind truth for a serving node, never the
//! rewritten hints, and nothing at all for a dialling one.

use core::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};

use bifrost::{Addr, Error, InProcess, NodeId, Transport};
use bifrost_mdns::{Advertising, MdnsDiscovery, MdnsError};
use bifrost_mem::{MemSession, MemTransport};

use crate::peer::{Peer, Role};

/// A wildcard bind on a fixed port: the shape the rewrite destroys, since `local_addr` reports it as
/// loopback and a publisher cannot then tell it from a node that deliberately bound `127.0.0.1`.
const WILDCARD: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 9000);

/// An address accessor read off the transport, with what it handed back.
#[derive(Debug, PartialEq, Eq)]
enum Read {
    /// The dialable hints, which rewrite an unspecified bind to loopback.
    LocalAddr(Vec<SocketAddr>),
    /// The sockets as bound, unspecified IP preserved.
    BoundSockets(Vec<SocketAddr>),
}

/// A transport over mem's sessions that records which address accessor was read and answers
/// [`bound_sockets`](Transport::bound_sockets) with a wildcard bind of its own.
///
/// The two accessors are indistinguishable downstream (the advertisement goes to the network, not to
/// a value the test holds), so recording the read at the source is what proves which one the
/// composition root trusted.
struct Recording {
    inner: MemTransport,
    reads: Arc<Mutex<Vec<Read>>>,
}

impl Transport for Recording {
    type Security = InProcess;
    type Session = MemSession;

    fn node_id(&self) -> NodeId {
        self.inner.node_id()
    }

    fn local_addr(&self) -> Addr {
        let addr = self.inner.local_addr();
        self.record(Read::LocalAddr(addr.hints.clone()));
        addr
    }

    fn bound_sockets(&self) -> Vec<SocketAddr> {
        self.record(Read::BoundSockets(vec![WILDCARD]));
        vec![WILDCARD]
    }

    async fn connect(&self, addr: Addr) -> Result<Self::Session, Error> {
        self.inner.connect(addr).await
    }

    async fn accept(&self) -> Result<Self::Session, Error> {
        self.inner.accept().await
    }

    async fn close(&self) {
        self.inner.close().await;
    }
}

/// A [`Recording`] transport and the log of what was read off it.
fn recording() -> (Recording, Arc<Mutex<Vec<Read>>>) {
    let reads = Arc::new(Mutex::new(Vec::new()));
    let transport = Recording {
        inner: MemTransport::bind(),
        reads: Arc::clone(&reads),
    };
    (transport, reads)
}

impl Recording {
    /// Note one accessor read. A poisoned lock would only be a panic inside an accessor, which would
    /// have failed the test already.
    fn record(&self, read: Read) {
        self.reads.lock().unwrap().push(read);
    }
}

/// Composing the discovery hands mDNS the transport's bound sockets, and never asks for the hints.
///
/// The advertisement itself may or may not reach the network here (a sandbox blocks multicast, which
/// is the honest degraded path), so the assertion is on what the composition root read, which holds
/// either way.
#[tokio::test]
async fn composing_discovery_advertises_the_bound_sockets() {
    let (transport, reads) = recording();

    let _discovery = Peer::discovery(&transport, [], Role::Serving);

    assert_eq!(
        *reads.lock().unwrap(),
        vec![Read::BoundSockets(vec![WILDCARD])],
        "the advertisement must take raw bind truth, not the loopback-rewritten hints"
    );
}

/// A serving bind hands its bound sockets to the advertisement: a dialer finds it by its key.
#[test]
fn a_serving_bind_advertises_its_bind() {
    let (transport, _reads) = recording();

    assert_eq!(
        Role::Serving.advertised(&transport),
        vec![WILDCARD],
        "a serving node must still publish its bind"
    );
}

/// A dialling bind hands the advertisement no address, and reads none off the transport: there is
/// nothing to publish, so no record on the LAN names this node's key.
#[test]
fn a_dialling_bind_advertises_no_address() {
    let (transport, reads) = recording();

    assert_eq!(
        Role::Dialing.advertised(&transport),
        Vec::<SocketAddr>::new(),
        "a dialling node must publish no address"
    );
    assert_eq!(
        *reads.lock().unwrap(),
        Vec::new(),
        "a dialling node has no reason to read an address to publish"
    );
}

/// Composing a dialling node's discovery reads no address off the transport, so nothing reaches the
/// advertisement.
#[tokio::test]
async fn composing_a_dialling_discovery_reads_no_address() {
    let (transport, reads) = recording();

    let _discovery = Peer::discovery(&transport, [], Role::Dialing);

    assert_eq!(
        *reads.lock().unwrap(),
        Vec::new(),
        "a dialling node's advertisement must be composed from no address"
    );
}

/// The advertisement a dialling node starts is browse-only for want of addresses, the one outcome
/// the report treats as intended rather than degraded.
#[tokio::test]
async fn a_dialling_advertisement_is_browse_only_for_want_of_addresses() {
    let (transport, _reads) = recording();

    let started =
        MdnsDiscovery::advertise(transport.node_id(), Role::Dialing.advertised(&transport))
            .expect("the mDNS service starts");

    assert!(
        matches!(
            started.advertising,
            Advertising::BrowseOnly(MdnsError::NoAddrs)
        ),
        "a dialling node publishes no record: {:?}",
        started.advertising
    );
}
