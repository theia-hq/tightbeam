//! `Connector::open_on`: one admitted stream on a session the caller already holds, over bifrost-mem.
//!
//! The caller dials once and keeps the session; each connector then opens its own service on it, and the
//! host admits every stream on the request that stream carries. The wrapper `open_service` returns runs
//! the same handshake, so both paths put the same bytes on the wire.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use core::time::Duration;

use bifrost::{NoDiscovery, Node, Session as _};
use bifrost_mem::MemTransport;
use nauthy::{Gate, Identity, Link, Service};
use tightbeam::identity::AsVerifyKey as _;
use tightbeam::protocol::{Request, Response};
use tightbeam::tunnel::{CancellationToken, Connector, Router};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::sync::mpsc;

/// Two services ride one held session, each stream admitted on its own request: the third request, for a
/// service the host does not expose, is refused on the same session the first two were admitted on.
#[tokio::test]
async fn open_on_admits_two_services_on_one_session() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let host = echo_host(&["one", "two"]);
            let consumer = Node::new(MemTransport::bind(), NoDiscovery);
            let session = consumer.connect(host).await.unwrap();

            for (name, probe) in [("one", b"to one"), ("two", b"to two")] {
                let dial = Connector::to_node(host, service(name), None);
                let (mut writer, mut reader) = dial.open_on(&session).await.unwrap();
                writer.write_all(probe).await.unwrap();
                let mut echoed = [0u8; 6];
                reader.read_exact(&mut echoed).await.unwrap();
                assert_eq!(&echoed, probe, "{name} echoes on the held session");
            }

            let absent = Connector::to_node(host, service("three"), None);
            assert!(matches!(
                absent.open_on(&session).await,
                Err(bifrost::Error::Refused(_))
            ));
        })
        .await;
}

/// The request `open_on` sends is byte for byte the one a `ServiceSession` stream sends, credentials in
/// both slots included: the two paths share one handshake.
#[tokio::test]
async fn open_on_and_open_service_write_the_same_request() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let host = Node::new(MemTransport::bind(), NoDiscovery);
            let host_id = host.node_id();
            let consumer = Node::new(MemTransport::bind(), NoDiscovery);
            let (heard, mut requests) = mpsc::unbounded_channel();
            tokio::task::spawn_local(record_requests(host, heard));

            let link = member_link(&consumer);
            let dial = || {
                Connector::to_node(host_id, service("svc"), Some(Link::clone(&link)))
                    .with_membership(Link::clone(&link))
            };

            let session = consumer.connect(host_id).await.unwrap();
            dial().open_on(&session).await.unwrap();
            let held = requests.recv().await.unwrap();

            let wrapped = dial().open_service(&consumer).await.unwrap();
            wrapped.open_bi().await.unwrap();
            let fresh = requests.recv().await.unwrap();

            assert_eq!(held, fresh);
            let parsed = Request::read(&mut held.as_slice()).await.unwrap();
            assert_eq!(parsed.service, "svc");
            assert!(parsed.capability.is_some() && parsed.membership.is_some());
        })
        .await;
}

/// A refusal on `open_on` is the typed `Refused` variant, never a stream error carrying a message.
#[tokio::test]
async fn a_refusal_on_open_on_is_typed() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            // Two services, so an absent name is not resolved to the only one.
            let host = echo_host(&["one", "two"]);
            let consumer = Node::new(MemTransport::bind(), NoDiscovery);
            let session = consumer.connect(host).await.unwrap();

            let refused = Connector::to_node(host, service("absent"), None)
                .open_on(&session)
                .await;
            assert!(matches!(refused, Err(bifrost::Error::Refused(_))));
        })
        .await;
}

/// Serve an echo under each of `names` behind an open gate, and return the host's node id.
fn echo_host(names: &[&str]) -> bifrost::NodeId {
    let host = Node::new(MemTransport::bind(), NoDiscovery);
    let id = host.node_id();
    let router = names.iter().fold(Router::new(Gate::Open), |router, name| {
        router.echo(service(name)).unwrap()
    });
    tokio::task::spawn_local(async move {
        router
            .expose()
            .unwrap()
            .run(&host, CancellationToken::new())
            .await
            .unwrap();
    });
    id
}

/// Accept every session and stream, send back the raw bytes of each request, and admit it.
///
/// The dialer writes nothing after its request until it reads the reply, so every byte read before a
/// request parses is that request's.
async fn record_requests(
    host: Node<MemTransport, NoDiscovery>,
    heard: mpsc::UnboundedSender<Vec<u8>>,
) {
    while let Ok(session) = host.accept().await {
        let heard = heard.clone();
        tokio::task::spawn_local(async move {
            while let Ok((mut writer, mut reader)) = session.accept_bi().await {
                let mut bytes = Vec::new();
                let mut chunk = [0u8; 4096];
                while Request::read(&mut bytes.as_slice()).await.is_err() {
                    let read =
                        tokio::time::timeout(Duration::from_secs(5), reader.read(&mut chunk))
                            .await
                            .unwrap()
                            .unwrap();
                    assert_ne!(read, 0, "the stream closed before a whole request");
                    bytes.extend_from_slice(&chunk[..read]);
                }
                heard.send(bytes).unwrap();
                Response::Ok.write(&mut writer).await.unwrap();
            }
        });
    }
}

/// A member link for `device` under a fixed root, so the request carries a real credential in each slot.
fn member_link(device: &Node<MemTransport, NoDiscovery>) -> Link {
    Identity::from_secret(&[7u8; 32])
        .unwrap()
        .mint_member(
            device.node_id().verify_key().unwrap(),
            nauthy::Request::expires_in(Duration::from_secs(3600)),
        )
        .unwrap()
        .link()
        .unwrap()
}

fn service(name: &str) -> Service {
    name.parse().unwrap()
}
