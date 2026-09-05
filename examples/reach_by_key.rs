//! Reach a service on another node by its public key, over the bifrost overlay.
//!
//! This is the whole tightbeam library in one file. An [`Exposer`](tightbeam::tunnel::Exposer) publishes a
//! local service behind a gate; a [`Connector`](tightbeam::tunnel::Connector) reaches it from another node
//! by that node's public key and binds it to a local port; the caller then talks to it as if it were
//! local. No account, no coordinator, no control plane: the connector reaches the exposer by KEY alone.
//!
//! Run it on one machine, no network and no config needed:
//!
//! ```sh
//! cargo run --example reach_by_key
//! ```
//!
//! It uses bifrost's in-process transport so the two nodes talk without touching the network. Swap
//! `MemTransport` for a real transport (iroh, or our own quirk) and the exact same code reaches a peer
//! across NAT, anywhere, addressed by the same key.

use core::time::Duration;

use bifrost::{NoDiscovery, Node};
use bifrost_mem::MemTransport;
use nauthy::Gate;
use tightbeam::tunnel::{CancellationToken, Connector, Exposer, Registry, Services};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};

// tightbeam's overlay futures are not `Send`, so its tasks run on one thread inside a `LocalSet`.
#[tokio::main(flavor = "current_thread")]
async fn main() -> eyre::Result<()> {
    tokio::task::LocalSet::new().run_until(run()).await
}

async fn run() -> eyre::Result<()> {
    // 1. A local service to expose. Here a tiny TCP echo server; in real use this is your ssh daemon, an
    //    HTTP origin, a database, anything that speaks over a socket.
    let echo = TcpListener::bind("127.0.0.1:0").await?;
    let echo_addr = echo.local_addr()?;
    tokio::task::spawn_local(async move {
        while let Ok((mut sock, _)) = echo.accept().await {
            tokio::task::spawn_local(async move {
                let mut buf = [0u8; 1024];
                while let Ok(n) = sock.read(&mut buf).await {
                    if n == 0 || sock.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });

    // 2. Two overlay nodes. Each is an identity (a public key) plus a transport. The exposer's key is the
    //    only address the consumer needs; with a real transport it is reachable across NAT from anywhere.
    let exposer = Node::new(MemTransport::bind(), NoDiscovery);
    let exposer_key = exposer.node_id();
    let consumer = Node::new(MemTransport::bind(), NoDiscovery);
    println!("exposer is reachable at key {exposer_key}");

    // 3. The exposer forwards every admitted overlay stream to the local echo service. `Gate::Open` admits
    //    anyone who reaches the key; in production you pass a signet gate so only your own devices and the
    //    delegates you signed get in. `Registry::new()` is empty because a raw forward needs no named
    //    handler; you inject `Handler`s (a keyless shell, an HTTP fetcher) for named services.
    let services = Services::parse(&[echo_addr.to_string()])?;
    tokio::task::spawn_local(async move {
        if let Err(e) = Exposer::new(
            services,
            Registry::new(),
            Gate::Open,
            tightbeam::tunnel::PublicUnsafeRequest::none(),
        )?
        .run(&exposer, CancellationToken::new())
        .await
        {
            eprintln!("exposer stopped: {e}");
        }
        Ok::<_, eyre::Error>(())
    });

    // 4. The consumer reaches the exposer's service BY KEY and binds it to a free local port, so anything
    //    that connects to that port is tunnelled to the echo service on the other node.
    let probe = TcpListener::bind("127.0.0.1:0").await?;
    let local_port = probe.local_addr()?.port();
    drop(probe);
    tokio::task::spawn_local(async move {
        if let Err(e) = async {
            Connector::to_node(exposer_key, "default".to_owned(), None)
                .preflight(&consumer, local_port)
                .await?
                .run()
                .await
        }
        .await
        {
            eprintln!("connector stopped: {e}");
        }
    });

    // 5. Use it. Connect to the local port, retrying until the connector is listening, and echo a message
    //    that travels: local port -> consumer node -> (overlay, by key) -> exposer node -> echo service,
    //    and all the way back.
    let mut client = None;
    for _ in 0..100 {
        if let Ok(stream) = TcpStream::connect(("127.0.0.1", local_port)).await {
            client = Some(stream);
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let Some(mut client) = client else {
        eyre::bail!("the connector never started listening");
    };

    let message = b"ping over the overlay";
    client.write_all(message).await?;
    let mut echoed = vec![0u8; message.len()];
    client.read_exact(&mut echoed).await?;
    assert_eq!(&echoed, message, "the echoed bytes must match what we sent");

    println!(
        "sent {:?}, got {:?} back through the tunnel, reached purely by key",
        String::from_utf8_lossy(message),
        String::from_utf8_lossy(&echoed),
    );
    Ok(())
}
