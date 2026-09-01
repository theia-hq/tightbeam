//! Serve a NAMED service by injecting your own handler, and reach it by name.
//!
//! The companion to `reach_by_key` (a raw forward) and `gate_a_service` (the
//! gate). Here the node serves a NAMED service: you write a [`Handler`](tightbeam::tunnel::Handler),
//! register it under a scheme name, and tightbeam hands every admitted stream for that name to your code.
//! tightbeam knows only the contract, never what the handler does: a keyless shell, an HTTP fetch, and this
//! toy "shout" service are all the same shape. This is the library's extension point.
//!
//! ```sh
//! cargo run --example named_handler
//! ```
//!
//! It runs on the in-process transport, no network. The handler here upper-cases whatever it receives; swap
//! in a real service and the wiring is identical.

use core::time::Duration;
use std::sync::Arc;

use bifrost::{NoDiscovery, Node};
use bifrost_mem::MemTransport;
use futures::FutureExt as _;
use nauthy::Gate;
use tightbeam::tunnel::{CancellationToken, Connector, Exposer, Handler, Registry, ServeFn, Services};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};

// tightbeam's overlay futures are not `Send`, so its tasks run on one thread inside a `LocalSet`.
#[tokio::main(flavor = "current_thread")]
async fn main() -> eyre::Result<()> {
    tokio::task::LocalSet::new().run_until(run()).await
}

async fn run() -> eyre::Result<()> {
    // 1. A named handler: code that consumes ONE admitted stream. This one upper-cases every chunk it
    //    receives and writes it back. It gets the gate's `Admitted` witness BY VALUE (proof this peer
    //    passed the gate), so it can never run for a peer the gate turned away. `Handler::open` marks it
    //    safe to expose publicly; a service that is remote code execution (a shell) uses `Handler::gated`,
    //    which refuses an open gate at `Exposer::new`.
    let shout: ServeFn = Arc::new(|_admitted, mut writer, mut reader| {
        async move {
            let mut buf = [0u8; 1024];
            loop {
                let read = reader.read(&mut buf).await?;
                if read == 0 {
                    break;
                }
                buf[..read].make_ascii_uppercase();
                writer.write_all(&buf[..read]).await?;
                writer.flush().await?;
            }
            Ok(())
        }
        .boxed()
    });
    let registry = Registry::new().with("shout", Handler::open(shout));

    // 2. Two overlay nodes, and expose the `shout` service under the exposer's key. `shout=shout:` names a
    //    service `shout` served by the `shout` handler registered above.
    let exposer = Node::new(MemTransport::bind(), NoDiscovery);
    let exposer_key = exposer.node_id();
    let consumer = Node::new(MemTransport::bind(), NoDiscovery);
    println!("serving the shout service on key {exposer_key}");

    let services = Services::parse(&["shout=shout:".to_owned()])?;
    tokio::task::spawn_local(async move {
        if let Err(e) = Exposer::new(services, registry, Gate::Open)?
            .run(&exposer, CancellationToken::new())
            .await
        {
            eprintln!("exposer stopped: {e}");
        }
        Ok::<_, eyre::Error>(())
    });

    // 3. Reach the `shout` service BY NAME from the other node, bound to a local port.
    let probe = TcpListener::bind("127.0.0.1:0").await?;
    let port = probe.local_addr()?.port();
    drop(probe);
    tokio::task::spawn_local(async move {
        if let Err(e) = async {
            Connector::to_node(exposer_key, "shout".to_owned(), None)
                .preflight(&consumer, port)
                .await?
                .run()
                .await
        }
        .await
        {
            eprintln!("connector stopped: {e}");
        }
    });

    // 4. Send a line through the tunnel and watch the handler shout it back.
    let mut client = None;
    for _ in 0..100 {
        if let Ok(stream) = TcpStream::connect(("127.0.0.1", port)).await {
            client = Some(stream);
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let Some(mut client) = client else {
        eyre::bail!("the connector never started listening");
    };

    let message = b"hello from the other node";
    client.write_all(message).await?;
    let mut shouted = vec![0u8; message.len()];
    client.read_exact(&mut shouted).await?;
    println!(
        "sent {:?}, the handler shouted back {:?}",
        String::from_utf8_lossy(message),
        String::from_utf8_lossy(&shouted),
    );
    Ok(())
}
