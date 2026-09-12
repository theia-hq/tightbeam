//! Serve a NAMED service by writing your own handler, and reach it by name.
//!
//! The companion to `reach_by_key` (a raw forward) and `gate_a_service` (the
//! gate). Here the node serves a NAMED service: you write a [`Handler`](tightbeam::tunnel::Handler), bind it
//! to a name with one [`Router`](tightbeam::tunnel::Router) call, and tightbeam hands every admitted stream
//! for that name to your code. tightbeam knows only the contract, never what the handler does: a keyless
//! shell, an HTTP fetch, and this toy "shout" service are all the same shape. This is the library's
//! extension point.
//!
//! ```sh
//! cargo run --example named_handler
//! ```
//!
//! It runs on the in-process transport, no network. The handler here upper-cases whatever it receives; swap
//! in a real service and the wiring is identical.

use core::time::Duration;

use bifrost::{NoDiscovery, Node};
use bifrost_mem::MemTransport;
use nauthy::{Gate, Service};
use tightbeam::open_policy::OptIn;
use tightbeam::tunnel::{
    BoxRead, BoxWrite, CancellationToken, Connector, Handler, Router, ServeError, Served,
};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};

/// A named handler: code that consumes ONE admitted stream. This one upper-cases every chunk it receives and
/// writes it back. It gets a [`Served<Self>`](tightbeam::tunnel::Served) proof BY VALUE (it carries the
/// gate's single-use witness), so it can never run for a peer the gate turned away.
/// `type Exposure = OptIn` marks it legitimately public (safe to expose openly if the operator opts in); a
/// service that is remote code execution (a shell) names `type Exposure = Never`, which refuses an open
/// gate when the proof is prepared.
struct Shout;

impl Handler for Shout {
    type Exposure = OptIn;

    async fn serve(
        &self,
        _served: Served<Self>,
        mut writer: BoxWrite,
        mut reader: BoxRead,
    ) -> Result<(), ServeError> {
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
}

// tightbeam's overlay futures are not `Send`, so its tasks run on one thread inside a `LocalSet`.
#[tokio::main(flavor = "current_thread")]
async fn main() -> eyre::Result<()> {
    tokio::task::LocalSet::new().run_until(run()).await
}

async fn run() -> eyre::Result<()> {
    // 1. Two overlay nodes, and expose the `shout` service under the exposer's key. One call binds the name
    //    to the handler VALUE: no registry, no scheme string.
    let exposer = Node::new(MemTransport::bind(), NoDiscovery);
    let exposer_key = exposer.node_id();
    let consumer = Node::new(MemTransport::bind(), NoDiscovery);
    println!("serving the shout service on key {exposer_key}");

    let shout: Service = "shout".parse()?;
    let serving = Router::new(Gate::Open).service(shout, Shout)?.expose()?;
    tokio::task::spawn_local(async move {
        if let Err(e) = serving.run(&exposer, CancellationToken::new()).await {
            eprintln!("exposer stopped: {e}");
        }
        Ok::<_, eyre::Error>(())
    });

    // 2. Reach the `shout` service BY NAME from the other node, bound to a local port.
    let probe = TcpListener::bind("127.0.0.1:0").await?;
    let port = probe.local_addr()?.port();
    drop(probe);
    tokio::task::spawn_local(async move {
        if let Err(e) = async {
            Connector::to_node(exposer_key, "shout".parse()?, None)
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

    // 3. Send a line through the tunnel and watch the handler shout it back.
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
