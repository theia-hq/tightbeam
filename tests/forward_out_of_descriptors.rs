//! A port forward that runs out of file descriptors backs off instead of spinning on its failed accept.
//!
//! Its own test binary, with one test: it lowers the process's descriptor limit, which would break any
//! test running beside it.
#![cfg(unix)]

use core::sync::atomic::{AtomicUsize, Ordering};
use core::time::Duration;
use std::fs::File;
use std::io;
use std::sync::Arc;

use bifrost::{NoDiscovery, Node};
use bifrost_mem::MemTransport;
use nauthy::Gate;
use tightbeam::tunnel::{CancellationToken, Connector, Router};
use tokio::net::TcpListener;

/// Counts the forward's failed-accept warnings.
#[derive(Clone, Default)]
struct Failures(Arc<AtomicUsize>);

impl io::Write for Failures {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if String::from_utf8_lossy(bytes).contains("local accept failed") {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Set this process's soft descriptor limit, returning the previous one.
fn set_descriptor_limit(soft: libc::rlim_t) -> libc::rlim_t {
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `limit` is a valid, writable rlimit for the call to fill.
    assert_eq!(
        unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) },
        0
    );
    let previous = limit.rlim_cur;
    limit.rlim_cur = soft;
    // SAFETY: `limit` is a valid rlimit; a soft limit at or below the hard one is always accepted.
    assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limit) }, 0);
    previous
}

/// Connections queued for the forward while it has no descriptor to accept them with. More than a
/// forward that backs off tries in the second the test watches.
const CLIENTS: usize = 30;

#[tokio::test(flavor = "current_thread")]
async fn a_forward_out_of_descriptors_backs_off() {
    let failures = Failures::default();
    let sink = failures.clone();
    let _log = tracing::subscriber::set_default(
        tracing_subscriber::fmt()
            .with_ansi(false)
            .with_max_level(tracing::Level::WARN)
            .with_writer(move || sink.clone())
            .finish(),
    );

    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let echo_addr = echo.local_addr().unwrap();
            let probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = probe.local_addr().unwrap().port();
            drop(probe);

            let exposer = Node::new(MemTransport::bind(), NoDiscovery);
            let exposer_id = exposer.node_id();
            let consumer = Node::new(MemTransport::bind(), NoDiscovery);
            tokio::task::spawn_local(async move {
                Router::new(Gate::Open)
                    .parse(&[format!("echo=tcp:{echo_addr}")])
                    .unwrap()
                    .expose()
                    .unwrap()
                    .run(&exposer, CancellationToken::new())
                    .await
                    .unwrap();
            });
            let forward = Connector::to_node(exposer_id, "default".parse().unwrap(), None)
                .preflight(&consumer, port)
                .await
                .unwrap();
            tokio::task::spawn_local(forward.run());
            tokio::task::yield_now().await;

            // Use up every descriptor but the ones the clients below take, so the forward's accept
            // cannot get one for any connection it is handed.
            let previous = set_descriptor_limit(256);
            let mut spent = Vec::new();
            loop {
                match File::open("/dev/null") {
                    Ok(file) => spent.push(file),
                    Err(error) if error.raw_os_error() == Some(libc::EMFILE) => break,
                    Err(error) => panic!("unexpected open failure: {error}"),
                }
            }
            spent.truncate(spent.len() - CLIENTS);
            // Blocking connects, so the forward is not polled until every client is queued. Each one
            // completes in the kernel's backlog without being accepted.
            let mut clients = Vec::new();
            for _ in 0..CLIENTS {
                clients.push(std::net::TcpStream::connect(("127.0.0.1", port)).unwrap());
            }

            // Every accept now fails: on Linux the connection stays queued and the same accept fails
            // again, on macOS the failed accept drops it and the next one fails. Either way a forward
            // that retries at once fails as fast as it can loop; one that backs off fails about ten
            // times in a second.
            tokio::time::sleep(Duration::from_secs(1)).await;
            let failed = failures.0.load(Ordering::SeqCst);

            drop(clients);
            drop(spent);
            set_descriptor_limit(previous);
            assert!(
                failed > 0,
                "the forward never tried to accept the connection"
            );
            assert!(
                failed <= 15,
                "the forward retried a failing accept {failed} times in a second: it spins"
            );
        })
        .await;
}
