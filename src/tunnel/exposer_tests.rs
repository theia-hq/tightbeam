//! Tests for the exposer: the door interlocks [`Router::expose`](crate::tunnel::Router::expose) runs, the
//! banner manifest it renders, the served path end to end, and the cancel that ends it.

use std::collections::HashMap;

use bifrost::{NoDiscovery, Node};
use bifrost_mem::MemTransport;
use nauthy::Gate;
use tokio::io::AsyncReadExt as _;

use super::Exposer;
use crate::enabled::AllEnabled;
use crate::open_policy::OptIn;
use crate::raw_stream::RawStream;
use crate::tunnel::fixtures::{
    GatedNoop, OpenNoop, ServiceStream, family_gate, prove, services, svc,
};
use crate::tunnel::router::{
    PublicRequest, PublicServices, PublicUnsafeRequest, Route, Services, Target,
};
use crate::tunnel::{
    BoxRead, BoxWrite, CancellationToken, Handler, Metering, Posture, RawSource, ServeError,
    Served, TargetKind,
};

/// A legitimately-public responder that also declares itself [`Metering::Unmetered`]: the shape of
/// `ping`/`speed`, so a manifest reads the caveat off the handler, not a name list.
struct AmplifierNoop;
impl Handler for AmplifierNoop {
    type Exposure = OptIn;
    fn metering(&self) -> Metering {
        Metering::Unmetered
    }
    async fn serve(
        &self,
        _served: Served<Self>,
        _writer: BoxWrite,
        _reader: BoxRead,
    ) -> Result<(), ServeError> {
        Ok(())
    }
}

/// A handler that declares itself [`Metering::Metered`]: the manifest must render exactly what the
/// handler reports, independent of the trait default.
struct MeteredNoop;
impl Handler for MeteredNoop {
    type Exposure = OptIn;
    fn metering(&self) -> Metering {
        Metering::Metered
    }
    async fn serve(
        &self,
        _served: Served<Self>,
        _writer: BoxWrite,
        _reader: BoxRead,
    ) -> Result<(), ServeError> {
        Ok(())
    }
}

/// A single-service `Services` whose one target is a `stdin:`-shaped source over `reader`, so the full
/// served path can be exercised with known bytes instead of the process's real fd 0.
fn stdin_service(name: &str, reader: BoxRead) -> Services {
    let mut map = HashMap::new();
    map.insert(
        name.to_owned(),
        Route::family(Target::RawStream(RawStream::from_reader(reader))),
    );
    Services(map)
}

/// A single-service `Services` whose one target is a `stdin:+lossy`-shaped FAN-OUT source over `reader`, so
/// the full multi-consumer served path (one shared ring, N cursors) runs without the process's real fd 0.
fn lossy_service(name: &str, reader: BoxRead) -> Services {
    let mut map = HashMap::new();
    map.insert(
        name.to_owned(),
        Route::family(Target::RawStream(RawStream::lossy_from_reader(reader))),
    );
    Services(map)
}

/// The readiness manifest reads posture off the PROVEN overlay, kind off the target, and the metering
/// caveat off the handler's declaration, name-sorted: an opened unmetered responder reads
/// `Open + Unmetered`, a gated one keeps its declaration (the caveat is the handler's, independent of
/// posture), and the built-in forward is neither open nor unmetered-warned (its handler IS the default
/// `Unmetered`, which is the honest read of the built-in). This is what feeds a caller's grouped serve
/// banner.
#[test]
fn the_manifest_declares_posture_kind_and_metering() {
    let services = services(&["web=tcp:127.0.0.1:80"])
        .with_handler("fast", AmplifierNoop)
        .expect("`fast` binds");
    let services = services
        .with_handler("quiet", MeteredNoop)
        .expect("`quiet` binds");
    let exposer = prove(
        services,
        family_gate("manifest"),
        PublicRequest::new(["fast".to_owned()]),
        PublicUnsafeRequest::none(),
    )
    .expect("assembles");

    let manifest = exposer.manifest();
    let names: Vec<&str> = manifest.iter().map(|e| e.name.as_str()).collect();
    assert_eq!(names, ["fast", "quiet", "web"], "manifest is name-sorted");

    let fast = &manifest[0];
    assert_eq!(fast.posture, Posture::Open, "`fast` was opened per-service");
    assert_eq!(fast.kind, TargetKind::Handler);
    assert_eq!(
        fast.metering,
        Some(Metering::Unmetered),
        "the opened unmetered responder declares its caveat"
    );

    let quiet = &manifest[1];
    assert_eq!(quiet.posture, Posture::Gated, "`quiet` stays gated");
    assert_eq!(
        quiet.metering,
        Some(Metering::Metered),
        "the caveat is the handler's, shown independent of posture"
    );

    let web = &manifest[2];
    assert_eq!(web.kind, TargetKind::Handler);
    assert_eq!(web.posture, Posture::Gated);
    assert!(
        web.raw_source.is_none(),
        "a forward has no raw source to warn about"
    );
}

/// The metering default: a handler that does not override [`Handler::metering`] reports
/// [`Metering::Unmetered`] through the erased bridge (the fail-loud direction: an open service warns),
/// and a handler that overrides it reports exactly its own declaration.
#[test]
fn metering_defaults_to_unmetered_and_reads_the_override() {
    let services = services(&["web=tcp:127.0.0.1:80"])
        .with_handler("plain", OpenNoop)
        .expect("`plain` binds");
    let services = services
        .with_handler("bounded", MeteredNoop)
        .expect("`bounded` binds");
    let exposer = prove(
        services,
        Gate::Open,
        PublicRequest::new(["plain".to_owned(), "bounded".to_owned()]),
        PublicUnsafeRequest::none(),
    )
    .expect("both are OptIn, so an open gate builds");

    let manifest = exposer.manifest();
    let plain = manifest
        .iter()
        .find(|entry| entry.name == "plain")
        .expect("`plain` is in the manifest");
    assert_eq!(
        plain.metering,
        Some(Metering::Unmetered),
        "the trait default is the fail-loud Unmetered"
    );
    let bounded = manifest
        .iter()
        .find(|entry| entry.name == "bounded")
        .expect("`bounded` is in the manifest");
    assert_eq!(bounded.metering, Some(Metering::Metered));
}

#[test]
fn a_public_gate_over_a_lossy_source_is_refused_at_the_same_door() {
    // A `+lossy` fan-out is still a raw-stream source with no auth of its own: a public gate over it would
    // serve the piped bytes to anyone. It must be refused at the SAME door as a non-lossy raw stream, so
    // `+lossy` cannot reopen the raw-byte exfil this door exists to close.
    let lossy = services(&["cam=stdin:+lossy"]);
    assert!(
        prove(
            lossy,
            Gate::Open,
            PublicRequest::none(),
            PublicUnsafeRequest::none()
        )
        .is_err(),
        "an open gate over a `+lossy` raw-stream source must be refused"
    );
}

#[test]
fn an_exposer_refuses_an_open_gate_over_a_gated_only_handler() {
    // A gated-only handler (`type Exposure = Never`): it has no legitimate public use, so an open gate
    // over it would serve it to anyone. The proof door must reject that pairing, wherever the caller
    // assembles it.
    let gated = Services(HashMap::new())
        .with_handler("a", GatedNoop)
        .expect("`a` binds");
    assert!(
        prove(
            gated,
            Gate::Open,
            PublicRequest::none(),
            PublicUnsafeRequest::none()
        )
        .is_err(),
        "an open gate over a gated-only handler must be refused"
    );
    // The same handler behind a real gate is fine; only the open-gate pairing is refused. A family gate
    // needs a signet and denylist, so prove the inverse with a plain forward under the open gate.
    let web = services(&["web=tcp:127.0.0.1:80"]);
    assert!(
        prove(
            web,
            Gate::Open,
            PublicRequest::none(),
            PublicUnsafeRequest::none()
        )
        .is_ok(),
        "an open gate over a plain forward is allowed"
    );
}

/// A member-only route under a node-wide open gate is a DEAD route: an open gate proves nothing about a
/// peer, so its only witness is a slip and the floor would refuse every dialer. Refused at the door, not
/// served as a route that answers no one.
#[test]
fn a_member_only_route_under_an_open_gate_is_refused_at_construction() {
    let services = services(&["web=tcp:127.0.0.1:80"])
        .member_only("web")
        .expect("`web` is served");
    let Err(error) = prove(
        services,
        Gate::Open,
        PublicRequest::none(),
        PublicUnsafeRequest::none(),
    ) else {
        panic!("a member-only route under an open gate must be refused at construction");
    };
    let message = error.to_string();
    assert!(
        message.contains("member-only") && message.contains("web"),
        "the refusal names the route and the contradiction: {message:?}"
    );
}

/// A member-only route named public is contradictory: the public overlay admits through `Gate::Open`,
/// whose only witness is a slip, so the route would refuse every dialer while the catalog renders it
/// `Open` (a posture lie). Refused where the overlay is proven.
#[test]
fn a_member_only_route_named_public_is_refused_at_construction() {
    let services = services(&["web=tcp:127.0.0.1:80"])
        .member_only("web")
        .expect("`web` is served");
    let Err(error) = prove(
        services,
        family_gate("member-public"),
        PublicRequest::new(["web".to_owned()]),
        PublicUnsafeRequest::none(),
    ) else {
        panic!("a member-only route must not be opened to everyone");
    };
    let message = error.to_string();
    assert!(
        message.contains("member-only") && message.contains("web"),
        "the refusal names the route and the contradiction: {message:?}"
    );
}

/// A member-only raw stream named in the unsafe overlay is the same dead route as the safe public case,
/// and the same posture lie: the opened stream admits through `Gate::Open` (a slip), so the floor would
/// refuse every dialer while the manifest renders it `Open`.
#[test]
fn a_member_only_raw_stream_named_public_unsafe_is_refused_at_construction() {
    let path = std::env::temp_dir().join("tb-member-unsafe");
    let entry = format!("logs=file:{}", path.display());
    let services = services(&[&entry])
        .member_only("logs")
        .expect("`logs` is served");
    let Err(error) = prove(
        services,
        family_gate("member-unsafe"),
        PublicRequest::none(),
        PublicUnsafeRequest::new(["logs".to_owned()]),
    ) else {
        panic!("a member-only raw stream in the unsafe set must be refused at construction");
    };
    let message = error.to_string();
    assert!(
        message.contains("member-only") && message.contains("logs"),
        "the refusal names the route and the contradiction: {message:?}"
    );
}

#[test]
fn an_exposer_refuses_a_public_raw_stream() {
    // A raw-stream source (`file:`/`fifo:`) has no auth of its own: under an open gate it would serve a
    // chosen path's bytes to anyone, so a public gate over `file:<secret>` would exfil it. Refused at the
    // same door as a public shell UNLESS the operator knowingly names it unsafe (that path is covered by
    // `an_exposer_admits_a_public_raw_stream_named_in_public_unsafe`). With an EMPTY unsafe set it bails.
    let secret = services(&["leak=file:/etc/hosts"]);
    assert!(
        prove(
            secret,
            Gate::Open,
            PublicRequest::none(),
            PublicUnsafeRequest::none()
        )
        .is_err(),
        "an open gate over a file:/fifo: source with no unsafe opt-in must be refused"
    );
    // A raw forward the operator deliberately stood up (host:port) stays open-able; only the no-auth
    // raw-stream source is refused under the open gate.
    let web = services(&["web=tcp:127.0.0.1:80"]);
    assert!(
        prove(
            web,
            Gate::Open,
            PublicRequest::none(),
            PublicUnsafeRequest::none()
        )
        .is_ok(),
        "an open gate over a host:port forward is still allowed"
    );
}

#[test]
fn an_exposer_admits_a_public_raw_stream_named_in_public_unsafe() {
    // The escape hatch: an open BASE gate over a `file:` source that the operator KNOWINGLY named in the
    // unsafe opt-in set BUILDS (the door is relaxed per-name), and the manifest reports that name Open, a
    // RawStream, carrying its resolved absolute source for the banner warning.
    let path = std::env::temp_dir().join("tb-public-unsafe-admits");
    let entry = format!("logs=file:{}", path.display());
    let services = services(&[&entry]);
    let exposer = prove(
        services,
        Gate::Open,
        PublicRequest::none(),
        PublicUnsafeRequest::new(["logs".to_owned()]),
    )
    .expect("a raw stream named in the unsafe set builds under an open gate");

    let manifest = exposer.manifest();
    let logs = manifest
        .iter()
        .find(|entry| entry.name == "logs")
        .expect("`logs` is in the manifest");
    assert_eq!(
        logs.posture,
        Posture::Open,
        "the unsafe-open raw stream reads Open"
    );
    assert_eq!(logs.kind, TargetKind::RawStream, "it is a raw stream");
    let Some(RawSource::Path(absolute)) = &logs.raw_source else {
        panic!("a file: raw stream declares a resolved absolute Path source: {logs:?}");
    };
    assert!(
        std::path::Path::new(absolute).is_absolute(),
        "the banner source is an absolute path (std::path::absolute), got {absolute:?}"
    );
}

#[test]
fn echo_is_admitted_under_plain_public_with_no_unsafe_opt_in() {
    // The whole point of the built-in reflector: it is the ONE thing a newcomer can open to strangers
    // under a PLAIN public gate, with no louder raw-stream opt-in. Prove both public doors admit it:
    // (1) the per-service SAFE overlay opens it, and it reads Open + Handler in the manifest with no
    //     raw-source warning; and
    // (2) a node-wide open BASE gate over `Gate::Open` with an EMPTY unsafe set BUILDS, where a raw
    //     stream would have been refused and redirected to the unsafe raw-stream set.
    let per_service = prove(
        services(&["demo=echo:"]),
        family_gate("echo-public"),
        PublicRequest::new(["demo".to_owned()]),
        PublicUnsafeRequest::none(),
    )
    .expect("echo is safe public, so a plain public gate opens it with no unsafe opt-in");

    let manifest = per_service.manifest();
    let demo = manifest
        .iter()
        .find(|entry| entry.name == "demo")
        .expect("`demo` is in the manifest");
    assert_eq!(demo.posture, Posture::Open, "the opened echo reads Open");
    assert_eq!(demo.kind, TargetKind::Handler, "it is a bound handler");
    assert!(
        demo.raw_source.is_none(),
        "echo exposes no raw source, so there is nothing to warn about: {demo:?}"
    );
    assert_eq!(
        demo.metering,
        Some(Metering::Metered),
        "echo reflects the caller's own bytes (symmetric), so it does not carry the unmetered caveat"
    );

    assert!(
        prove(
            services(&["demo=echo:"]),
            Gate::Open,
            PublicRequest::none(),
            PublicUnsafeRequest::none(),
        )
        .is_ok(),
        "a node-wide open gate over an echo reflector builds with no unsafe opt-in (unlike a raw stream)"
    );
}

#[test]
fn public_unsafe_over_a_device_or_directory_is_refused_at_serve() {
    // The banner must never advertise bytes the dial will refuse: a `file:` source that is a DEVICE or a
    // DIRECTORY is refused at connect, so naming it in the unsafe set is refused loudly at SERVE (in
    // `Exposer::new`, before any banner), rather than printed as "serving the raw bytes of ..." and then
    // refused mid-dial. Both `/dev/null` (a char device) and the temp dir (a directory) EXIST, so the
    // serve-time `lstat` sees the always-refused type.
    let device = services(&["drain=file:/dev/null"]);
    let Err(via_device) = prove(
        device,
        Gate::Open,
        PublicRequest::none(),
        PublicUnsafeRequest::new(["drain".to_owned()]),
    ) else {
        panic!(
            "a device named in the unsafe set must be refused at serve, not advertised then refused"
        );
    };
    assert!(
        via_device.to_string().contains("character device"),
        "the serve-time refusal names the device type: {via_device}"
    );

    let dir_entry = format!("logs=file:{}", std::env::temp_dir().display());
    let directory = services(&[&dir_entry]);
    let Err(via_dir) = prove(
        directory,
        Gate::Open,
        PublicRequest::none(),
        PublicUnsafeRequest::new(["logs".to_owned()]),
    ) else {
        panic!("a directory named in the unsafe set must be refused at serve");
    };
    assert!(
        via_dir.to_string().contains("directory"),
        "the serve-time refusal names the directory type: {via_dir}"
    );
}

#[test]
fn public_unsafe_naming_a_handler_or_forward_is_redirected() {
    // The disjoint-token partition: the unsafe overlay is ONLY for raw streams. A handler or a forward
    // named in it is a teaching redirect to the public overlay, never silently
    // opened.
    let handler = Services(HashMap::new())
        .with_handler("ping", OpenNoop)
        .expect("`ping` binds");
    let Err(via_handler) = prove(
        handler,
        family_gate("unsafe-handler"),
        PublicRequest::none(),
        PublicUnsafeRequest::new(["ping".to_owned()]),
    ) else {
        panic!("a handler named unsafe must be redirected, not opened");
    };
    assert!(
        via_handler.to_string().contains("not a raw byte source")
            && via_handler.to_string().contains("public set"),
        "a handler named unsafe is redirected to the public overlay: {via_handler}"
    );

    let forward = services(&["web=tcp:127.0.0.1:80"]);
    let Err(via_forward) = prove(
        forward,
        family_gate("unsafe-forward"),
        PublicRequest::none(),
        PublicUnsafeRequest::new(["web".to_owned()]),
    ) else {
        panic!("a forward named unsafe must be redirected, not opened");
    };
    assert!(
        via_forward.to_string().contains("not a raw byte source")
            && via_forward.to_string().contains("public set"),
        "a forward named unsafe is redirected to the public overlay: {via_forward}"
    );
}

#[test]
fn public_unsafe_naming_an_unserved_name_is_a_parse_error() {
    // A name the node does not serve, named unsafe, bails with the served list (parse-don't-validate at
    // the door), never silently opening nothing.
    let services = services(&["cam=stdin:"]);
    let Err(error) = prove(
        services,
        family_gate("unsafe-unserved"),
        PublicRequest::none(),
        PublicUnsafeRequest::new(["nope".to_owned()]),
    ) else {
        panic!("an unserved name in the unsafe set must bail");
    };
    assert!(
        error.to_string().contains("no service named"),
        "an unserved unsafe name is refused with the served list: {error}"
    );
}

/// A DESIGN-LOCK marker with no operand today: the toggle mutual-exclusion interlock is OWED but not yet
/// buildable. A live-toggle allowlist (the set of services a peer may re-enable at runtime) is unbuilt, so
/// there is no second set for `Exposer::new` to refuse against a `public_unsafe` set; inventing a toggle
/// field now purely to refuse it would be machinery for a case that cannot occur yet. This test records
/// the acceptance criterion instead: when the toggle allowlist lands it enters `Exposer::new` beside
/// `public_unsafe` and adds ONE bail refusing their co-presence
/// (`!proven_unsafe.is_empty() && !toggleable.is_empty()`), because a remotely flippable toggle over an
/// open raw byte source is a re-armable exfil. Replace this marker with the live construction-fail test
/// once the toggle set exists. Today, an unsafe set alone builds (no toggle operand to conflict with).
#[test]
fn public_unsafe_alone_builds_and_the_toggle_interlock_stays_a_design_lock() {
    let path = std::env::temp_dir().join("tb-public-unsafe-designlock");
    let entry = format!("logs=file:{}", path.display());
    let services = services(&[&entry]);
    // No toggle operand exists today, so an unsafe set on its own is fully legal.
    assert!(
        prove(
            services,
            Gate::Open,
            PublicRequest::none(),
            PublicUnsafeRequest::new(["logs".to_owned()]),
        )
        .is_ok(),
        "an unsafe raw-stream set alone builds; the toggle mutual-exclusion is owed a toggle set"
    );
}

#[test]
fn an_exposer_refuses_a_public_stdin() {
    // `stdin:` has no auth of its own: under an open gate it would pipe the producer's bytes to anyone, so
    // a public gate over `stdin:` would exfil them. Refused at the same door as a public shell or a public file:.
    let piped = services(&["cam=stdin:"]);
    assert!(
        prove(
            piped,
            Gate::Open,
            PublicRequest::none(),
            PublicUnsafeRequest::none()
        )
        .is_err(),
        "an open gate over a stdin: source with no unsafe opt-in must be refused"
    );
}

/// The full served path: an exposer over a `stdin:`-shaped source, a connector reaching it over the
/// in-process transport, and the peer receiving the source's EXACT bytes. Drives the same take-once +
/// `Target::RawStream` splice the served path uses, with an injected reader in place of the real fd 0. A second
/// concurrent connection finds the source taken and is refused cleanly (not a corrupted second read).
#[tokio::test]
async fn a_stdin_source_is_served_to_the_peer_and_a_second_reader_is_refused() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let body: &'static [u8] = b"live bytes piped into the exposer";
            let services = stdin_service("cam", Box::new(body));

            let exposer_node = Node::new(MemTransport::bind(), NoDiscovery);
            let exposer_id = exposer_node.node_id();
            let consumer = Node::new(MemTransport::bind(), NoDiscovery);

            // Drive the SERVE path directly. `Exposer::new`'s public-gate refusal for a raw-stream source
            // is covered separately (`an_exposer_refuses_a_public_stdin`); here we construct the exposer
            // past that door so the open gate keeps the peer admitted with no token, and the test isolates
            // the take-once + splice path a `stdin:` source runs.
            let exposer = Exposer {
                services,
                gate: Gate::Open,
                public: PublicServices::default(),
                public_unsafe: PublicServices::default(),
                enabled: Box::new(AllEnabled),
            };
            tokio::task::spawn_local(async move {
                exposer
                    .run(&exposer_node, CancellationToken::new())
                    .await
                    .expect("exposer runs");
            });

            // First consumer: opens a service stream, gets Ok, and reads the source's exact bytes.
            let session = consumer.connect(exposer_id).await.expect("connect");
            let service = ServiceStream::open(&session, "cam")
                .await
                .expect("first stream admitted");
            let got = service.read_all().await.expect("read the piped bytes");
            assert_eq!(got, body, "the reaching peer gets the source's exact bytes");

            // Second CONCURRENT connection: the source is taken, so the host refuses cleanly with the
            // single-consumer reason, never a racing (corrupting) second read.
            let session2 = consumer.connect(exposer_id).await.expect("second connect");
            let Err(refusal) = ServiceStream::open(&session2, "cam").await else {
                panic!("the second reader must be refused, not a racing second read");
            };
            let bifrost::Refusal::Unavailable { detail } = &refusal else {
                panic!("the second reader must be refused as unavailable, got: {refusal:?}");
            };
            assert!(
                detail
                    .as_str()
                    .contains("single-consumer source, already in use"),
                "the refusal must name the single-consumer contract: {detail}"
            );
        })
        .await;
}

/// The full served path for the built-in reflector: an exposer over an `echo:` target, a connector
/// reaching it over the in-process transport, and the peer receiving its OWN bytes back verbatim. Drives
/// the exact `builtins::Echo` loopback the exposer serves. The open BASE gate keeps the peer admitted with
/// no token, isolating the reflect path (the safe-public admission is covered by
/// `echo_is_admitted_under_plain_public_with_no_unsafe_opt_in`).
#[tokio::test]
async fn an_echo_service_reflects_the_clients_own_bytes() {
    use tokio::io::AsyncWriteExt as _;

    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let exposer_node = Node::new(MemTransport::bind(), NoDiscovery);
            let exposer_id = exposer_node.node_id();
            let consumer = Node::new(MemTransport::bind(), NoDiscovery);

            let exposer = prove(
                services(&["demo=echo:"]),
                Gate::Open,
                PublicRequest::none(),
                PublicUnsafeRequest::none(),
            )
            .expect("echo builds under an open gate with no unsafe opt-in (it is safe public)");
            tokio::task::spawn_local(async move {
                exposer
                    .run(&exposer_node, CancellationToken::new())
                    .await
                    .expect("exposer runs");
            });

            let session = consumer.connect(exposer_id).await.expect("connect");
            let mut stream = ServiceStream::open(&session, "demo")
                .await
                .expect("echo admits the reaching peer under the open gate");

            // Send our bytes, then half-close so the reflector's copy hits EOF, closes, and we can read to
            // EOF. The peer gets back EXACTLY what it sent: a loopback of its own input, no host resource.
            let body = b"reflect these bytes back to me";
            stream.writer.write_all(body).await.expect("write the body");
            stream
                .writer
                .shutdown()
                .await
                .expect("half-close toward the host");
            let mut got = Vec::new();
            stream
                .reader
                .read_to_end(&mut got)
                .await
                .expect("read the echo");
            assert_eq!(got, body, "echo returns the client's own bytes verbatim");
        })
        .await;
}

/// The cancel path: `Exposer::run` returns gracefully when its cancel token fires, so any
/// holder of a CLONE of this token can stop the node. Here the token is cancelled from OUTSIDE the run
/// (the shape any such holder uses); the run must finish with `Ok(())` rather than accept forever. Uses
/// the mem transport so no real socket is bound.
#[tokio::test]
async fn run_returns_gracefully_when_its_cancel_token_fires() {
    let node = Node::new(MemTransport::bind(), NoDiscovery);
    let exposer = Exposer {
        services: services(&["web=tcp:127.0.0.1:80"]),
        gate: Gate::Open,
        public: PublicServices::default(),
        public_unsafe: PublicServices::default(),
        enabled: Box::new(AllEnabled),
    };
    let cancel = CancellationToken::new();

    // Run the exposer, then cancel it: the run is idle (no peer connects), so its accept loop is parked
    // on `accept`. Cancelling must wake it and return `Ok(())`, bounded so a regression (a run that
    // ignores the token and accepts forever) fails as a timeout rather than hanging the suite.
    let handle = tokio::spawn({
        let cancel = cancel.clone();
        async move { exposer.run(&node, cancel).await }
    });
    cancel.cancel();
    let ended = tokio::time::timeout(core::time::Duration::from_secs(5), handle)
        .await
        .expect("a cancelled run must return promptly, not accept forever")
        .expect("the run task joins");
    assert!(
        ended.is_ok(),
        "a cancelled run returns Ok(()), not an error: {ended:?}"
    );
}

/// FAN-OUT: a `+lossy` source served to N consumers over the in-process transport,
/// each receiving the source's bytes from ONE shared ring. The source is a duplex whose write half the test
/// holds, so all N consumers attach BEFORE any bytes flow (a live session, not a replay); then the body is
/// written once and every consumer reads it. This drives the exact `Target::RawStream(RawStream::lossy)`
/// serve path, proving one source fans out to many independent cursors.
#[tokio::test]
async fn a_lossy_source_fans_out_to_many_consumers() {
    use tokio::io::AsyncWriteExt as _;

    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let body: &'static [u8] = b"one live source, fanned out to every consumer";
            // A duplex source: the exposer reads one end, the test writes the other AFTER all consumers
            // have attached (a live session), so no consumer misses the start.
            let (mut source_writer, source_reader) = tokio::io::duplex(4096);
            let services = lossy_service("cam", Box::new(source_reader));

            let exposer_node = Node::new(MemTransport::bind(), NoDiscovery);
            let exposer_id = exposer_node.node_id();
            let consumer = Node::new(MemTransport::bind(), NoDiscovery);

            // Past the public-gate door (covered by `a_public_gate_over_a_lossy_source_is_refused...`): an
            // open gate keeps every peer admitted so the test isolates the fan-out splice path.
            let exposer = Exposer {
                services,
                gate: Gate::Open,
                public: PublicServices::default(),
                public_unsafe: PublicServices::default(),
                enabled: Box::new(AllEnabled),
            };
            tokio::task::spawn_local(async move {
                exposer
                    .run(&exposer_node, CancellationToken::new())
                    .await
                    .expect("exposer runs");
            });

            // Attach N consumers: each opens a stream and is admitted (Response::Ok), the first lazy-opening
            // the source and arming the ring, the rest attaching to it. Hold them all before writing.
            const N: usize = 4;
            let mut streams = Vec::new();
            for _ in 0..N {
                let session = consumer.connect(exposer_id).await.expect("connect");
                streams.push(
                    ServiceStream::open(&session, "cam")
                        .await
                        .expect("consumer admitted to the fan-out"),
                );
            }

            // Now write the body once and close the source: the pump copies it into the one ring, and every
            // cursor drains the same bytes. The body fits the ring, so no consumer lags -> each gets it all.
            source_writer.write_all(body).await.expect("write source");
            drop(source_writer);

            for stream in streams {
                let got = stream.read_all().await.expect("read the fan-out");
                assert_eq!(
                    got, body,
                    "each of the N consumers receives the source's exact bytes from the one ring"
                );
            }
        })
        .await;
}

/// SECURITY, the discovery oracle: a dialer the gate does NOT admit must get ONE
/// indistinguishable refusal on the wire. No reason separates a stranger (no token) from a revoked
/// holder from a not-granting token, and no response enumerates or confirms a service. This test dials a
/// Family-gated node four ways -- a stranger, a revoked-slip holder, an unknown-service probe, and a
/// slip-for-the-wrong-service holder -- and asserts every refusal is the same payload-free
/// `NotAdmitted` (one wire code, nothing after it), so the wire is not a revocation oracle and not a
/// capability-enumeration oracle. The gate is the discovery boundary: existence, shape, and verdict are
/// revealed only AFTER admission.
#[tokio::test]
async fn an_unadmitted_dialer_gets_one_uniform_refusal_no_reason_no_menu() {
    use nauthy::{FileDenylist, Identity};

    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            // The signet that roots the family, and a real exposed service (`ssh`) plus a second name
            // (`web`) so the node has a genuine menu that MUST NOT leak. The bodies are irrelevant: every
            // dial here is refused at the gate or at the unknown-service arm, never served.
            let signet = Identity::from_secret(&[7u8; 32]).expect("valid secret");
            let hour = nauthy::Request::expires_in(core::time::Duration::from_secs(3600));

            let mut map = HashMap::new();
            map.insert(
                "ssh".to_owned(),
                Route::family(Target::RawStream(RawStream::from_reader(Box::new(
                    &b"secret"[..],
                )))),
            );
            map.insert(
                "web".to_owned(),
                Route::family(Target::RawStream(RawStream::from_reader(Box::new(
                    &b"secret"[..],
                )))),
            );
            let services = Services(map);

            // A slip the family once honored for `ssh`, now REVOKED: the revoked-but-persistent holder.
            let revoked_slip = signet.mint(&svc("ssh"), hour).expect("mint ssh slip");
            let path =
                std::env::temp_dir().join(format!("tb-uniform-refusal-{}", std::process::id()));
            let _ = std::fs::remove_file(&path);
            let mut denylist = FileDenylist::load(path.clone())
                .await
                .expect("load denylist");
            denylist
                .revoke(&revoked_slip)
                .await
                .expect("revoke the slip");

            let exposer = Exposer {
                services,
                gate: Gate::rooted(signet.verifying_key(), denylist),
                public: PublicServices::default(),
                public_unsafe: PublicServices::default(),
                enabled: Box::new(AllEnabled),
            };

            let exposer_node = Node::new(MemTransport::bind(), NoDiscovery);
            let exposer_id = exposer_node.node_id();
            let consumer = Node::new(MemTransport::bind(), NoDiscovery);
            tokio::task::spawn_local(async move {
                exposer
                    .run(&exposer_node, CancellationToken::new())
                    .await
                    .expect("exposer runs");
            });

            // Every dial opens a fresh session/stream (each stream is gated on its own merits).
            let dial = |service: &'static str, cap: Option<String>| {
                let consumer = &consumer;
                async move {
                    let session = consumer.connect(exposer_id).await.expect("connect");
                    match ServiceStream::open_with(&session, service, cap).await {
                        Ok(_) => panic!("dial for {service:?} must be refused, not served"),
                        Err(refusal) => refusal,
                    }
                }
            };

            // (a) a STRANGER: no token at all -> gate refuses (Missing) -> `NotAdmitted`.
            let stranger = dial("ssh", None).await;
            // (b) a REVOKED holder: presents the now-denylisted `ssh` slip -> gate refuses (Revoked).
            let revoked = dial("ssh", Some(revoked_slip.link().expect("link").to_string())).await;
            // (c) an UNKNOWN-SERVICE probe by a stranger: gate refuses the unknown name -> NotAdmitted.
            let unknown = dial("admin", None).await;
            // (d) a WRONG-SERVICE slip: a valid, UNREVOKED slip for `web` presented for `ssh` -> gate
            //     refuses (NotGranted). Distinct internal reason, must still be the same wire class.
            let wrong_slip = signet.mint(&svc("web"), hour).expect("mint web slip");
            let not_granted = dial("ssh", Some(wrong_slip.link().expect("link").to_string())).await;

            // The whole point: all four are the SAME payload-free `NotAdmitted`, so no consumer can
            // tell revoked from stranger from not-granted, and none can confirm `ssh` exists or that
            // `admin` does not.
            assert_eq!(
                stranger, revoked,
                "a revoked holder and a stranger must get the same refusal (no revocation oracle)"
            );
            assert_eq!(
                stranger, unknown,
                "an unknown-service probe must be indistinguishable from a refused known service"
            );
            assert_eq!(
                stranger, not_granted,
                "a not-granting slip must get the same refusal as a stranger (no capability oracle)"
            );

            // And the refusal renders NOTHING distinguishing: no cause word, no service name, no menu.
            // The `NotAdmitted` phrase names both credential kinds by policy ("no member badge
            // or capability ... was accepted"), the same bytes for every cause, so it is not a leak.
            let rendered = stranger.to_string();
            for leaked in [
                "revoked", "requires", "grant", "exposes", "unknown", "ssh", "web", "admin",
            ] {
                assert!(
                    !rendered.contains(leaked),
                    "the uniform refusal must not leak {leaked:?}: {rendered:?}"
                );
            }

            let _ = std::fs::remove_file(&path);
        })
        .await;
}

/// The unknown-service menu must not cross the wire even to an ADMITTED caller: under an open gate every
/// dialer is admitted, yet a probe for a name the node does not expose still gets the uniform refusal,
/// never the sorted "this node exposes: ..." menu that used to enumerate the surface. (The teaching hint
/// returns as the gated `control.services` verb, not as a free menu on the wrong-name path.)
#[tokio::test]
async fn an_unknown_service_probe_never_gets_the_menu_even_when_admitted() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let mut map = HashMap::new();
            map.insert(
                "cam".to_owned(),
                Route::family(Target::RawStream(RawStream::from_reader(Box::new(
                    &b"x"[..],
                )))),
            );
            map.insert(
                "mic".to_owned(),
                Route::family(Target::RawStream(RawStream::from_reader(Box::new(
                    &b"x"[..],
                )))),
            );
            let exposer = Exposer {
                services: Services(map),
                        gate: Gate::Open,
                public: PublicServices::default(),
                public_unsafe: PublicServices::default(),
                enabled: Box::new(AllEnabled),
            };

            let exposer_node = Node::new(MemTransport::bind(), NoDiscovery);
            let exposer_id = exposer_node.node_id();
            let consumer = Node::new(MemTransport::bind(), NoDiscovery);
            tokio::task::spawn_local(async move {
                exposer.run(&exposer_node, CancellationToken::new()).await.expect("exposer runs");
            });

            let session = consumer.connect(exposer_id).await.expect("connect");
            let Err(refusal) = ServiceStream::open(&session, "nope").await else {
                panic!("an unknown service must be refused, not served");
            };
            let rendered = refusal.to_string();
            for leaked in ["cam", "mic", "exposes", "unknown"] {
                assert!(
                    !rendered.contains(leaked),
                    "an admitted unknown-service probe must not learn the menu; leaked {leaked:?}: {rendered:?}"
                );
            }
        })
        .await;
}

/// The public proof is the wall (BLOCKER-2): it refuses a `Never` handler named public with a teaching
/// error (leading with the fix, never leaking the marker names), refuses a name the node does not serve,
/// and REDIRECTS a raw stream named in the SAFE overlay toward the unsafe overlay (a distinct message
/// from the `Never`-handler hard refusal). The three walls are disjoint.
#[test]
fn the_public_proof_refuses_a_never_handler_a_raw_stream_and_an_unexposed_name() {
    let table = || {
        Services::parse(&["logs=file:/etc/hosts".to_owned()])
            .expect("the raw stream parses")
            .with_handler("ssh", GatedNoop)
            .expect("`ssh` binds")
            .with_handler("speed", OpenNoop)
            .expect("`speed` binds")
    };

    // A Never handler named public is refused: the teaching error names the SERVICE and the fix, never a
    // marker type. (A stranger never sees it; it is a build-time bail to the operator's own terminal.)
    let Err(never) = prove(
        table(),
        family_gate("never"),
        PublicRequest::new(["ssh".to_owned()]),
        PublicUnsafeRequest::none(),
    ) else {
        panic!("a Never handler cannot be opened");
    };
    let message = never.to_string();
    assert!(
        message.contains("ssh") && message.contains("gated"),
        "the refusal names the service and leads with the fix: {message:?}"
    );
    for marker in ["Never", "OptIn"] {
        assert!(
            !message.contains(marker),
            "the refusal must not leak the marker name {marker:?}: {message:?}"
        );
    }

    // A raw stream named in the SAFE overlay is REDIRECTED to the unsafe overlay, with a message DISTINCT
    // from the `Never`-handler refusal.
    let Err(raw) = prove(
        table(),
        family_gate("rawredirect"),
        PublicRequest::new(["logs".to_owned()]),
        PublicUnsafeRequest::none(),
    ) else {
        panic!("a raw stream cannot be opened by the safe overlay; it is redirected");
    };
    let raw_message = raw.to_string();
    assert!(
        raw_message.contains("raw byte source") && raw_message.contains("unsafe raw-stream set"),
        "a raw stream in the safe overlay is redirected to the unsafe raw-stream set: {raw_message:?}"
    );
    assert_ne!(
        raw_message, message,
        "the raw-stream redirect is a distinct message from the Never-handler hard refusal"
    );

    // A name the node does not serve is refused, and the error names what it DOES serve.
    let Err(unknown) = prove(
        table(),
        family_gate("unknown"),
        PublicRequest::new(["nope".to_owned()]),
        PublicUnsafeRequest::none(),
    ) else {
        panic!("an unexposed name cannot be opened");
    };
    assert!(
        unknown.to_string().contains("no service named"),
        "an unexposed public name is refused with the served list: {unknown}"
    );
}
