//! Tests for the route table: the `name=target` grammar, the typed bind verbs, the access floor a
//! route carries, and the catalog the router assembles.

use std::collections::HashMap;
use std::sync::Arc;

use nauthy::Gate;

use super::{Access, PublicRequest, PublicUnsafeRequest, Router, Services, Target};
use crate::raw_stream::RawStream;
use crate::tunnel::fixtures::{GatedNoop, OpenNoop, family_gate, services, svc};
use crate::tunnel::{Posture, ServiceCatalog, TargetKind};

#[test]
fn a_bare_service_name_is_rejected_with_a_hint() {
    // Every serve entry must be `name=target`; a bare entry names no service and fails at parse.
    let Err(err) = Services::parse(&["web".to_owned()]) else {
        panic!("bare `web` should be rejected, not served");
    };
    assert!(
        err.to_string().contains("name=target"),
        "the error should teach the grammar: {err}"
    );
}

#[test]
fn a_bare_scheme_without_a_name_is_rejected() {
    // Bare `ping:` names no service either: only `ping=ping:` is spelled.
    let Err(err) = Services::parse(&["ping:".to_owned()]) else {
        panic!("bare `ping:` should be rejected, not served");
    };
    assert!(
        err.to_string().contains("name=target"),
        "the error should teach the grammar: {err}"
    );
}

/// A duplicate name is refused by the same policy `with_handler` and `Registry::extend` apply: a silent
/// overwrite would drop the first target (and could move a member floor off the route it was declared on).
#[test]
fn a_duplicate_service_name_is_refused_by_parse() {
    let Err(err) = Services::parse(&["web=127.0.0.1:80".to_owned(), "web=127.0.0.1:81".to_owned()])
    else {
        panic!("a duplicate name must be refused, never silently overwritten");
    };
    assert!(
        err.to_string().contains("already defined"),
        "the refusal names the duplicate: {err}"
    );
}

#[test]
fn real_targets_parse() {
    for entry in [
        "web=127.0.0.1:8080",
        "db=unix:/run/db.sock",
        "pipe=file:/tmp/beam",
        "named=fifo:/tmp/beam",
        "demo=echo:",
    ] {
        assert!(
            Services::parse(&[entry.to_owned()]).is_ok(),
            "{entry} should parse"
        );
    }
}

/// A bare `<scheme>:` used to name a registry handler. Handlers bind by value on the Router, so the
/// scheme namespace is a teaching error now, never a silently-dangling target.
#[test]
fn a_handler_scheme_entry_is_a_teaching_error() {
    for entry in [
        "a=handler:",
        "status=control.status:",
        "restart=control.restart:",
    ] {
        let Err(err) = Services::parse(&[entry.to_owned()]) else {
            panic!("`{entry}` names a handler scheme and must be refused");
        };
        assert!(
            err.to_string().contains("handler scheme"),
            "the refusal teaches the binding shape: {err}"
        );
    }
}

#[test]
fn raw_stream_schemes_resolve_to_a_raw_stream_target_never_a_bare_forward_or_handler() {
    // `file:`/`fifo:` carry a PATH tail, so they must resolve to the guarded raw-stream forward, NEVER
    // a plain `Target::Forward` (which would splice unguarded) nor a `Target::Handler` (a bare scheme).
    // Pin it so a future refactor cannot regress the routing into an unguarded shape.
    for entry in ["pipe=file:/tmp/beam", "named=fifo:/tmp/beam"] {
        let Services(parsed) = services(&[entry]);
        let route = parsed.values().next().expect("one service parsed");
        assert!(
            matches!(&route.target, super::Target::RawStream(_)),
            "{entry} must resolve to Target::RawStream, got {route:?}"
        );
    }
    // A bare `file:`/`fifo:` with no path is NOT a handler: it fails loudly at parse.
    assert!(
        Services::parse(&["pipe=file:".to_owned()]).is_err(),
        "`file:` with no path must be rejected, never treated as a handler scheme"
    );
    assert!(
        Services::parse(&["pipe=fifo:".to_owned()]).is_err(),
        "`fifo:` with no path must be rejected, never treated as a handler scheme"
    );
}

#[test]
fn a_named_service_pointed_at_a_bogus_addr_is_rejected() {
    assert!(Services::parse(&["web=nonsense".to_owned()]).is_err());
}

#[test]
fn echo_scheme_resolves_to_the_builtin_reflector() {
    // `echo:` is the zero-arg built-in reflector, now a first-party handler value: parsing it must
    // produce the built-in Echo, never a forward. Pin the routing so it stays a first-class built-in.
    let Services(parsed) = services(&["demo=echo:"]);
    let route = parsed.values().next().expect("one service parsed");
    assert!(
        matches!(&route.target, super::Target::Handler(_)),
        "`echo:` must resolve to a bound handler, got {route:?}"
    );
    assert_eq!(route.target.kind(), TargetKind::Handler);
    // `echo:` takes no argument and tolerates no `+lossy` (it is not a raw-stream source): both are refused
    // at parse, loudly at expose.
    assert!(
        Services::parse(&["demo=echo:+lossy".to_owned()]).is_err(),
        "`echo:+lossy` must be rejected: echo is not a fan-out raw-stream source"
    );
    // The typed verb is the sugar the README teaches: `.echo(name)` is `.service(name, Echo)`.
    let exposer = Router::new(Gate::Open)
        .echo(svc("demo"))
        .expect("echo binds")
        .expose()
        .expect("echo is OptIn, so an open gate serves it with no unsafe opt-in");
    let manifest = exposer.manifest();
    let demo = manifest
        .iter()
        .find(|entry| entry.name == "demo")
        .expect("`demo` is in the manifest");
    assert_eq!(demo.posture, Posture::Open);
    assert_eq!(demo.kind, TargetKind::Handler);
    assert!(
        demo.raw_source.is_none(),
        "echo exposes no raw source, so there is nothing to warn about: {demo:?}"
    );
}

#[test]
fn lossy_is_accepted_only_on_stdin_and_fifo_and_rejected_elsewhere() {
    // `+lossy` opts a live single-writer source into fan-out; it is legal ONLY on `stdin:`/`fifo:`.
    for entry in ["cam=stdin:+lossy", "cam=fifo:/tmp/cam+lossy"] {
        let Services(parsed) = services(&[entry]);
        let route = parsed.values().next().expect("one service parsed");
        assert!(
            matches!(&route.target, Target::RawStream(_)),
            "{entry} must resolve to a raw-stream fan-out target, got {route:?}"
        );
    }
    // On any OTHER scheme `+lossy` is refused at PARSE with a teaching message: a `file:` (static bytes,
    // dropping would be corruption), a `host:port` / `unix:` forward, or a handler scheme are not
    // loss-tolerant live sources. Rejected loudly at expose, not silently ignored.
    for entry in [
        "doc=file:/etc/hosts+lossy",
        "web=127.0.0.1:8080+lossy",
        "db=unix:/run/db.sock+lossy",
        "a=handler:+lossy",
    ] {
        let Err(err) = Services::parse(&[entry.to_owned()]) else {
            panic!("`+lossy` on {entry} must be rejected at parse");
        };
        assert!(
            err.to_string().contains("`+lossy`"),
            "the refusal must name the modifier: {err}"
        );
    }
}

#[test]
fn a_dotted_name_binds_a_handler_for_a_method_on_an_interface() {
    // A method on an interface (`control.status`, `control.restart`) is one dotted SERVICE NAME: `.` is
    // in the `Service` alphabet, so a handler binds under the dotted name directly, never through a
    // scheme-string grammar.
    for name in ["control.status", "control.restart"] {
        let services = Services(HashMap::new())
            .with_handler(name, OpenNoop)
            .expect("a dotted name binds");
        assert!(
            services.0.contains_key(name),
            "the dotted name is preserved verbatim as the route key, got {name:?}"
        );
    }
}

/// Access is opt-in per route: every parsed route defaults to [`Access::Family`] (the gate alone
/// decides), and `member_only` flips exactly the named route to [`Access::Member`].
#[test]
fn routes_default_to_family_and_member_only_flips_the_named_route() {
    let parsed = services(&["web=127.0.0.1:80", "locked=127.0.0.1:81"]);
    let Services(routes) = &parsed;
    assert!(
        routes.values().all(|route| route.access == Access::Family),
        "parsed routes default to the gate-alone floor"
    );
    let parsed = parsed.member_only("locked").expect("`locked` is served");
    let Services(routes) = &parsed;
    assert_eq!(routes["web"].access, Access::Family);
    assert_eq!(routes["locked"].access, Access::Member);
}

/// Marking a name the node does not serve is a caller error, exactly like a duplicate in `with_handler`:
/// a silent no-op would leave the operator believing a floor exists that does not.
#[test]
fn member_only_refuses_a_name_the_node_does_not_serve() {
    let Err(error) = services(&["web=127.0.0.1:80"]).member_only("nope") else {
        panic!("marking an unserved name must be refused");
    };
    assert!(
        error.to_string().contains("no service named"),
        "the refusal teaches the served list: {error}"
    );
}

#[test]
fn stdin_resolves_to_a_raw_stream_target_routed_before_the_bare_scheme_arm() {
    // `stdin:` is a zero-arg raw-stream source: it must resolve to `Target::RawStream`, NOT a
    // `Target::Handler("stdin")` (which the bare-scheme arm would produce and no registry would hold).
    // (Under `cargo test` fd 0 is not a tty, so the parse-time TTY refusal does not fire.)
    let Services(parsed) = services(&["cam=stdin:"]);
    let route = parsed.values().next().expect("one service parsed");
    assert!(
        matches!(&route.target, Target::RawStream(_)),
        "`stdin:` must resolve to Target::RawStream, got {route:?}"
    );
}

#[test]
fn a_router_refuses_a_duplicate_across_bind_verbs() {
    // The Router is one add-only table with one duplicate policy: a name bound by `service`, then named
    // again by `parse`, a built-in verb, or a second `service`, is refused at bind. The base case: two
    // `service` binds collide.
    let dup = Router::new(Gate::Open)
        .service(svc("web"), OpenNoop)
        .expect("first bind")
        .service(svc("web"), OpenNoop);
    assert!(
        dup.is_err(),
        "a second bind under one name must be refused, never silently overwrite"
    );
    // A parsed `name=target` entry colliding with a bound handler is the same policy at the same door.
    let through_parse = Router::new(Gate::Open)
        .service(svc("web"), OpenNoop)
        .expect("first bind")
        .parse(&["web=127.0.0.1:80".to_owned()]);
    assert!(
        through_parse.is_err(),
        "the parse entry must refuse the duplicate too"
    );
    // And within one `parse`, the duplicate is refused by the same message.
    let Err(error) = Router::new(Gate::Open)
        .parse(&["web=127.0.0.1:80".to_owned(), "web=127.0.0.1:81".to_owned()])
    else {
        panic!("a duplicate `name=target` entry must be refused");
    };
    assert!(
        error.to_string().contains("already defined"),
        "the refusal names the duplicate: {error}"
    );
}

/// `open_safe` is TOTAL over [`Target`]: a bound handler reads its erased `Exposure` ceiling (an OptIn
/// handler yes, a Never handler never), and a raw stream never (it opens only through the distinct unsafe
/// overlay). The built-ins are OptIn handlers: a deliberately stood-up forward is openable, and the
/// symmetric echo reflector is safe public.
#[test]
fn open_safe_is_total_over_target() {
    let optin: Target = Target::Handler(Arc::new(OpenNoop));
    let never: Target = Target::Handler(Arc::new(GatedNoop));
    let forward: Target = Target::Handler(Arc::new(crate::builtins::Forward::new("127.0.0.1:80")));
    let echo: Target = Target::Handler(Arc::new(crate::builtins::Echo));
    let raw = Target::RawStream(RawStream::from_reader(Box::new(&b"x"[..])));

    assert!(
        forward.open_safe(),
        "a deliberately stood-up forward is openable"
    );
    assert!(
        echo.open_safe(),
        "an echo reflector exposes no host resource, so it is safe public"
    );
    assert!(optin.open_safe(), "an OptIn handler is openable");
    assert!(!never.open_safe(), "a Never handler is never openable");
    assert!(
        !raw.open_safe(),
        "a raw stream has no auth of its own and opens only through the unsafe overlay"
    );
}

/// The scheme namespace is gone: a `fetch_0:`-shaped entry is a handler-scheme teaching error at parse,
/// while the NAME `fetch_0` binds through the typed Router call like any other service name. Nothing is
/// special about an underscore anymore; per-service instances are structural (one `service` call each).
#[test]
fn a_synthetic_shaped_name_is_just_a_bound_name() {
    assert!(
        Services::parse(&["x=fetch_0:".to_owned()]).is_err(),
        "`fetch_0:` is a handler scheme and must be a teaching error"
    );
    let exposer = Router::new(Gate::Open)
        .service(svc("pub"), OpenNoop)
        .expect("a bound name")
        .expose()
        .expect("an OptIn handler under an open gate");
    assert!(
        exposer.manifest().iter().any(|entry| entry.name == "pub"),
        "the bound name is served"
    );
}

/// The catalog reports each service's PER-SERVICE posture: a service in the public request reads `open`,
/// the rest `gated`, under a family base gate. This is what the `control.services` read serves.
#[test]
fn a_catalog_reports_public_services_open_and_the_rest_gated() {
    let services = services(&["web=127.0.0.1:80"])
        .with_handler("speed", OpenNoop)
        .expect("`speed` binds")
        .with_handler("ssh", GatedNoop)
        .expect("`ssh` binds");
    let catalog = services.catalog(
        &family_gate("catalog"),
        &PublicRequest::new(["speed".to_owned()]),
        &PublicUnsafeRequest::none(),
    );
    for entry in catalog.entries() {
        let expected = if entry.name == "speed" {
            Posture::Open
        } else {
            Posture::Gated
        };
        assert_eq!(
            entry.posture,
            expected,
            "`{}` should read {:?} with speed in the public set",
            entry.name,
            expected.label()
        );
    }
}

/// The catalog's self-listing contract: `self_listing` renders the one row whose handler value
/// is being built from the catalog (the member-only `control.services` read) as a GATED entry, sorted in
/// tightbeam with the rest, so a consumer never patches the wire ordering itself.
#[test]
fn a_catalog_self_lists_the_row_being_built_gated() {
    let gate = family_gate("self-listing");
    let router = Router::new(gate)
        .parse(&["aaa=127.0.0.1:81".to_owned()])
        .expect("parses");
    let catalog = router.catalog(Some(svc("control.services")));
    let names: Vec<&str> = catalog.entries().map(|entry| entry.name.as_str()).collect();
    assert_eq!(names, ["aaa", "control.services"], "sorted, row included");
    let self_row = catalog
        .entries()
        .find(|entry| entry.name == "control.services")
        .expect("the self-listing row is present");
    assert_eq!(
        self_row.posture,
        Posture::Gated,
        "the row being built is gated by construction"
    );
    assert_eq!(
        ServiceCatalog::decode(&catalog.encode()).expect("round-trips"),
        catalog
    );
}

/// The Router's typed verbs bind one table and the one terminal proof: a bound handler, the built-in
/// forward, and the built-in reflector all serve from one catalog after `.expose()`, and `parse` absorbs
/// the `name=target` entries alongside them.
#[test]
fn a_router_binds_every_verb_and_proves_at_expose() {
    let exposer = Router::new(Gate::Open)
        .service(svc("ping"), OpenNoop)
        .expect("service binds")
        .forward(svc("web"), "127.0.0.1:80")
        .expect("forward binds")
        .echo(svc("demo"))
        .expect("echo binds")
        .parse(&["db=unix:/run/db.sock".to_owned()])
        .expect("parse absorbs the target grammar")
        .expose()
        .expect("an open gate over OptIn handlers and forwards proves");
    let manifest = exposer.manifest();
    let names: Vec<&str> = manifest.iter().map(|e| e.name.as_str()).collect();
    assert_eq!(
        names,
        ["db", "demo", "ping", "web"],
        "one table, name-sorted"
    );
    assert!(
        manifest
            .iter()
            .all(|entry| entry.posture == Posture::Open && entry.kind == TargetKind::Handler),
        "under the open base every bound route reads Open and Handler"
    );
}

/// A raw stream stays a native target arm: bound through `.raw_stream`, it proves only into the distinct
/// unsafe overlay, and the manifest renders it the loudest group with its resolved source.
#[test]
fn a_raw_stream_stays_a_native_arm_proven_unsafe() {
    let path = std::env::temp_dir().join("tb-native-raw-stream");
    let exposer = Router::new(family_gate("native-raw"))
        .raw_stream(
            svc("logs"),
            RawStream::file(&path.display().to_string(), "logs=file:...")
                .expect("the path shapes a raw stream"),
        )
        .expect("raw stream binds")
        .public_unsafe([svc("logs")])
        .expose()
        .expect("a named unsafe raw stream proves");
    let logs = exposer
        .manifest()
        .into_iter()
        .find(|entry| entry.name == "logs")
        .expect("`logs` is in the manifest");
    assert_eq!(logs.posture, Posture::Open);
    assert_eq!(logs.kind, TargetKind::RawStream);
    assert!(
        logs.raw_source.is_some(),
        "a raw stream declares its resolved source for the banner"
    );
}
