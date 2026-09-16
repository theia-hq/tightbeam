//! Tests for the catalog: the posture a node publishes per service, and the wire form that snapshot
//! survives a round trip in.

use nauthy::Gate;

use super::{Posture, ServiceCatalog, ServiceEntry};
use crate::tunnel::fixtures::{OpenNoop, services};
use crate::tunnel::router::{PublicRequest, PublicUnsafeRequest};

/// The catalog a gated node serves reports every service as `gated`, name-sorted, and survives a wire
/// round trip byte for byte: the read `control.services` returns and the client decodes are the same value.
#[test]
fn a_gated_catalog_reports_gated_and_round_trips() {
    let services = services(&["c=127.0.0.1:80"])
        .with_handler("a", OpenNoop)
        .expect("`a` binds");
    let services = services.with_handler("b", OpenNoop).expect("`b` binds");
    let signet = nauthy::Identity::from_secret(&[7u8; 32]).expect("valid secret");
    let denylist = nauthy::FileDenylist::empty(std::env::temp_dir().join("tb-catalog-gated"));
    let gate = Gate::rooted(signet.verifying_key(), denylist);
    let catalog = services.catalog(&gate, &PublicRequest::none(), &PublicUnsafeRequest::none());

    let names: Vec<&str> = catalog.entries().map(|entry| entry.name.as_str()).collect();
    assert_eq!(names, ["a", "b", "c"], "entries are name-sorted");
    assert!(
        catalog
            .entries()
            .all(|entry| entry.posture == Posture::Gated),
        "a gated node reports every service as gated"
    );

    let decoded = ServiceCatalog::decode(&catalog.encode()).expect("catalog decodes");
    assert_eq!(decoded, catalog, "the catalog survives a wire round trip");
}

/// An open node reports every service as `open`: the effective posture is read off the node gate, so a
/// public node's catalog says anyone may reach these.
#[test]
fn an_open_catalog_reports_open() {
    let services = services(&["a=127.0.0.1:80"])
        .with_handler("b", OpenNoop)
        .expect("`b` binds");
    let catalog = services.catalog(
        &Gate::Open,
        &PublicRequest::none(),
        &PublicUnsafeRequest::none(),
    );
    assert!(
        catalog
            .entries()
            .all(|entry| entry.posture == Posture::Open),
        "an open node reports every service as open"
    );
    assert_eq!(
        ServiceCatalog::decode(&catalog.encode()).expect("decodes"),
        catalog
    );
}

/// An empty catalog encodes to a bare count and decodes back to empty (zero / one / many coverage).
#[test]
fn an_empty_catalog_round_trips() {
    let catalog = ServiceCatalog(Vec::new());
    let decoded = ServiceCatalog::decode(&catalog.encode()).expect("empty decodes");
    assert_eq!(decoded, catalog);
    assert_eq!(decoded.entries().count(), 0);
}

/// A truncated blob, an unknown posture tag, and trailing bytes are clean decode errors, never a panic:
/// the wire is bounds-checked against untrusted input.
#[test]
fn a_malformed_catalog_is_a_clean_error() {
    // A count of 1 but no entry bytes: truncated.
    assert!(ServiceCatalog::decode(&1u32.to_be_bytes()).is_err());

    // One entry with a posture tag of 9 (neither gated nor open).
    let mut bad_tag = Vec::new();
    bad_tag.extend_from_slice(&1u32.to_be_bytes());
    bad_tag.extend_from_slice(&1u16.to_be_bytes());
    bad_tag.push(b'x');
    bad_tag.push(9);
    assert!(ServiceCatalog::decode(&bad_tag).is_err());

    // A well-formed single entry followed by a stray byte: trailing bytes are rejected.
    let good = ServiceCatalog(vec![ServiceEntry {
        name: "a".to_owned(),
        posture: Posture::Gated,
    }]);
    let mut trailing = good.encode();
    trailing.push(0);
    assert!(ServiceCatalog::decode(&trailing).is_err());
}
