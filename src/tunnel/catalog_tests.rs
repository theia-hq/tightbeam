//! Tests for the catalog: the posture a node publishes per service, and the wire form that snapshot
//! survives a round trip in.

use nauthy::Gate;

use super::{
    CatalogTooLarge, MAX_CATALOG_BLOB, MAX_CATALOG_ENTRIES, MAX_SERVICE_NAME_LEN, Posture,
    ServiceCatalog, ServiceEntry,
};
use crate::tunnel::fixtures::{OpenNoop, services};
use crate::tunnel::router::{PublicRequest, PublicUnsafeRequest};

/// The catalog a gated node serves reports every service as `gated`, name-sorted, and survives a wire
/// round trip byte for byte: the read `control.services` returns and the client decodes are the same value.
#[test]
fn a_gated_catalog_reports_gated_and_round_trips() {
    let services = services(&["c=tcp:127.0.0.1:80"])
        .with_handler("a", OpenNoop)
        .expect("`a` binds");
    let services = services.with_handler("b", OpenNoop).expect("`b` binds");
    let root = nauthy::Identity::from_secret(&[7u8; 32]).expect("valid secret");
    let denylist = nauthy::FileDenylist::empty(std::env::temp_dir().join("tb-catalog-gated"));
    let gate = Gate::rooted(root.verifying_key(), denylist);
    let catalog = services.catalog(&gate, &PublicRequest::none(), &PublicUnsafeRequest::none());

    let names: Vec<&str> = catalog.entries().map(|entry| entry.name.as_str()).collect();
    assert_eq!(names, ["a", "b", "c"], "entries are name-sorted");
    assert!(
        catalog
            .entries()
            .all(|entry| entry.posture == Posture::Gated),
        "a gated node reports every service as gated"
    );

    let blob = catalog
        .encode()
        .expect("a three-service catalog is under the wire bound");
    let decoded = ServiceCatalog::decode(&blob).expect("catalog decodes");
    assert_eq!(decoded, catalog, "the catalog survives a wire round trip");
}

/// An open node reports every service as `open`: the effective posture is read off the node gate, so a
/// public node's catalog says anyone may reach these.
#[test]
fn an_open_catalog_reports_open() {
    let services = services(&["a=tcp:127.0.0.1:80"])
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
        ServiceCatalog::decode(&catalog.encode().expect("under the wire bound")).expect("decodes"),
        catalog
    );
}

/// An empty catalog encodes to a bare count and decodes back to empty (zero / one / many coverage).
#[test]
fn an_empty_catalog_round_trips() {
    let catalog = ServiceCatalog(Vec::new());
    let blob = catalog
        .encode()
        .expect("an empty catalog is under the wire bound");
    let decoded = ServiceCatalog::decode(&blob).expect("empty decodes");
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
    let mut trailing = good.encode().expect("one entry is under the wire bound");
    trailing.push(0);
    assert!(ServiceCatalog::decode(&trailing).is_err());
}

/// The blob bound is DERIVED, so this pins the derivation to the wire it describes: the largest catalog the
/// decoder accepts (every entry slot filled, every name at the name bound) encodes to EXACTLY
/// [`MAX_CATALOG_BLOB`] bytes, and decodes back. A framing change the derivation does not follow shows up
/// here rather than as a reader's cap that quietly admits less, or more, than the decoder does.
#[test]
fn the_largest_admissible_catalog_is_exactly_the_blob_bound() {
    let entries = (0..MAX_CATALOG_ENTRIES)
        .map(|_| ServiceEntry {
            name: "n".repeat(MAX_SERVICE_NAME_LEN),
            posture: Posture::Gated,
        })
        .collect();
    let full = ServiceCatalog(entries);

    let blob = full
        .encode()
        .expect("a catalog at both field bounds is admissible");
    assert_eq!(
        blob.len() as u64,
        MAX_CATALOG_BLOB,
        "the reader's cap is derived from these bounds plus the framing; it must be attainable to the byte"
    );
    assert_eq!(
        ServiceCatalog::decode(&blob).expect("and the decoder takes it"),
        full,
        "the largest blob a reader will accept is one the decoder accepts"
    );
}

/// A catalog past either field bound is refused by the ENCODER, on the serving side, naming what to fix.
/// Without this the node writes a blob no reader will take: over the entry bound it decodes as an error at
/// the far end, and over the name bound the `u16` length prefix WRAPS and the frame decodes as something
/// else entirely. Both bounds are the decoder's own, asserted here against the same blobs, so the two ends
/// cannot drift apart.
#[test]
fn a_catalog_past_a_field_bound_refuses_at_the_encoder() {
    // The negative assertions come first in each pair: with the guards removed both encodes return Ok, and
    // the test must fail HERE, at the assertion that names the guard, rather than further down.
    let over_count = ServiceCatalog(
        (0..=MAX_CATALOG_ENTRIES)
            .map(|index| ServiceEntry {
                name: format!("s{index}"),
                posture: Posture::Gated,
            })
            .collect(),
    );
    let Err(error) = over_count.encode() else {
        panic!("one service past the entry bound must refuse at the encoder");
    };
    assert!(
        matches!(error, CatalogTooLarge::TooManyServices { count, max }
            if count == MAX_CATALOG_ENTRIES + 1 && max == MAX_CATALOG_ENTRIES),
        "the refusal names the count and the bound: {error}"
    );

    let over_name = ServiceCatalog(vec![ServiceEntry {
        name: "n".repeat(MAX_SERVICE_NAME_LEN + 1),
        posture: Posture::Gated,
    }]);
    let Err(error) = over_name.encode() else {
        panic!("one byte past the name bound must refuse at the encoder");
    };
    assert!(
        matches!(error, CatalogTooLarge::NameTooLong { len, max, .. }
            if len == MAX_SERVICE_NAME_LEN + 1 && max == MAX_SERVICE_NAME_LEN),
        "the refusal names the length and the bound: {error}"
    );

    // The same two shapes on the wire: the decoder refuses each from its count and length prefixes alone, so
    // what the encoder refuses to emit is exactly what a reader refuses to take.
    let mut count_prefix = Vec::new();
    count_prefix.extend_from_slice(&((MAX_CATALOG_ENTRIES as u32) + 1).to_be_bytes());
    assert!(
        ServiceCatalog::decode(&count_prefix).is_err(),
        "the decoder refuses the count the encoder refused to write"
    );

    let mut name_prefix = Vec::new();
    name_prefix.extend_from_slice(&1u32.to_be_bytes());
    name_prefix.extend_from_slice(&((MAX_SERVICE_NAME_LEN as u16) + 1).to_be_bytes());
    assert!(
        ServiceCatalog::decode(&name_prefix).is_err(),
        "the decoder refuses the name length the encoder refused to write"
    );
}
