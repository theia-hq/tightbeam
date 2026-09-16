//! The service catalog: what a node publishes it serves, with the posture a dialer faces, and the
//! self-delimiting wire form the member-only `control.services` read carries it in.
//!
//! The one thing the route table puts on the wire, so its bounds and its decoder live here, apart from the
//! table that fills it: a blob reaching [`ServiceCatalog::decode`] is untrusted.

/// How much a served service costs a stranger to reach: whether the node's gate lets an unauthenticated
/// peer in, or requires a member badge. An enum, not a bool, so a future posture (a per-service gate, a
/// paused service) forces a decision at every match site rather than silently reading as one of these two.
///
/// This is the EFFECTIVE posture a dialer would experience today, read off the node's gate: an
/// [`Gate::Open`](nauthy::Gate::Open) node serves every service to anyone, so each is
/// [`Open`](Posture::Open); any other gate requires a member
/// badge, so each is [`Gated`](Posture::Gated). It is not the handler's compile-time open-safety CEILING
/// (`type Exposure`): a service that COULD be public still reports `Gated` on a gated node, because
/// that is what a caller actually faces.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Posture {
    /// Reaching this service requires a member badge the node's gate admits.
    Gated,
    /// The node's gate is open: anyone who reaches the node reaches this service, no badge.
    Open,
}

impl Posture {
    /// The one-byte wire tag: `0` gated, `1` open. A closed match, so a new posture must extend the wire
    /// deliberately rather than borrow an existing tag.
    const fn tag(self) -> u8 {
        match self {
            Self::Gated => 0,
            Self::Open => 1,
        }
    }

    /// Parse the wire tag back to a posture; an unknown tag is a decode error, never a silent default.
    fn from_tag(tag: u8) -> eyre::Result<Self> {
        match tag {
            0 => Ok(Self::Gated),
            1 => Ok(Self::Open),
            other => eyre::bail!("unknown service posture tag {other:#04x}"),
        }
    }

    /// The word a table renders for this posture (`gated` / `open`), so a caller's table reads at a glance.
    pub fn label(self) -> &'static str {
        match self {
            Self::Gated => "gated",
            Self::Open => "open",
        }
    }
}
/// One served service in a node's catalog: its name and the [`Posture`] a dialer faces reaching it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceEntry {
    /// The service name the exposer published it under (the name a connector requests).
    pub name: String,
    /// The posture a dialer faces reaching this service (gated behind a member badge, or open to anyone).
    pub posture: Posture,
}
/// The services a node SERVES, each with its reach posture: the answer the gated `control.services` read
/// returns. A pure snapshot read from what the exposer was built with (its
/// [`Services`](super::router::Services) + gate), no mutable
/// state. Entries are sorted by name, so the wire is canonical and a rendered table reads in a stable order.
///
/// The wire form (all ints big-endian), self-delimiting so a reader needs no out-of-band length, mirroring
/// the roster blob's count-then-length-prefixed-entries shape:
///
/// ```text
///   count        u32
///   per entry x count, ascending by name:
///     name_len   u16
///     name       [u8; name_len]   (UTF-8)
///     posture    u8               (0 gated, 1 open)
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceCatalog(pub(super) Vec<ServiceEntry>);

/// The largest service-name length the catalog wire admits, bounding the buffer a decoder allocates per
/// entry from an untrusted blob. A service name is short; this is far above any real one.
const MAX_SERVICE_NAME_LEN: usize = 256;

/// The largest number of catalog entries the wire admits, bounding the work a decoder does on an untrusted
/// blob. A node serves a handful of services, never thousands.
const MAX_CATALOG_ENTRIES: usize = 1024;

impl ServiceCatalog {
    /// The served services, in name order.
    pub fn entries(&self) -> impl Iterator<Item = &ServiceEntry> {
        let Self(entries) = self;
        entries.iter()
    }

    /// Encode the catalog to its self-delimiting wire form (see the type's layout). The count and each name
    /// are length-prefixed, so a reader delimits every field with no framing around the blob.
    pub fn encode(&self) -> Vec<u8> {
        let Self(entries) = self;
        let mut out = Vec::new();
        // A node's service count never approaches u32::MAX; the cast is deterministic and the decoder bounds
        // it at MAX_CATALOG_ENTRIES.
        out.extend_from_slice(&(entries.len() as u32).to_be_bytes());
        for entry in entries {
            let name = entry.name.as_bytes();
            // A service name is short (well under u16::MAX, bounded by MAX_SERVICE_NAME_LEN below), so this
            // cast never truncates.
            out.extend_from_slice(&(name.len() as u16).to_be_bytes());
            out.extend_from_slice(name);
            out.push(entry.posture.tag());
        }
        out
    }

    /// Decode a catalog from the wire form written by [`encode`](Self::encode). Bounds-checked against
    /// untrusted input: an over-long name, an over-large count, an unknown posture tag, or trailing bytes is
    /// a clean error, never a panic. The whole blob must be consumed.
    pub fn decode(bytes: &[u8]) -> eyre::Result<Self> {
        let mut cursor = 0;
        let count = take_u32(bytes, &mut cursor)? as usize;
        if count > MAX_CATALOG_ENTRIES {
            eyre::bail!("service catalog names too many services ({count})");
        }
        let mut entries = Vec::with_capacity(count);
        for _ in 0..count {
            let name_len = usize::from(take_u16(bytes, &mut cursor)?);
            if name_len > MAX_SERVICE_NAME_LEN {
                eyre::bail!("service name too long ({name_len} bytes)");
            }
            let name = core::str::from_utf8(take(bytes, &mut cursor, name_len)?)
                .map_err(|_| eyre::eyre!("service name is not valid UTF-8"))?
                .to_owned();
            let posture = Posture::from_tag(take_array::<1>(bytes, &mut cursor)?[0])?;
            entries.push(ServiceEntry { name, posture });
        }
        if cursor != bytes.len() {
            eyre::bail!("service catalog has trailing bytes");
        }
        Ok(Self(entries))
    }
}

/// Read `len` bytes at `cursor`, advancing it, or fail if the blob is too short.
fn take<'a>(bytes: &'a [u8], cursor: &mut usize, len: usize) -> eyre::Result<&'a [u8]> {
    let end = cursor
        .checked_add(len)
        .ok_or_else(|| eyre::eyre!("length overflow"))?;
    let slice = bytes
        .get(*cursor..end)
        .ok_or_else(|| eyre::eyre!("service catalog is truncated"))?;
    *cursor = end;
    Ok(slice)
}

/// Read a fixed-size array at `cursor`, advancing it.
fn take_array<const N: usize>(bytes: &[u8], cursor: &mut usize) -> eyre::Result<[u8; N]> {
    let slice = take(bytes, cursor, N)?;
    let mut array = [0u8; N];
    array.copy_from_slice(slice);
    Ok(array)
}

/// Read a big-endian `u16` at `cursor`, advancing it.
fn take_u16(bytes: &[u8], cursor: &mut usize) -> eyre::Result<u16> {
    Ok(u16::from_be_bytes(take_array::<2>(bytes, cursor)?))
}

/// Read a big-endian `u32` at `cursor`, advancing it.
fn take_u32(bytes: &[u8], cursor: &mut usize) -> eyre::Result<u32> {
    Ok(u32::from_be_bytes(take_array::<4>(bytes, cursor)?))
}

#[cfg(test)]
#[path = "catalog_tests.rs"]
mod catalog_tests;
