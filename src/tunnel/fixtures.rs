//! The test doubles and builders the tunnel's unit tests share: two handlers at either end of the
//! open-safety marker, the one-door prove shortcut, the table builders, and a minimal wire client.

use nauthy::{Gate, Service};
use tokio::io::AsyncReadExt as _;

use super::exposer::Exposer;
use super::router::{PublicRequest, PublicUnsafeRequest, Services};
use super::{BoxRead, BoxWrite, Handler, ServeError, Served};
use crate::open_policy::{Never, OptIn};

/// A do-nothing GATED handler (`type Exposure = Never`): a handler with no public use of its own, so an
/// open gate over it must be refused when the proof is prepared.
pub(super) struct GatedNoop;
impl Handler for GatedNoop {
    type Exposure = Never;
    async fn serve(
        &self,
        _served: Served<Self>,
        _writer: BoxWrite,
        _reader: BoxRead,
    ) -> Result<(), ServeError> {
        Ok(())
    }
}

/// A do-nothing OPEN handler (`type Exposure = OptIn`): a legitimately-public responder, exposable under
/// any gate.
pub(super) struct OpenNoop;
impl Handler for OpenNoop {
    type Exposure = OptIn;
    async fn serve(
        &self,
        _served: Served<Self>,
        _writer: BoxWrite,
        _reader: BoxRead,
    ) -> Result<(), ServeError> {
        Ok(())
    }
}

/// Prove a table + gate + raw requests into the runnable exposer, the one-door shape the assembly tests
/// exercise directly ([`Exposer::prove`]).
pub(super) fn prove(
    services: Services,
    gate: Gate,
    public: PublicRequest,
    public_unsafe: PublicUnsafeRequest,
) -> eyre::Result<Exposer> {
    Exposer::prove(services, gate, public, public_unsafe)
}

pub(super) fn svc(name: &str) -> Service {
    name.parse()
        .unwrap_or_else(|_| panic!("valid service: {name}"))
}

pub(super) fn services(entries: &[&str]) -> Services {
    Services::parse(&entries.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>())
        .expect("entries parse")
}

/// A tiny test client that speaks tightbeam's `Request`/`Response` handshake on one stream, so the unit
/// tests can reach a service without the `Connector`'s port/stdio machinery.
pub(super) struct ServiceStream<W, R> {
    pub(super) writer: W,
    pub(super) reader: R,
}

impl<W, R> ServiceStream<W, R>
where
    W: tokio::io::AsyncWrite + Unpin,
    R: tokio::io::AsyncRead + Unpin,
{
    /// Open a stream, request `service`, and return it on `Ok` or the host's typed refusal.
    pub(super) async fn open<S>(session: &S, service: &str) -> Result<Self, bifrost::Refusal>
    where
        S: bifrost::Session<Write = W, Read = R>,
    {
        Self::open_with(session, service, None).await
    }

    /// Like [`open`](Self::open) but presents `capability`, so a test can dial as a stranger (`None`) or
    /// as a token-holder (a revoked slip). Returns the host's typed refusal verbatim, which is what lets
    /// a test assert two dialers got the SAME refusal value.
    pub(super) async fn open_with<S>(
        session: &S,
        service: &str,
        capability: Option<String>,
    ) -> Result<Self, bifrost::Refusal>
    where
        S: bifrost::Session<Write = W, Read = R>,
    {
        Self::open_with_slots(session, service, capability, None).await
    }

    /// Like [`open_with`](Self::open_with) but also presents a second `membership` slot: a badge under
    /// the foreign fleet a signet-bound slip names, so a test can drive the two-token AND at the gate.
    pub(super) async fn open_with_slots<S>(
        session: &S,
        service: &str,
        capability: Option<String>,
        membership: Option<String>,
    ) -> Result<Self, bifrost::Refusal>
    where
        S: bifrost::Session<Write = W, Read = R>,
    {
        let (mut writer, mut reader) = session.open_bi().await.expect("open a stream");
        crate::protocol::Request {
            service: service.to_owned(),
            capability,
            membership,
        }
        .write(&mut writer)
        .await
        .expect("write request");
        match crate::protocol::Response::read(&mut reader)
            .await
            .expect("read response")
        {
            crate::protocol::Response::Ok => Ok(Self { writer, reader }),
            crate::protocol::Response::Refused(refusal) => Err(refusal),
        }
    }

    /// Read the piped payload to EOF. The exposer half-closes its write when the source hits EOF.
    pub(super) async fn read_all(mut self) -> std::io::Result<Vec<u8>> {
        // Hold the writer open for the stream's lifetime (dropping it early would half-close our side
        // before the peer finishes sending); read the piped payload to EOF.
        let mut got = Vec::new();
        self.reader.read_to_end(&mut got).await?;
        drop(self.writer);
        Ok(got)
    }
}

/// A family gate + a `speed` service; a helper to build the two postures the per-service tests need.
pub(super) fn family_gate(tag: &str) -> Gate {
    let signet = nauthy::Identity::from_secret(&[3u8; 32]).expect("valid secret");
    Gate::rooted(
        signet.verifying_key(),
        nauthy::FileDenylist::empty(std::env::temp_dir().join(format!("tb-per-service-{tag}"))),
    )
}
