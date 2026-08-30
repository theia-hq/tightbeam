//! `tightbeam attenuate`: narrow an existing `sheer:` link, offline, before handing it on.

use clap::Args;
use nauthy::{Cap, Service};

use crate::duration::Lifetime;

/// Narrow a capability link, offline: tighten its service and/or shorten its expiry, then print the
/// tighter link.
///
/// This needs no secret and no network. It only ever adds constraints, so the result is never broader
/// than the input; a holder uses it to hand a colleague a strictly smaller slice of their own access.
#[derive(Debug, Args)]
pub struct AttenuateCmd {
    /// The `sheer:` link to narrow.
    #[arg(value_name = "link")]
    pub link: String,
    /// Restrict the link to this service (must be one the link already permits).
    #[arg(long, value_name = "service")]
    pub service: Option<Service>,
    /// Shorten the link to expire within this span from now, e.g. `30m`. Only ever tightens: a span
    /// longer than the link's remaining life does not extend it.
    #[arg(long, value_name = "duration")]
    pub expires: Option<Lifetime>,
}

impl AttenuateCmd {
    /// Narrow the link and print the result.
    pub fn run(self) -> eyre::Result<()> {
        if self.service.is_none() && self.expires.is_none() {
            eyre::bail!("give --service and/or --expires to narrow the link");
        }
        let cap = Cap::parse(&self.link)?;
        let shorten = self.expires.map(|life| nauthy::expires_in(life.duration()));
        let narrowed = cap.attenuate(self.service.as_ref(), shorten)?;
        println!("{}", narrowed.link()?);
        Ok(())
    }
}
