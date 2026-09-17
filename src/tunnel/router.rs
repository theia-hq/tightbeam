//! The route table: the names a node serves, what each one forwards to, and the access floor declared
//! for it.
//!
//! [`Router`] is the one author-facing assembly (typed handlers, the built-in forward and reflector, the
//! native raw-stream arm, and the `name=target` grammar); it proves its declarations at
//! [`expose`](Router::expose) and hands back the runnable exposer. The catalog and manifest views a caller
//! renders a node from are read off the same table.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use nauthy::{Gate, Service};
use tightbeam_handler::bridge::ErasedHandler;
use tightbeam_handler::{Handler, Metering};

use super::catalog::{Posture, ServiceCatalog, ServiceEntry};
use super::exposer::Exposer;
use crate::raw_stream::RawStream;

/// The one server-side route table: each served name binds to its handler or raw source in one call, and the
/// terminal [`expose`](Router::expose) proves every route against the gate and hands back the runnable
/// [`Exposer`]. Everything an author assembles is here: typed handlers ([`service`](Router::service),
/// [`member_service`](Router::member_service)), the built-in local forward ([`forward`](Router::forward)),
/// the built-in loopback reflector ([`echo`](Router::echo)), and the native raw-stream arm
/// ([`raw_stream`](Router::raw_stream)).
///
/// The whole table is keyed by the typed [`Service`] name, one duplicate policy (refuse), and the open
/// overlays are proven once, at [`expose`](Router::expose), so prove-before-announce holds: the caller
/// prints its banner only after the exposer exists. A raw-stream route stays a native arm because it has a
/// second open axis (the unsafe overlay) that the one-dimensional [`Handler::Exposure`] marker cannot
/// express; every other route is a handler, the built-ins included.
#[must_use = "a Router is a declaration; call `.expose()` to prove it and get the runnable Exposer"]
pub struct Router {
    services: Services,
    /// The raw safe public request, proven at [`expose`](Router::expose).
    public: PublicRequest,
    /// The raw unsafe raw-stream request, proven at [`expose`](Router::expose).
    public_unsafe: PublicUnsafeRequest,
    /// The base gate every route faces unless opened by an overlay.
    gate: Gate,
}

impl Router {
    /// An empty router over `gate`: the node-wide base gate every route faces, including the
    /// whole-node-open [`Gate::Open`] a caller may deliberately choose.
    pub fn new(gate: Gate) -> Self {
        Self {
            services: Services(HashMap::new()),
            public: PublicRequest::none(),
            public_unsafe: PublicUnsafeRequest::none(),
            gate,
        }
    }

    /// Bind `name` to a handler you wrote. Fallible: a name may map to only one target.
    pub fn service(self, name: Service, handler: impl Handler) -> eyre::Result<Self> {
        self.bind(name, Target::Handler(Arc::new(handler)), Access::Family)
    }

    /// As [`service`](Self::service), with the member floor: only a witness the gate admitted as a
    /// whole-node member may reach it, checked before any `Response::Ok`. A delegated slip for the same
    /// name is refused with the same uniform refusal a gate miss gives.
    pub fn member_service(self, name: Service, handler: impl Handler) -> eyre::Result<Self> {
        self.bind(name, Target::Handler(Arc::new(handler)), Access::Member)
    }

    /// Bind `name` to tightbeam's built-in loopback reflector: it opens no host resource and reflects only
    /// the caller's OWN bytes, so it has a legitimately-safe public form. Sugar over
    /// [`service`](Self::service) with [`Echo`](crate::builtins::Echo).
    pub fn echo(self, name: Service) -> eyre::Result<Self> {
        self.service(name, crate::builtins::Echo)
    }

    /// Bind `name` to tightbeam's built-in local forward: connect `addr` (a `host:port` or a
    /// `unix:<path>`) and splice bytes to it. Sugar over [`service`](Self::service) with
    /// [`Forward`](crate::builtins::Forward). The addr is validated here, so a typo fails at bind with a
    /// teaching message rather than at dial time as an opaque reset.
    pub fn forward(self, name: Service, addr: &str) -> eyre::Result<Self> {
        validate_forward(addr)?;
        self.service(name, crate::builtins::Forward::new(addr))
    }

    /// Bind `name` to a raw byte source (`file:`/`fifo:`/`stdin:`). Native, not a handler: the raw-stream
    /// family carries the second open axis (the unsafe overlay) and its own path guards.
    pub fn raw_stream(self, name: Service, source: RawStream) -> eyre::Result<Self> {
        self.bind(name, Target::RawStream(source), Access::Family)
    }

    /// Absorb the `name=target` serve grammar: `echo:` is the built-in reflector, a `host:port` /
    /// `unix:<path>` a local forward, and `file:<path>` / `fifo:<path>` / `stdin:` a raw-stream source. A
    /// bare `<scheme>:` is a teaching error: handlers are bound by value through
    /// [`service`](Self::service), so the scheme namespace does not survive the merge.
    pub fn parse(mut self, entries: &[String]) -> eyre::Result<Self> {
        self.services.extend_parse(entries)?;
        Ok(self)
    }

    /// Declare these served names open to anyone, per service. The proof runs at
    /// [`expose`](Router::expose), where a name the node does not serve, a member-only route, a raw stream,
    /// or a `Never` handler is refused with a teaching message.
    pub fn public(mut self, names: impl IntoIterator<Item = Service>) -> Self {
        self.public = PublicRequest::new(names.into_iter().map(|name| name.to_string()));
        self
    }

    /// Declare these served raw-stream names knowingly served to anyone, unauthenticated: the DISTINCT,
    /// louder opt-in for a byte source with no auth of its own. The proof runs at
    /// [`expose`](Router::expose), where a name the node does not serve or a handler route is refused.
    pub fn public_unsafe(mut self, names: impl IntoIterator<Item = Service>) -> Self {
        self.public_unsafe =
            PublicUnsafeRequest::new(names.into_iter().map(|name| name.to_string()));
        self
    }

    /// The declared service names, sorted, for a caller's readiness banner.
    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.services.names()
    }

    /// The node's base gate, the one this router was built on: a composing program renders a catalog from
    /// the gate it already holds instead of resolving a second one.
    pub fn gate(&self) -> &Gate {
        &self.gate
    }

    /// The served services and their reach posture, for the `control.services` read: a name-sorted
    /// [`ServiceCatalog`] snapshot. `self_listing` names the one row whose handler VALUE is built from this
    /// catalog (the member-only `control.services` read): it is rendered as a GATED entry and sorted in
    /// tightbeam, so a caller never patches the wire ordering itself. The only legitimate catalog-serving
    /// handler is member-only (a `Never` route can never be open), so Gated is its only possible posture.
    ///
    /// The posture is read off the base gate this router has held since [`new`](Router::new), so a caller
    /// renders a catalog mid-assembly without carrying a second copy of the gate to hand back.
    pub fn catalog(&self, self_listing: Option<Service>) -> ServiceCatalog {
        let ServiceCatalog(mut entries) =
            self.services
                .catalog(&self.gate, &self.public, &self.public_unsafe);
        if let Some(name) = self_listing {
            entries.push(ServiceEntry {
                name: name.to_string(),
                posture: Posture::Gated,
            });
            entries.sort_by(|a, b| a.name.cmp(&b.name));
        }
        ServiceCatalog(entries)
    }

    /// The one door: prove every route and interlock against the base gate, prove both open overlays, and
    /// hand back the runnable [`Exposer`]. Fallible: a keyless handler under an open gate, an unproven
    /// public name, a member-only route under an open gate, a raw stream under an open gate not named in
    /// the unsafe set, or a duplicate bind all fail HERE, before any banner.
    pub fn expose(self) -> eyre::Result<Exposer> {
        let Self {
            services,
            public,
            public_unsafe,
            gate,
        } = self;
        Exposer::prove(services, gate, public, public_unsafe)
    }

    /// The one bind: insert a row under its typed name, refusing a duplicate with the one policy every
    /// bind verb shares.
    fn bind(mut self, name: Service, target: Target, access: Access) -> eyre::Result<Self> {
        if self.services.0.contains_key(name.as_str()) {
            eyre::bail!("service `{name}` is already defined; a name may map to only one target");
        }
        self.services
            .0
            .insert(name.to_string(), Route { target, access });
        Ok(self)
    }
}

/// A forwarding target for one exposed service: either a named service handler, bound BY VALUE at
/// registration, or tightbeam's own raw-stream source (a `file:`/`fifo:`/`stdin:` byte source spliced
/// toward the peer).
///
/// There is no scheme-string indirection: the handler value IS the row, so two names bound to one handler
/// type are two independent instances with no synthetic key namespace. The built-in local forward
/// (`host:port` / `unix:<path>`) and the loopback reflector are first-party [`Handler`]s (see
/// [`crate::builtins`]), so everything but the raw-stream family is one access path.
#[derive(Clone)]
pub(super) enum Target {
    /// A service handler: the value this route serves. Boxed behind the private [`ErasedHandler`] bridge,
    /// the only legal heterogeneous storage (the public [`Handler`] trait is not dyn compatible).
    Handler(Arc<dyn ErasedHandler>),
    /// tightbeam's own primitive, the raw-stream half: source an already-open byte stream and splice it
    /// toward the peer, either an OS object the operator named (`file:<path>` / `fifo:<path>`) or this
    /// process's own standard input (`stdin:`, a single-consumer source taken once). The reverse of piping
    /// a service to the connector's stdout. It stays a native arm because of the second open axis: a raw
    /// stream is unsafe-open only through its own overlay, a policy the one-dimensional `Exposure` marker
    /// cannot express.
    RawStream(RawStream),
}

impl core::fmt::Debug for Target {
    /// Manual, deliberately opaque: never forward `Debug` through the erased handler (a handler may hold a
    /// secret, e.g. a shell's host seed), so this names the arm and nothing inside it.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Handler(_) => f.write_str("Handler(<handler>)"),
            Self::RawStream(stream) => f.debug_tuple("RawStream").field(stream).finish(),
        }
    }
}

impl Target {
    /// Whether this target may be OPENED to strangers (added to an [`Exposer`]'s public overlay). A TOTAL
    /// function over [`Target`], resolved THROUGH the target rather than off its served name, so an alias
    /// cannot be opened by naming it: the target's own posture decides, never the name.
    ///
    /// The TYPE guarantee (the sealed, uninhabited [`PublicUse`](crate::open_policy::PublicUse) marker erased to
    /// [`ErasedHandler::open_safe`]) covers [`Handler`](Target::Handler): a `Never` handler (a keyless
    /// shell) reads `false`, an `OptIn` handler `true`. A [`RawStream`](Target::RawStream) has no auth of
    /// its own and is one keystroke from a secret, so it is NOT openable here; it opens only through the
    /// distinct unsafe raw-stream overlay. The exhaustive match is the guarantee: a future `Target`
    /// variant forces a decision rather than defaulting into either answer.
    fn open_safe(&self) -> bool {
        match self {
            Target::Handler(handler) => handler.open_safe(),
            Target::RawStream(_) => false,
        }
    }

    /// Which [`TargetKind`] this target is, so a caller's banner RENDERS what tightbeam resolved (a raw
    /// stream splits into the loudest posture group) instead of re-parsing an address string of its own.
    pub(super) fn kind(&self) -> TargetKind {
        match self {
            Target::Handler(_) => TargetKind::Handler,
            Target::RawStream(_) => TargetKind::RawStream,
        }
    }
}

/// What KIND of thing a served service forwards to, as a caller's readiness banner needs to reason about it
/// WITHOUT re-parsing an address string in the consumer: a bound handler (a caller-injected service, or a
/// tightbeam built-in such as the local forward or the loopback reflector) or a raw-stream source. Declared
/// by the resolved [`Target`], so a consumer RENDERS what tightbeam resolved (splitting a public raw stream
/// into its own louder posture group) rather than string-matching a `file:` prefix of its own. An enum, not
/// a bool, so a future target kind forces a decision at every match site rather than silently reading as one
/// of these two.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetKind {
    /// A bound handler: a service the caller wrote, or a tightbeam built-in (the local forward, the
    /// loopback reflector).
    Handler,
    /// A raw-stream source (`file:`/`fifo:`/`stdin:`): bytes with no auth of their own, so an OPEN one is the
    /// loudest reach posture a banner can show (a stranger reading a chosen path or the piped stdin).
    RawStream,
}

/// A route's access class: what the gate must have proven beyond admission. Declared where the route is
/// registered ([`Services::member_only`]), never on the handler: a handler's compile-time marker
/// ([`Handler::Exposure`]) says what the CODE may face, while access is a property of the NAME a caller
/// reaches. Per-route is also the only axis that lets two names bound to one handler carry different
/// floors, and it keeps a handler impl from growing a fourth mandatory item (the cold-author bar).
///
/// [`Family`](Access::Family) is the default and means "the gate alone decides": under a node-wide open
/// gate it admits anyone, so it is no floor beyond the gate, never "this node's family".
/// [`Member`](Access::Member) can only REFUSE: it reads one bit of the witness the gate minted and never
/// mints, clones, or widens one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Access {
    /// The default: the gate's verdict is the whole verdict, byte-identical to a node with no declaration.
    Family,
    /// MEMBER-only: a witness the gate admitted as a whole-node member passes; every other witness (a
    /// delegated slip, a stranger on an open node) is refused with the same payload-free class the gate
    /// gives a miss, BEFORE any `Response::Ok` is written.
    Member,
}

/// One served route: the [`Target`] the name resolves to and the [`Access`] class declared for it. Access
/// travels with the route so the two can never drift apart, and a name a node does not serve cannot carry
/// a declaration.
#[derive(Debug, Clone)]
pub(super) struct Route {
    pub(super) target: Target,
    pub(super) access: Access,
}

impl Route {
    /// A route under the default [`Access::Family`] floor (the gate alone decides).
    pub(super) fn family(target: Target) -> Self {
        Self {
            target,
            access: Access::Family,
        }
    }
}

/// The local services an exposer publishes: a map of service name to its [`Route`] (a [`Target`] plus the
/// [`Access`] class declared at registration), validated as it is built so the rest of the core receives
/// names, targets, and floors that are already well-formed. Private: the author-facing assembly is the
/// [`Router`], which binds handler values directly.
#[derive(Debug, Clone)]
pub(super) struct Services(pub(super) HashMap<String, Route>);

impl Services {
    /// Parse `name=target` service entries into a fresh table; every entry must name its service. `echo:` is
    /// the built-in loopback reflector, a `host:port` / `unix:<path>` a local forward, and `file:<path>` /
    /// `fifo:<path>` / `stdin:` a raw-stream source. A bare `<scheme>:` no longer resolves: handlers are
    /// bound by value through [`Router::service`], so the scheme namespace is a teaching error.
    #[cfg(test)]
    pub(super) fn parse(entries: &[String]) -> eyre::Result<Self> {
        let mut services = Self(HashMap::new());
        services.extend_parse(entries)?;
        Ok(services)
    }

    /// Parse `name=target` entries INTO this table (the [`Router::parse`] path): the same grammar and the same
    /// one duplicate policy as every other bind, refused with a teaching message.
    fn extend_parse(&mut self, entries: &[String]) -> eyre::Result<()> {
        let Self(services) = self;
        for entry in entries {
            let Some((name, addr)) = entry.split_once('=') else {
                eyre::bail!(
                    "`{entry}` names no service. Every serve entry must be `name=target`, e.g. \
                     `web=127.0.0.1:8080`, `logs=file:/var/log/app.log`"
                );
            };
            // Validate the name through the same domain type the wire uses, so an exposed name and a
            // requested name are compared as the same kind of thing.
            name.parse::<Service>()?;
            // A duplicate name is refused HERE, the same policy every bind verb applies: silently
            // overwriting would drop the first target (and, after `member_only`, could silently move a
            // declared floor off the route the operator thought they marked).
            if services.contains_key(name) {
                eyre::bail!(
                    "service `{name}` is already defined; a name may map to only one target"
                );
            }
            // Resolve (and validate) the addr into a Target: a bogus
            // address fails HERE with a teaching message, not at dial time as an opaque reset.
            services.insert(name.to_owned(), Route::family(parse_target(addr, entry)?));
        }
        Ok(())
    }

    /// Add a handler-target service under `name`, bound to the handler VALUE (constructed directly rather
    /// than through the target grammar, so a caller holding per-service state, an origin scope, a sink
    /// directory, binds one instance per served name and no scheme namespace is needed). The `name` is
    /// validated through the [`Service`] domain type; a duplicate `name` is refused. The Router wires the
    /// same insert through its typed verbs; this is the test-facing shape.
    #[cfg(test)]
    pub(super) fn with_handler(mut self, name: &str, handler: impl Handler) -> eyre::Result<Self> {
        let Self(services) = &mut self;
        name.parse::<Service>()?;
        if services.contains_key(name) {
            eyre::bail!("service `{name}` is already defined; a name may map to only one target");
        }
        services.insert(
            name.to_owned(),
            Route::family(Target::Handler(Arc::new(handler))),
        );
        Ok(self)
    }

    /// Declare `name` MEMBER-only: only a witness the gate admitted as a whole-node member may reach it,
    /// and a delegated slip for the same name is refused with the same uniform refusal a gate miss gives,
    /// before any `Response::Ok` (see [`Access::Member`]). The default is [`Access::Family`] (the gate
    /// alone decides), so a declaration can only tighten an already-admitted caller.
    ///
    /// Fallible for the same reason [`with_handler`](Self::with_handler) is: a name the node does not
    /// serve is a caller error, not a silent no-op. The contradicting pairings are refused at the door,
    /// never here: [`Exposer`] refuses a member-only route under a node-wide open gate (an open gate mints
    /// only slips, so the route would refuse every dialer) or in the unsafe raw-stream set (the same dead
    /// route, rendered open); the public proof refuses one named public. The Router's `member_service`
    /// declares the same floor through its typed verb; this is the test-facing shape.
    #[cfg(test)]
    pub(super) fn member_only(mut self, name: &str) -> eyre::Result<Self> {
        let Self(routes) = &mut self;
        let Some(route) = routes.get_mut(name) else {
            let mut served: Vec<&str> = routes.keys().map(String::as_str).collect();
            served.sort_unstable();
            eyre::bail!(
                "no service named `{name}` to mark member-only; this node serves: {}",
                served.join(", ")
            );
        };
        route.access = Access::Member;
        Ok(self)
    }

    /// The exposed service names, sorted, for a caller's readiness banner.
    fn names(&self) -> impl Iterator<Item = &str> {
        let Self(services) = self;
        let mut names: Vec<&str> = services.keys().map(String::as_str).collect();
        names.sort_unstable();
        names.into_iter()
    }

    /// The served services and their reach posture, for the `control.services` read: a name-sorted
    /// [`ServiceCatalog`] snapshot. The posture is the EFFECTIVE one a dialer faces, PER SERVICE: a service
    /// is [`Open`](Posture::Open) if the node's base `gate` is [`Gate::Open`] (everything is open to anyone)
    /// OR the service is a member of the public overlay `public` (opened per-service); otherwise it is
    /// [`Gated`](Posture::Gated) behind a member badge. Not the handler's compile-time ceiling. A pure read
    /// over the parsed services, no mutable state.
    ///
    /// `public` and `public_unsafe` are the raw operator requests (the display side reads what was ASKED);
    /// the security walls are the public proof ([`Router::public`]) and the unsafe proof
    /// ([`Services::prove_unsafe`]), which prove every requested name before the node serves. So a catalog
    /// naming a service `open` is only ever served once the matching proof passed for the same request. An
    /// unsafe-open raw stream IS open to anyone, so it reads `Open` on the wire too.
    pub(super) fn catalog(
        &self,
        gate: &Gate,
        public: &PublicRequest,
        public_unsafe: &PublicUnsafeRequest,
    ) -> ServiceCatalog {
        let node_open = matches!(gate, Gate::Open);
        let mut entries: Vec<ServiceEntry> = self
            .names()
            .map(|name| ServiceEntry {
                posture: if node_open || public.contains(name) || public_unsafe.contains(name) {
                    Posture::Open
                } else {
                    Posture::Gated
                },
                name: name.to_owned(),
            })
            .collect();
        // `names()` already sorts, so this is stable; kept explicit so the wire canonical-order invariant is
        // stated where the catalog is built, not left implicit in a helper.
        entries.sort_by(|a, b| a.name.cmp(&b.name));
        ServiceCatalog(entries)
    }

    /// The bound handler routes this exposer names, so the construction interlocks can check each: a
    /// handler with no auth of its own may not sit behind an open gate.
    pub(super) fn handlers(&self) -> impl Iterator<Item = (&str, &Arc<dyn ErasedHandler>)> {
        let Self(routes) = self;
        routes
            .iter()
            .filter_map(|(name, route)| match &route.target {
                Target::Handler(handler) => Some((name.as_str(), handler)),
                Target::RawStream(_) => None,
            })
    }

    /// The served names declared [`Access::Member`], for the construction interlocks: a member-only route
    /// no dialer can reach is a dead route, and when it renders `Open` (the public overlays) that is a
    /// posture lie too.
    pub(super) fn member_only_names(&self) -> impl Iterator<Item = &str> {
        let Self(routes) = self;
        routes.iter().filter_map(|(name, route)| {
            matches!(route.access, Access::Member).then_some(name.as_str())
        })
    }

    /// The exposed names whose target is a [`Target::RawStream`] (a `file:`/`fifo:` path source, or `stdin:`).
    /// Like a keyless shell, a raw-stream source has no auth of its own: it serves a chosen path's bytes (or
    /// the piped stdin) to whoever the gate admits, so [`Exposer`] refuses it behind an [`Gate::Open`]
    /// gate (a public gate over a `file:` source would exfil a secret, over a `stdin:` source the piped
    /// bytes, to anyone). A local forward (`host:port`/`unix:`) is a service the operator deliberately stood
    /// up, so it may still be a public gate; a bare file path or a piped stdin is one keystroke from a
    /// secret, so it may not.
    pub(super) fn raw_stream_names(&self) -> impl Iterator<Item = &str> {
        let Self(routes) = self;
        routes
            .iter()
            .filter_map(|(name, route)| match &route.target {
                Target::RawStream(_) => Some(name.as_str()),
                Target::Handler(_) => None,
            })
    }

    /// Prove an UNSAFE raw-stream opt-in set: this is the wall that turns a raw [`PublicUnsafeRequest`] into
    /// the exposer's proven [`PublicServices`] overlay. Every requested name must (1) be an EXACT served name
    /// (a typo or a name the node does not serve bails with the served list) AND (2) resolve to a
    /// [`Target::RawStream`] (a `file:`/`fifo:`/`stdin:` source with no auth of its own).
    ///
    /// A name that resolves to a handler is a TEACHING REDIRECT, never silently opened: the unsafe overlay is
    /// ONLY for raw byte sources, so a legitimate service named here is refused with a message pointing at the
    /// safe public overlay ([`Router::public`]). The two overlays partition the opened names disjointly and
    /// never fold, so crossing them teaches rather than opens. A survivor set freezes into the
    /// overlay [`admit`](super::admit) consults. The proof reads THROUGH each target, matched by served name, so an alias
    /// can never open a raw stream by naming it.
    pub(super) fn prove_unsafe(
        &self,
        requested: PublicUnsafeRequest,
    ) -> eyre::Result<PublicServices> {
        let PublicUnsafeRequest(names) = requested;
        let Self(services) = self;
        let mut proven = HashSet::with_capacity(names.len());
        for name in names {
            match services.get(&name).map(|route| &route.target) {
                None => {
                    let mut served: Vec<&str> = services.keys().map(String::as_str).collect();
                    served.sort_unstable();
                    eyre::bail!(
                        "no service named `{name}` to open; this node serves: {}",
                        served.join(", ")
                    );
                }
                // Crossing the token: the unsafe overlay is ONLY for raw byte sources. A handler named here
                // is redirected to the SAFE public overlay, never silently opened, never leaking a marker
                // type name. The layering gate forbids a library naming a consumer's flags, so this speaks
                // the concept (the public overlay) and a caller's own help names the exact flag.
                Some(Target::Handler(_)) => {
                    eyre::bail!(
                        "`{name}` is not a raw byte source, so the unsafe raw-stream set will not open it; a handler \
                     is opened to anyone through the public set instead"
                    )
                }
                Some(Target::RawStream(stream)) => {
                    // Serve-time source guard: a name proven into the unsafe overlay is advertised in the
                    // readiness banner as "serving the raw bytes of <path> to anyone". The connect-time open
                    // refuses a device, a directory, a socket, or a symlink, so validate the source HERE too and
                    // refuse it loudly at serve, rather than let the banner over-claim bytes a dial will always
                    // reject. A not-yet-created path is still allowed (the dial-time open guards that case). This
                    // aligns the banner with the guard.
                    stream.check_open_source()?;
                    proven.insert(name);
                }
            }
        }
        Ok(PublicServices(proven))
    }

    /// Prove the SAFE public opt-in set: every requested name must be an EXACT served name, must not be
    /// member-only (a public dial carries no membership proof, so the route would refuse every caller while
    /// the catalog rendered it open), must not be a raw stream (a teaching redirect to the unsafe overlay),
    /// and must resolve to an open-safe target (a `Never` handler is a hard no). Resolving through the
    /// target, matched by served name, is what stops an alias from being opened by naming it: the target's
    /// posture decides, never the name. A survivor set freezes into the overlay [`admit`](super::admit) consults.
    pub(super) fn prove_public(&self, requested: PublicRequest) -> eyre::Result<PublicServices> {
        let PublicRequest(names) = requested;
        let Self(routes) = self;
        let mut proven = HashSet::with_capacity(names.len());
        for name in names {
            let Some(route) = routes.get(&name) else {
                let mut served: Vec<&str> = routes.keys().map(String::as_str).collect();
                served.sort_unstable();
                eyre::bail!(
                    "no service named `{name}` to open; this node serves: {}",
                    served.join(", ")
                );
            };
            // A member-only route cannot be public: the public overlay admits through `Gate::Open`, whose
            // only witness is an open one, so a public dial could never pass the floor while the catalog
            // renders the name `Open`: a dead route and a posture lie. Refused here, where the overlay is
            // proven, so the contradiction cannot be built however the two declarations were ordered.
            if matches!(route.access, Access::Member) {
                eyre::bail!(
                    "`{name}` is member-only, so it cannot be opened to everyone: a public dial carries no \
                     membership proof, so the route would refuse every caller while the catalog renders it \
                     open. drop it from the public set, or drop the member-only declaration"
                );
            }
            match &route.target {
                // A raw stream named in the SAFE overlay is a teaching REDIRECT, not a flat refusal: the safe
                // overlay never opens a raw byte source (`open_safe` stays `false` for it), but the operator
                // CAN serve its bytes knowingly through the DISTINCT unsafe overlay. Byte-for-byte the SAME
                // string as the whole-node door above: one condition, one string, both callers.
                Target::RawStream(_) => eyre::bail!(
                    "`{name}` is a raw byte source (file:/fifo:/stdin:) with no auth of its own, so a public \
                     gate will not serve it. to serve its raw bytes to anyone, name it in the unsafe raw-stream \
                     set; otherwise gate it or drop it from the public set"
                ),
                // A keyless shell is a HARD no: it has no legitimate public use and no redirect exists
                // (unlike a raw stream). Never leaks a marker type name.
                Target::Handler(_) if !route.target.open_safe() => eyre::bail!(
                    "`{name}` has no legitimate public use: a keyless shell (or an alias of one) would hand a \
                     shell to anyone who reaches this node. keep it family-gated; drop it from the public set"
                ),
                Target::Handler(_) => {
                    proven.insert(name);
                }
            }
        }
        Ok(PublicServices(proven))
    }
}

/// One served service as a caller's READINESS BANNER needs it: its name, the [`Posture`] a dialer faces, the
/// [`TargetKind`] it forwards to, and the responder-side [`Metering`] its handler declared when open.
///
/// A LOCAL render view an embedder draws its OWN banner from, DISTINCT from the on-wire [`ServiceEntry`] the
/// member-only `control.services` read returns: the banner is printed by a node to its own operator, so it
/// carries the extra render tells (kind, metering) that never cross the wire, and it stays off the
/// anti-oracle surface the wire catalog guards. Built by [`Exposer::manifest`] from the resolved
/// services, so a consumer RENDERS declared facts (posture from the proven overlay, kind from the target,
/// the metering caveat from the handler) rather than re-deriving them from address strings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestEntry {
    /// The service name the exposer published it under (the name a connector requests).
    pub name: String,
    /// The posture a dialer faces reaching it (gated behind a member badge, or open to anyone).
    pub posture: Posture,
    /// What kind of target it forwards to, so the banner can split a public raw stream into its own group.
    pub kind: TargetKind,
    /// The handler's declared responder-side rate limit, for a bound handler route: [`Some`] of what the
    /// handler reports, so a banner narrates "open plus unmetered" where the danger is. [`None`] for a raw
    /// stream (it declares no responder policy of its own; its loudness is the raw-stream group).
    pub metering: Option<Metering>,
    /// For a raw-stream service, the source a banner names in its unsafe warning: the operator's path made
    /// ABSOLUTE (lexically, via [`std::path::absolute`] -- no FS access, no symlink follow, no existence
    /// requirement, so a not-yet-created `fifo:` still renders), or the piped-stdin marker. [`None`] for a
    /// bound handler (no raw source to warn about). Declared by tightbeam so the banner renders a resolved
    /// fact, never re-derives a path from the operator's typed string.
    pub raw_source: Option<RawSource>,
}

/// The resolved source of a raw-stream service, as a caller's banner names it in the loud unsafe warning
/// (which exact bytes reach a stranger when this stream is open). Declared by tightbeam, which OWNS raw-stream
/// resolution, so a consumer renders a resolved fact rather than re-deriving a path from the operator's typed
/// string. An enum, not a bare string, so `stdin:` (no path, the risk is this process's piped input) and a
/// path source are distinct cases a renderer must handle, never conflated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RawSource {
    /// A `file:`/`fifo:` source: the operator's path made absolute lexically ([`std::path::absolute`], no FS
    /// access, no symlink follow), so the warning names exactly which path's bytes are at risk.
    Path(String),
    /// A `stdin:` source: no path, so the exfil risk is this process's own piped standard input.
    Stdin,
}

/// The raw, UNVALIDATED set of service names an operator asked to open to strangers (however an embedder
/// surfaces that request), before the [`Router`] proves each one exposed and open-safe. Kept DISTINCT from
/// [`PublicServices`] (the proven set the gate consults) so an unvalidated set can never reach admission:
/// the only way to a [`PublicServices`] is through the proof, so "opened a name the node does not serve / a
/// keyless shell" is a build-time bail, not a silently-open service. Private: the author-facing request is
/// [`Router::public`].
#[derive(Debug, Clone, Default)]
pub(super) struct PublicRequest(Vec<String>);

impl PublicRequest {
    /// An empty request: no service is opened (every service faces the base gate). The default a node builds
    /// when the operator names nothing public.
    pub(super) fn none() -> Self {
        Self(Vec::new())
    }

    /// Build a request from the operator's raw public-request names, verbatim (no validation here: this is the
    /// UNPROVEN side of parse-don't-validate; the public proof is the wall).
    pub(super) fn new(names: impl IntoIterator<Item = String>) -> Self {
        Self(names.into_iter().collect())
    }

    /// Whether `name` was requested public, for a display read (the `control.services` catalog). This reads
    /// the raw request, never the proof, so it is a DISPLAY predicate only, never an admission decision.
    fn contains(&self, name: &str) -> bool {
        let Self(names) = self;
        names.iter().any(|requested| requested == name)
    }
}

/// The raw, UNVALIDATED set of raw-stream service names an operator asked to serve to strangers
/// unauthenticated (however an embedder surfaces that request), before the [`Router`] proves each one an
/// exposed [`Target::RawStream`]. Sibling of [`PublicRequest`], kept DISTINCT from the proven
/// [`PublicServices`] so an unproven name can never reach admission: the only way to a [`PublicServices`] is
/// through [`Services::prove_unsafe`], so "opened a name the node does not serve / a handler as an unsafe raw
/// stream" is a build-time bail, not a silently-open service. Private: the author-facing request is
/// [`Router::public_unsafe`].
///
/// DISJOINT from [`PublicRequest`] on purpose: a safe public overlay opens a legitimate service (a handler
/// the operator stood up), an UNSAFE overlay opens a raw byte source with no auth of its own. The two never
/// fold, so the louder opt-in stays a distinct, deliberate thing the operator cannot type by accident.
#[derive(Debug, Clone, Default)]
pub(super) struct PublicUnsafeRequest(Vec<String>);

impl PublicUnsafeRequest {
    /// An empty request: no raw stream is served to strangers (every raw stream stays gated).
    pub(super) fn none() -> Self {
        Self(Vec::new())
    }

    /// Build a request from the operator's raw unsafe-open names, verbatim (no validation here: this is the
    /// UNPROVEN side of parse-don't-validate; [`Services::prove_unsafe`] is the wall).
    pub(super) fn new(names: impl IntoIterator<Item = String>) -> Self {
        Self(names.into_iter().collect())
    }

    /// Whether `name` was requested unsafe-open, for a display read (the `control.services` catalog). This
    /// reads the raw request, never the proof, so it is a DISPLAY predicate only, never an admission decision.
    fn contains(&self, name: &str) -> bool {
        let Self(names) = self;
        names.iter().any(|requested| requested == name)
    }
}

/// The PROVEN-open set of served service names an [`Exposer`] admits any reaching peer to: every member was
/// validated at [`Exposer::with_public`] against the served set AND its target's [`open_safe`](Target::open_safe)
/// posture, so a member is, by construction, an exposed, open-safe service. Membership is the ONLY fast/open
/// path at admission ([`admit`](super::admit)); a `Never` handler, a raw stream, or a name the node does not serve can
/// never be a member, so `control.*` and every keyless shell stay member-only by SET NON-MEMBERSHIP, a
/// stronger guarantee than a map entry that merely holds a permissive value.
#[derive(Debug, Clone, Default)]
pub(super) struct PublicServices(pub(super) HashSet<String>);

impl PublicServices {
    /// Whether `service` is a proven-open member: the one branch [`admit`](super::admit) takes on the requested name. A
    /// pure set-membership test with no side branch on member content, so a HIT (open) and a MISS (gated or
    /// absent) differ only in the one bit the model intends, never in timing on the member's identity.
    pub(super) fn contains(&self, service: &str) -> bool {
        let Self(names) = self;
        names.contains(service)
    }
}

/// Resolve an exposed service's address to a [`Target`]: `file:<path>` / `fifo:<path>` are the raw-stream
/// forward (open an existing OS object, splice its bytes to the peer); `echo:` is the built-in loopback
/// reflector (no argument, no host resource); a bare scheme (a `<name>:` -- a word then a colon with nothing
/// after) names a handler; anything else must be a socket forward (`host:port` or `unix:<path>`). All
/// validated here so a typo fails at parse with a teaching message, not at dial time.
fn parse_target(addr: &str, entry: &str) -> eyre::Result<Target> {
    // A trailing `+lossy` is the operator's opt-in to raw-stream FAN-OUT: the
    // source may be reached by MANY consumers at once, and a consumer that falls behind has its bytes DROPPED
    // rather than stall the producer or the others. It is a claim only the operator can make ("this stream
    // tolerates loss"), so it is legal ONLY on the live single-writer sources `stdin:`/`fifo:` and REFUSED at
    // parse on anything else: a `file:` (static bytes, already safe fan-out by re-open, loss would be corruption)
    // or a `host:port`/`unix:`/built-in (not a raw-stream source at all). Strip it here, then route the
    // scheme; a source that keeps it (`file:...+lossy`, `web+lossy`) is rejected below.
    let (addr, lossy) = match addr.strip_suffix("+lossy") {
        Some(base) => (base, true),
        None => (addr, false),
    };
    let reject_lossy = |scheme: &str| -> eyre::Result<()> {
        if lossy {
            eyre::bail!(
                "`+lossy` (raw-stream fan-out) is only valid on a `stdin:`/`fifo:` source, not `{scheme}` \
                 (`{entry}`); drop it, or point the service at a live single-writer source"
            );
        }
        Ok(())
    };
    // `stdin:` is a raw-stream source with NO tail (this process's fd 0), so it is a zero-arg target routed
    // FIRST, before any other arm. It shares the raw-stream direction and the public-gate refusal, but
    // inherits none of the path guards (there is no path). Anything after the colon is a typo: `stdin:` takes
    // no argument.
    if addr == "stdin:" {
        return Ok(Target::RawStream(RawStream::stdin(lossy)?));
    }
    // `echo:` is tightbeam's built-in loopback reflector, now a first-party [`Handler`]
    // ([`crate::builtins::Echo`]): a zero-arg target (no path, no host resource). It tolerates no `+lossy`
    // (it is not a raw-stream source) and no tail (`echo:` takes no argument), so both are refused.
    if addr == "echo:" {
        reject_lossy("echo:")?;
        return Ok(Target::Handler(Arc::new(crate::builtins::Echo)));
    }
    // A raw-stream route carries a PATH tail (`file:/tmp/x`, `fifo:/tmp/beam`), so it is native, not a
    // handler. Route it FIRST: the direction (a read-only source toward the peer) is fixed here at parse
    // time, and a bare `file:`/`fifo:` with no path fails loudly.
    if let Some(path) = addr.strip_prefix("file:") {
        reject_lossy("file:")?;
        return Ok(Target::RawStream(RawStream::file(path, entry)?));
    }
    if let Some(path) = addr.strip_prefix("fifo:") {
        return Ok(Target::RawStream(RawStream::fifo(path, entry, lossy)?));
    }
    if let Some(scheme) = addr.strip_suffix(':') {
        // A bare `<scheme>:` (nothing after the colon) used to name a registry handler. The scheme namespace
        // left the public API with the Router, so it is a teaching error, never a silently-dangling target:
        // handlers bind by value. `unix:<path>` and `host:port` carry a tail and fall through to the forward
        // grammar; a bare `unix:` is caught here too and taught.
        if !scheme.is_empty()
            && scheme
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.')
        {
            reject_lossy(addr)?;
            eyre::bail!(
                "`{entry}` names a handler scheme (`{addr}`), which is no longer spellable: handlers are bound \
                 by value, e.g. `.service(\"{scheme}\".parse()?, MyHandler)`. use `--` or a bound service"
            );
        }
    }
    reject_lossy(addr)?;
    validate_forward(addr)?;
    Ok(Target::Handler(Arc::new(crate::builtins::Forward::new(
        addr,
    ))))
}

/// Reject a forward addr that is not a real target, so a named service pointed at a bogus addr
/// (`web=nonsense`) fails at parse with a teaching message instead of pointing at an undialable host.
/// Valid forwards: `unix:<path>` or a `host:port` (a bare `<name>:` handler scheme is a teaching error).
fn validate_forward(addr: &str) -> eyre::Result<()> {
    let is_host_port = addr
        .rsplit_once(':')
        .is_some_and(|(host, port)| !host.is_empty() && port.parse::<u16>().is_ok());
    if addr.starts_with("unix:") || is_host_port {
        return Ok(());
    }
    eyre::bail!(
        "`{addr}` is not a valid forwarding address (host:port, unix:<path>, file:<path>, fifo:<path>, \
         or the built-in `echo:`)"
    )
}

#[cfg(test)]
#[path = "router_tests.rs"]
mod router_tests;
