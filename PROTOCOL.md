# TB04, the tunnel wire

The preamble every tightbeam stream opens with: the dialer names a service and presents whatever
credentials it holds, the host answers reached or refused, and from there the stream is a transparent
byte pipe this wire says nothing about.

This document is the wire, not the implementation of it. A second implementation built from this page
alone must interoperate with the one in `src/protocol.rs`, octet for octet. Where a statement here is
weaker than the code (a `MAY` the code happens to satisfy), the weaker statement is the contract. Where
the code is weaker than a `MUST` here, it is named in [Known gaps](#known-gaps) rather than left for a
reader to discover.

- [Conventions](#conventions)
- [Where this wire sits](#where-this-wire-sits)
- [The magic: identity and version](#the-magic-identity-and-version)
- [The request frame](#the-request-frame)
- [The response frame](#the-response-frame)
- [The state machine](#the-state-machine)
- [Unrecognised values](#unrecognised-values)
- [Refusal semantics](#refusal-semantics)
- [Caps](#caps)
- [Versioning and the frozen response](#versioning-and-the-frozen-response)
- [Known gaps](#known-gaps)
- [Test vectors](#test-vectors)
- [Regenerating the vectors](#regenerating-the-vectors)

## Conventions

`MUST`, `MUST NOT`, `SHOULD`, `SHOULD NOT` and `MAY` carry their RFC 2119 meanings. They are used only
where a divergent choice breaks interoperation or a security property; where an implementation is free,
this page says so.

An **octet** is 8 bits. Every multi-octet integer on this wire is **unsigned big-endian**. There are no
signed integers, no varints, and no alignment or padding anywhere: every field begins at the octet after
the previous one ends. Text fields are UTF-8 and are never NUL-terminated; their length is always
carried in front of them.

The **dialer** is the side that opens a stream. The **host** is the side that accepts it. Both roles can
live in one process, and a node is usually both to different peers.

Octets are shown as lowercase hexadecimal pairs. Grouping and line breaks inside a vector block are
presentation only.

## Where this wire sits

TB04 is carried on one bidirectional stream of an authenticated session between two node identities
(ed25519 public keys). It assumes the session already gives it an ordered, reliable, framed-by-nothing
byte stream in each direction, and an attribution of the peer's identity. It does not specify how that
session is established, and it adds no authentication of its own: the credential fields below are
authorization inputs, evaluated against the peer identity the session attributes.

Four rules bind this wire to the layer under it:

1. The dialer opens every stream. A host `MUST NOT` open a stream toward a dialer and call it tightbeam:
   there is one door, and the preamble only ever travels dialer to host.
2. Every stream carries its own preamble and its own admission. A host `MUST NOT` cache the outcome of
   one stream's admission and apply it to another stream of the same session, even for an identical
   request. Admission is bound to the stream it was decided for, so revocation and disablement take
   effect on the next stream rather than the next session.
3. A dialer `MUST NOT` present a credential (either slot of the request) over a session whose transport
   does not prove the peer holds the private key for the identity it is reached under. An announced,
   unproven identity is whoever answered the dial, and a presented token is bearer material. Over such a
   session a credential-bearing dialer `MUST` abandon the request without writing an octet.
4. After a successful response, every remaining octet in both directions belongs to the service. TB04
   defines no trailer, no keepalive, no close frame, and no escape sequence. The stream ends when the
   session's stream ends.

## The magic: identity and version

Every wire in this family opens with four ASCII octets that split into an **identity** and a **version**:

```text
identity = the maximal leading run of [A-Z]   (0x41 to 0x5a)
version  = the trailing digits                (0x30 to 0x39)
```

The rule is self-delimiting, so it parses a 2+2 magic and a 3+1 magic without being told which it is
looking at. For this wire:

| magic | identity | version |
| ----- | -------- | ------- |
| `TB04` (`54 42 30 34`) | `TB` | `04` |

The identity is **frozen forever**. A stream that does not open with `TB` is not a tightbeam stream, and
that is the only thing an identity mismatch is ever allowed to mean. The version names the request
grammar, and only the request grammar: see [Versioning](#versioning-and-the-frozen-response).

A receiver `MUST` split the four octets by the rule above and compare the **identity** first, then the
version. Comparing all four at once collapses two different facts into one and makes the answer in the
next section impossible to write. Comparing a fixed-width prefix instead of the maximal run is a
different parse with an observable consequence, because another wire in this family carries the
identity `TBH`, whose first two octets are this wire's whole identity: a two-octet reader takes a
`TBH1` head for tightbeam on an unserved version and answers it, telling something that does not speak
this wire what version this host speaks. A receiver `MUST` therefore read a capital octet immediately
after `TB` as the same run continuing into a longer identity, which is foreign.

The three conditions a host can meet on the head of a stream are distinct, and each has exactly one
correct answer:

| condition | what it means | the host's answer |
| --------- | ------------- | ----------------- |
| identity is not `TB` | not a tightbeam stream | **no octets at all**; close the stream |
| identity is `TB`, version is not served | a tightbeam peer on another grammar | a refusal naming **both** versions |
| the head cannot be read (short, closed, timed out) | nothing was received | no octets; close the stream |

A foreign identity `MUST` receive **zero** octets in reply. Nothing true can be said to a protocol we
cannot name, a reply would be a guess at what is meaningful to it, and silence keeps this wire from
being a cheaper fingerprint than the session handshake already is.

A served identity on an unserved version `MUST` be answered, because the peer has already proved it
speaks tightbeam, and both ends can act on the fact. This is the single reason the response frame is
frozen: a host that cannot parse a peer's request must still be able to write something that peer can
parse.

## The request frame

Written by the dialer, once, as the first octets of the stream.

| offset | field | width | encoding |
| ------ | ----- | ----- | -------- |
| 0 | identity | 2 | ASCII `TB` (`54 42`) |
| 2 | version | 2 | ASCII `04` (`30 34`) |
| 4 | service length | 2 | u16 big-endian, octets of UTF-8 |
| 6 | service | *service length* | UTF-8, no terminator |
| 6 + s | capability present | 1 | `00` absent, `01` present |
| 7 + s | capability length | 2 | u16 big-endian; **present only** when the octet above is `01` |
| 9 + s | capability | *capability length* | UTF-8 |
| ... | membership present | 1 | `00` absent, `01` present |
| ... | membership length | 2 | u16 big-endian; **present only** when the octet above is `01` |
| ... | membership | *membership length* | UTF-8 |

The frame ends after the last field. Its total width is
`4 + 2 + s + 1 + (2 + c if present) + 1 + (2 + m if present)`, at most 196 617 octets.

### service

The service to reach, as the host published it. The grammar is not free text:

- at least 1 and at most **128** octets,
- ASCII alphanumerics plus `-`, `_`, `.`, `/`, `:`, and nothing else.

The alphabet excludes quotes, whitespace, backslashes, parentheses and commas because the name is
embedded into the host's authorization query, and a name that could be mistaken for that query's syntax
is a way to smuggle a term into it.

A dialer `MUST NOT` send a name outside the grammar. A host that receives one `MUST` answer
**bad request** (not *not admitted*): the request's grammar is the dialer's own and is public by
definition, so naming the fault reveals nothing, while a policy-shaped refusal would claim a ruling that
no gate made. The field itself can carry 65 535 octets; a host `MUST` reject on the 128 octet grammar
bound and `MUST NOT` admit a longer name.

A host `MAY` resolve a name it does not expose to its sole exposed service when it exposes exactly one.
A single-service node then needs no agreed name. A host exposing two or more services `MUST NOT` guess.

### capability and membership

Both slots are **opaque** to this wire. TB04 carries them, counts their octets, and never parses them.

- **capability** (slot 1) is the token the dialer presents for authorization, when the host gates on
  capabilities. It is absent when the host gates on identity, where the proven peer key is the whole
  story.
- **membership** (slot 2) is a badge under the foreign authority that a slot 1 token names. A host
  `MUST` evaluate slot 2 only when slot 1 is present and is a token bound to a foreign authority, and
  `MUST` ignore slot 2 entirely otherwise. Admitting on a badge alone would let a dialer choose which
  authority vouches for it.

Either slot being present makes the request credential-bearing, which engages rule 3 of
[Where this wire sits](#where-this-wire-sits).

A present slot with length 0 is representable and is not special: it is a token of zero octets, which no
host parses successfully, so it refuses like any other unusable token.

## The response frame

Written by the host, once, before any payload octet. **This frame is frozen from TB04 forward**; see
[Versioning](#versioning-and-the-frozen-response).

| offset | field | width | encoding |
| ------ | ----- | ----- | -------- |
| 0 | tag | 1 | `00` reached, `01` refused |
| 1 | refusal code | 1 | present only when tag is `01` |
| 2 | detail length | 2 | u16 big-endian; present only for the codes that carry a detail |
| 4 | detail | *detail length* | UTF-8, at most 1024 octets |

Tag `00` is the whole frame: one octet, and the byte pipe follows it immediately.

The refusal codes, and the shape each one carries:

| code | class | detail |
| ---- | ----- | ------ |
| `00` | not admitted | **none**; the frame ends after the code |
| `01` | bad request | length-prefixed UTF-8 |
| `02` | unavailable | length-prefixed UTF-8 |

The detail is human-readable prose from the host. A peer `MAY` show it to a person and `MUST NOT` parse
it, match on it, or branch on its content: the class is the machine-readable part, and the detail's
wording is not part of this wire. A reader `MUST` reject a claimed detail length above 1024 before
allocating for it, and `MUST` reject a detail that is not valid UTF-8 rather than repairing it lossily.

The maximum response frame is 1 + 1 + 2 + 1024 = 1028 octets.

## The state machine

Both sides are strictly sequential; there is no pipelining and no interleaving.

**Dialer.**

| state | event | action | next |
| ----- | ----- | ------ | ---- |
| `Opened` | credential present and the session does not prove the peer | write nothing, fail locally | `Closed` |
| `Opened` | otherwise | write the request frame | `AwaitingResponse` |
| `AwaitingResponse` | tag `00` | begin the pipe | `Piping` |
| `AwaitingResponse` | tag `01` and a known code | surface the typed refusal | `Closed` |
| `AwaitingResponse` | tag `01` and an unknown code | fail the stream as unreadable | `Closed` |
| `AwaitingResponse` | unknown tag, short read, or invalid UTF-8 | fail the stream | `Closed` |
| `Piping` | either direction ends | let the other drain, then close | `Closed` |

A dialer `MUST NOT` write a payload octet while in `AwaitingResponse`. A refusal makes those octets
unrecoverable, and on a credential path they would have been handed to a host that then declined the
dial.

A dialer that is about to announce success to a person (binding a local port, printing a ready line)
`SHOULD` first run one throwaway stream through `Opened` to `AwaitingResponse` and discard it. Admission
is per stream and deterministic for the same request, so the probe's outcome predicts the real stream's,
and a refusal then surfaces before anything is announced rather than as a stream that resets later.

**Host.**

| state | event | action | next |
| ----- | ----- | ------ | ---- |
| `Accepted` | preamble not complete within the read deadline | close, no octets | `Closed` |
| `Accepted` | identity is not `TB` | close, **no octets** | `Closed` |
| `Accepted` | identity `TB`, version not served | write bad request naming both versions | `Closed` |
| `Accepted` | body unreadable (bad presence octet, bad UTF-8, short) | close, no octets | `Closed` |
| `Accepted` | frame read | parse the service name | `Parsed` |
| `Parsed` | name outside the grammar | write bad request | `Closed` |
| `Parsed` | name well formed | run the gate on the resolved name | `Ruled` |
| `Ruled` | gate did not admit | write not admitted | `Closed` |
| `Ruled` | gate could not decide in time | write unavailable | `Closed` |
| `Ruled` | admitted, service disabled | write not admitted | `Closed` |
| `Ruled` | admitted, route is member-only and the dialer is not a member | write not admitted | `Closed` |
| `Ruled` | admitted, no such service | write not admitted | `Closed` |
| `Ruled` | admitted, target cannot be opened | write unavailable | `Closed` |
| `Ruled` | admitted and the target is open | write reached, begin the pipe | `Piping` |

Two orderings in that table are normative rather than incidental:

- The disabled check `MUST` run **after** the gate, never before. Both outcomes write the same octets,
  so a check that ran first would let a token holder tell "refused without a gate evaluation" from
  "refused after one" on the clock, and read the disabled set straight off the timing.
- The host `MUST` write `reached` only after the target is actually open and any single-use admission
  proof has been consumed. A host that announces success and then fails hands the dialer a stream that
  dies mid-pipe with no reason, which is the one outcome this preamble exists to prevent.

## Unrecognised values

The table a second implementation is judged by. Every value this wire can carry that a receiver might
not know, and what the receiver does with it:

| where | unrecognised value | receiver | required behaviour |
| ----- | ------------------ | -------- | ------------------ |
| request identity | anything but `TB` | host | close with **no octets written** |
| request version | any served-identity version the host does not speak | host | write bad request whose detail names the peer's version and the host's |
| presence octet | anything but `00` or `01` | host | close with no octets; the frame's remaining shape is unknowable |
| any text field | not valid UTF-8 | host | close with no octets; never repair lossily |
| service name | valid UTF-8, outside the name grammar | host | write bad request |
| service name | valid name, not exposed | host | write **not admitted**, identical to a gate miss |
| response tag | anything but `00` or `01` | dialer | fail the stream; `MUST NOT` be read as reached |
| refusal code | anything but `00`, `01`, `02` | dialer | fail the stream, reporting a refusal class this build cannot name; `MUST NOT` be mapped onto a known class, and `MUST NOT` be skipped (see [Known gaps](#known-gaps)) |
| detail length | greater than 1024 | either | reject **before** allocating the buffer |

The rule behind the last two rows is one rule: a value a build cannot name is never quietly promoted to
one it can. Reusing *not admitted* for an unknown code tells a dialer their credential was rejected by a
host that ruled no such thing; reusing *unavailable* buries arbitrary future classes under one word.

## Refusal semantics

A refusal class names the set of **dialer responses**, not the set of host causes. There are three
things a dialer can do about a refusal, so there are three classes:

| code | class | what the dialer does |
| ---- | ----- | -------------------- |
| `00` | not admitted | the same dial will be refused again; obtain, renew or repair a credential, or ask to be admitted. No retry. |
| `01` | bad request | the request itself was rejected before any policy ran; fix the request or the version. No retry. |
| `02` | unavailable | the failure is the host's own and rules on nothing about this dialer; retry later. |

**Not admitted is deliberately uniform, and that uniformity is a security property.** A conformant host
`MUST` write the identical two octets `01 00`, with no detail and no further distinction, for **every**
one of these:

- the named service does not exist on this host,
- the named service exists but is disabled,
- the named service exists and its route is member-only, and the dialer is not a member,
- no credential was presented and the gate does not admit this identity on its own,
- a credential was presented and does not grant this service,
- a credential was presented and has been revoked,
- a credential was presented and did not parse,
- the session does not prove the peer, so a rooted gate cannot rule on a presented token,
- the host's public-path capacity is saturated,
- the route's handler refuses an unrooted admission.

A host `MUST NOT` distinguish these on the wire, `MUST NOT` add a refusal code that separates any of
them, and `MUST NOT` let the choice show in timing (see the ordering rules in
[The state machine](#the-state-machine)). A dialer learns a service exists by being admitted to it and
in no other way. The finer cause belongs in the host's own log, where the operator who owns the policy
can read it.

**Unavailable is not an authorization outcome.** It means "this is about us, not about you" and nothing
more. It `MUST NOT` be recorded, logged or surfaced as a ruling on the dialer, and in particular it is
**not** evidence that the dialer was admitted: a host whose gate ran out of time before deciding sends
it, and that gate decided nothing. Its detail is fixed host prose that `MUST NOT` vary with host state
for any pre-admission cause, because a detail that varied with load would put a side channel on a
refusal written before any ruling was made.

**Bad request carries the dialer's own grammar back.** That is why it is the one class allowed a
specific detail before any policy has run: the version a dialer sent, or the name it asked for, is
already known to the dialer. A host `MUST NOT` interpolate host state into a pre-admission bad-request
detail.

## Caps

Every bound this wire places on a receiver, with its unit. A cap marked `MUST` is part of the wire: an
implementation that exceeds it writes frames a conformant peer rejects, or accepts frames a conformant
peer never writes. A cap marked *host policy* is a resource decision each host makes for itself; the
value shipped here is given so a second implementation has a sane starting point, and the `MUST` is only
that **some** finite bound exists.

| bound | value | unit | strength |
| ----- | ----- | ---- | -------- |
| service name | 1 to 128 | octets | `MUST` |
| any length-prefixed text field | 65 535 | octets | `MUST` (the u16 length cannot express more) |
| refusal detail | 1024 | octets | `MUST`, enforced by both writer and reader |
| request frame, total | 196 617 | octets | `MUST` (derived: `4 + 2+65535 + 3+65535 + 3+65535`) |
| response frame, total | 1028 | octets | `MUST` (derived: `1 + 1 + 2 + 1024`) |
| preamble read deadline | 10 | seconds | host policy; a finite deadline is a `MUST` |
| concurrent sessions | 256 | sessions | host policy |
| concurrent streams per session | 256 | streams | host policy |
| concurrent sessions on the public path | 32 | sessions | host policy |
| concurrent streams on the public path | 4 | streams | host policy |
| concurrent raw-stream opens | 16 | opens | host policy |

The preamble read deadline is the one host-policy bound with a wire consequence: a peer that opens a
stream and never writes would otherwise park a host task and its buffer **before** the gate runs, so an
unauthenticated peer could exhaust a host one silent stream at a time. A host `MUST` bound the time from
accepting a stream to reading a complete preamble, and `MUST` close the stream with no octets written
when it elapses. A dialer `SHOULD` therefore write its request immediately on opening a stream, rather
than holding the stream open while it decides what to ask for.

Reaching a public-path capacity bound is refused with the uniform *not admitted*, never queued. Queueing
would park one stranger's stream behind another's, and a distinct answer would tell a dialer the host is
saturated.

## Versioning and the frozen response

There is **no negotiation** on this wire. A dialer speaks exactly one version, a host serves exactly one
version, and there is no field in which to offer a list. A dialer `MUST NOT` attempt to downgrade by
retrying with another version's magic; the answer to a version mismatch is to run the same release at
both ends.

**The request preamble may break with a version bump.** It carries the evolving authorization
vocabulary, and it is the gate's input record. A host `MUST NOT` skip a request field it does not
understand: a gate that ignores an input it cannot read is a downgrade, and that is precisely why this
frame cannot grow additively and must move its version instead.

**The response frame is frozen from TB04 forward.** A future version of the request grammar:

- `MUST NOT` change the meaning or width of the response tag,
- `MUST NOT` change the shape or meaning of an existing refusal code,
- `MAY` add a new refusal code,
- `MUST NOT` add a new response tag.

The freeze is what makes a version mismatch answerable at all: a host cannot answer a peer whose request
it cannot parse unless part of the wire is stable across every version. Versioning the response too
would put every future break back to a bare closed stream, which is where this wire started and what it
was changed to stop.

The freeze promises "a break names itself and announces itself", never "no break".

## Known gaps

Stated here rather than discovered later. Each is a real limit of the wire as it stands, with the fix it
is waiting for.

**1. An unknown refusal code cannot be skipped.** Code `00` carries no detail and codes `01` and `02`
carry a length-prefixed one, so the shape of a frame depends on knowing its code. A peer that meets a
code it does not know cannot find the end of the frame and `MUST` fail the stream rather than guess.
That makes "a new code is additive" true only between ends that both know the code, which is weaker than
the freeze above reads. The named fix is a **mandatory, possibly empty, detail on every code**: one
shape for all codes, so an unknown code is skippable and the additive promise becomes real. It rides the
next wire change rather than a break of its own, because every code a peer meets today is one it already
knows.

**2. An unreadable body gets silence, where an unreadable version gets an answer.** A head that names
`TB04` has proved the peer speaks this grammar, so a malformed presence octet, a truncated field or
invalid UTF-8 in the body could be answered with a bad request the peer would understand. It is not: any
failure past the version check closes the stream with no octets. A dialer therefore `MUST` treat a
closed stream with no response as "the host could not read my request", which is the least actionable
outcome on the wire. The fix is to answer bad request for a malformed body too, which needs no version
bump because it adds no code.

**3. The credential slots have no cap below the field width.** A host reads up to 65 535 octets in each
of the two token slots before any gate runs, and both are peer-supplied and unauthenticated at that
point. The field bound is enforced, the read deadline bounds the time, and the per-session stream cap
bounds the concurrency, so this is a cost rather than a hole. A host `SHOULD` bound each slot to the
largest token its authorization model can actually issue.

## Test vectors

Every octet below is produced by the codec in `src/protocol.rs` and checked against this page by
`cargo test`; see [Regenerating the vectors](#regenerating-the-vectors). Three of the vectors are peer
**heads** rather than frames this implementation writes: they are the input, published beside the answer
each provokes, and two of the three provoke none.

The token text in the credentialed request is a short stand-in. Both slots are opaque to this wire, so
the vector fixes the framing around a token, never the token's own grammar.

### A minimal request

Service `ssh`, neither credential slot filled.

```text
vector tb04-request-minimal
54 42 30 34 00 03 73 73 68 00 00
```

| octets | field | value |
| ------ | ----- | ----- |
| `54 42` | identity | `TB` |
| `30 34` | version | `04` |
| `00 03` | service length | 3 |
| `73 73 68` | service | `ssh` |
| `00` | capability present | absent |
| `00` | membership present | absent |

### A request carrying a capability and a membership badge

Service `ssh`, slot 1 `sheer:bf01abc.def`, slot 2 `sheer:bf02ghi.jkl`.

```text
vector tb04-request-capability-and-membership
54 42 30 34 00 03 73 73 68 01 00 11 73 68 65 65
72 3a 62 66 30 31 61 62 63 2e 64 65 66 01 00 11
73 68 65 65 72 3a 62 66 30 32 67 68 69 2e 6a 6b
6c
```

| octets | field | value |
| ------ | ----- | ----- |
| `54 42 30 34` | magic | `TB04` |
| `00 03` `73 73 68` | service | `ssh` |
| `01` | capability present | present |
| `00 11` | capability length | 17 |
| `73 68 ... 65 66` | capability | `sheer:bf01abc.def` |
| `01` | membership present | present |
| `00 11` | membership length | 17 |
| `73 68 ... 6b 6c` | membership | `sheer:bf02ghi.jkl` |

### The reached response

One octet. The byte pipe begins immediately after it.

```text
vector tb04-response-ok
00
```

### Refused, not admitted

Two octets, and these exact two octets are what every cause listed in
[Refusal semantics](#refusal-semantics) produces.

```text
vector tb04-response-not-admitted
01 00
```

### Refused, bad request: the service name is not a name

The dialer asked for `ssh admin`, which is outside the name grammar (it contains a space). The detail is
host prose and is shown here only so the framing is complete.

```text
vector tb04-response-bad-request-service-name
01 01 00 20 69 6e 76 61 6c 69 64 20 73 65 72 76
69 63 65 20 6e 61 6d 65 20 22 73 73 68 20 61 64
6d 69 6e 22
```

| octets | field | value |
| ------ | ----- | ----- |
| `01` | tag | refused |
| `01` | code | bad request |
| `00 20` | detail length | 32 |
| `69 6e ... 6e 22` | detail | `invalid service name "ssh admin"` |

### Refused, unavailable

The gate ran out of time and so ruled on nothing. The detail is fixed text: it `MUST NOT` carry host
state.

```text
vector tb04-response-unavailable
01 02 00 2f 74 68 65 20 67 61 74 65 20 64 69 64
20 6e 6f 74 20 66 69 6e 69 73 68 20 64 65 63 69
64 69 6e 67 20 69 6e 20 74 69 6d 65 3b 20 72 65
74 72 79
```

| octets | field | value |
| ------ | ----- | ----- |
| `01` | tag | refused |
| `02` | code | unavailable |
| `00 2f` | detail length | 47 |
| `74 68 ... 72 79` | detail | `the gate did not finish deciding in time; retry` |

### A version mismatch, and the answer to it

The head a peer on `TB05` writes, carrying the same minimal request body:

```text
vector tb04-head-version-mismatch
54 42 30 35 00 03 73 73 68 00 00
```

The answer a `TB04` host writes to it, and the only answer a version mismatch ever gets. Both versions
are named, because either one alone leaves the reader guessing at the other:

```text
vector tb04-response-bad-request-version-mismatch
01 01 00 6e 74 69 67 68 74 62 65 61 6d 20 77 69
72 65 20 76 65 72 73 69 6f 6e 20 6d 69 73 6d 61
74 63 68 3a 20 74 68 65 20 72 65 71 75 65 73 74
20 69 73 20 54 42 30 35 2c 20 74 68 69 73 20 68
6f 73 74 20 73 70 65 61 6b 73 20 54 42 30 34 3b
20 72 75 6e 20 74 68 65 20 73 61 6d 65 20 72 65
6c 65 61 73 65 20 61 74 20 62 6f 74 68 20 65 6e
64 73
```

| octets | field | value |
| ------ | ----- | ----- |
| `01` | tag | refused |
| `01` | code | bad request |
| `00 6e` | detail length | 110 |
| `74 69 ... 64 73` | detail | `tightbeam wire version mismatch: the request is TB05, this host speaks TB04; run the same release at both ends` |

The peer's two version octets are arbitrary and need not be printable. A host `MUST` escape them before
putting them in the detail, and `MUST` keep the result inside the 1024 octet detail cap, since escaping
expands each octet.

### A foreign head

A head from something that is not this protocol at all:

```text
vector tb04-head-foreign
53 53 48 2d 00 03 73 73 68 00 00
```

The correct answer is **zero octets**. There is no vector for the reply because there is no reply.

### A neighbouring identity

The head a peer on the `TBH1` wire writes. Its identity is `TBH`, not `TB`, because the run of capitals
does not stop after two octets, and a wire whose identity is not `TB` is foreign however closely it
starts like this one. The correct answer is **zero octets**, exactly as for the foreign head above, and
there is no vector for the reply because there is no reply:

```text
vector tb04-head-neighbouring-identity
54 42 48 31 00 03 73 73 68 00 00
```

## Regenerating the vectors

The vectors are generated, never typed. `src/protocol_tests.rs` builds each frame with this crate's own
writer, proves the reader takes the same octets back to the same value, parses this file, and fails when
the two disagree in either direction: a vector this page publishes that the codec no longer writes is
the same defect as one the codec writes that this page has not caught up with.

Run:

```text
cargo test -p tightbeam --lib protocol_tests::vectors -- --nocapture
```

It prints every vector in exactly the block form used above, sixteen octets to a line, so a regenerated
block pastes over the old one unedited. The test reads this file for lines of the form `vector <name>`
and takes the octet lines under each, up to the next blank line or fence, as that vector's frame. Keep
that shape when editing, and keep the field-by-field tables beside the blocks in step by hand: the octets
are checked mechanically, the annotations are not.
