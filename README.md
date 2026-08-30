# tightbeam

Reach a service on a machine with no public IP: no port forwarding, no VPN, no cloudflared. Expose a
local service by its public key on one machine, reach it as a local port on another, peer to peer with
nothing in between. `ssh -L` shaped, but pubkey-addressed.

Powered by [bifrost](https://github.com/theia-hq/bifrost) for the keyed connection and
[nauthy](https://github.com/theia-hq/nauthy) for authorizing who may connect.

**The name.** A tightbeam is a tight, aimed beam: a private point-to-point link that goes only where
you point it, not out to everyone. That is what this does, one machine's service reaching exactly
one other, addressed by key.

> Experimental. Works for TCP over the iroh transport; not ready for production use.

## Installation

Not yet published. Build from a checkout:

```sh
cargo install --path .
```

## Usage

Expose one or more local services (on the machine that has them). A target may be a `host:port` or a
`unix:<path>` socket:

```sh
tightbeam expose ssh=127.0.0.1:22 web=127.0.0.1:80 docker=unix:/var/run/docker.sock
```

Reach a service from another machine, bound to a local port:

```sh
tightbeam connect <node-id> --service ssh --to 2222
```

A bare address exposes the `default` service, which `connect` reaches without `--service`:

```sh
tightbeam expose 127.0.0.1:22      # on the host
tightbeam connect <node-id> --to 2222
```

By default a service is gated to this node's signet, set once by `swoosh adopt`: it admits the owner's
own devices and anyone they delegate a capability to (below), and refuses everyone else. Pass
`--public` to open a service to anyone, unauthenticated, the one deliberate opt-out.

`expose --quiet` suppresses the readiness banner, so the node's key never lands in a log, for unattended
or CI use. The tunnel runs the same either way.

For worked examples of what to run over a tunnel (stream a movie, pipe a raw stream, reach a database
port), see [examples.md](examples.md).

## Share a service as a capability

The default gate already accepts capabilities: a signed, expiring, attenuable link rooted at this
node's signet, verified offline with no server and no allowlist to sync. Mint one with `share` and
hand it to someone outside your own devices.

```sh
# on the host: expose ssh, gated to your signet by default
tightbeam expose ssh=127.0.0.1:22

# mint a share-link for ssh, valid two hours, that the holder may narrow and hand on
tightbeam share ssh --expires 2h --delegable      # prints sheer:<node>.<token>

# a holder narrows it further, offline, before delegating (no key, no network)
tightbeam attenuate <link> --service ssh --expires 30m

# anyone holding the link connects with it; it carries the node to dial and the token to present
tightbeam connect <link> --to 2222
```

The link works only for the service it grants, expires on its own, and can be narrowed and delegated
without the host's involvement. Drop `--delegable` to seal a link so its recipient can use but not
re-share it. `tightbeam revoke <link>` cuts a link off at once, without waiting for its expiry; short
expiry backs that up. There is no server to ask, only a node-local denylist. See
[DEMO-WEDGE.md](DEMO-WEDGE.md) for a full run over iroh.

## ssh over the overlay

ssh to a machine with no public IP, by its key. Expose its sshd as a service on the host, then point
ssh's `ProxyCommand` at `connect --stdio`: tightbeam pipes the overlay stream over ssh's stdin/stdout,
so ssh talks to the far sshd as if it were local.

On the host, expose sshd:

```sh
tightbeam expose ssh=127.0.0.1:22
```

`--stdio` pipes the service over stdin/stdout instead of binding a local port, which is exactly what an
ssh `ProxyCommand` wants. You cannot type `ssh alice/desk` directly: `/` is not legal in a hostname (and
it is theia's device separator), so ssh cannot parse it. Give ssh a legal alias in `~/.ssh/config`
instead:

```
Host alice-desk
    ProxyCommand tightbeam connect <peer> --service ssh --stdio
```

Then:

```sh
ssh alice-desk
```

`<peer>` is the host's node id, or a `sheer:` capability link (`tightbeam share ssh …`). With a link,
auth composes for free: the link names the node to dial and carries the token, so a link that reaches
only ssh and expires in an hour becomes an ssh `ProxyCommand` with nothing else to configure.

## Compose an overlay exit

tightbeam does not ship a proxy; it tunnels any existing one. To route traffic out through a remote
peer, run a proxy on the exit host and expose it (`ssh` provides a SOCKS5 proxy on any machine):

```sh
# on the exit host
ssh -D 1080 -N localhost        # or dante / Caddy / mitmproxy
tightbeam expose 127.0.0.1:1080

# on your machine
tightbeam connect <exit-node-id> --to 1080   # then point apps at socks5://127.0.0.1:1080
```

## Fetch a URL through a peer

The `fetch:` target is a built-in egress: instead of splicing to a local socket, the exposing node acts
as an HTTP client, fetches an origin URL, and streams the response back. TLS terminates at the exit, not
at the requester. It is GET/HEAD only and scoped to the URL asked for, so it is a fetch, not an open
proxy.

```sh
# on the exit host: expose the fetch service, gated to your signet by default
tightbeam expose fetch=fetch:
```

A requester hands the exit an origin URL and receives the body over the stream. `swoosh fetch <url>
--via <peer>` drives this end, minting a plain local URL that anything (`curl`, a browser) can pull,
`Range` intact so a resumable download resumes.

## Where this is heading: names you can type anywhere

> Not shipped. This is the target, not what runs today. The `ProxyCommand` alias above is what works
> now.

The alias works, but you still edit `~/.ssh/config`, and only ssh benefits. The goal is a real name you
type into any app and it resolves:

```sh
ssh desk.alice
ssh desk.alice.<user>.theia.net
curl http://desk.alice
```

No ssh-config, no `ProxyCommand`. This is the Tailscale MagicDNS model: a local DNS resolver answers the
overlay's names, and a DNS search domain lets you type the short form (`desk.alice`) instead of the full
one. `desk.alice.<user>.theia.net` is a right-to-left reading of the internal `alice/desk` address, so
`/` never has to appear in a hostname.

This needs a background daemon, because a resolver holds OS-level DNS state and a name-to-peer map that
must outlive any one command. That is why the `ProxyCommand` recipe ships first and this is roadmapped
(P10). The suffix has to be safe: a domain we own (`theia.net`) or the reserved-for-private-use
`.internal`. Not `.id`, which is a real country-code TLD (Indonesia), not ours to take.

## Things to know

- Built on [`bifrost`](https://github.com/theia-hq/bifrost) (reach): each proxied connection is one
  bidirectional stream. It is transport-blind and rides any bifrost transport.
- Only a peer holding the key can dial, and authorization is enforced by the
  [`nauthy`](https://github.com/theia-hq/nauthy) crate: the default gate admits a presented `sheer:`
  token rooted at this node's signet (a device's membership badge or a delegated service slip);
  `--public` is the only opt-out.
- TCP and unix-socket (`unix:<path>`) targets are supported.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the
work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any
additional terms or conditions.
