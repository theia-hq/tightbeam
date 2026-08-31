# The capability wedge, end to end

> *"Here's a link to reach my box's ssh. It only works for ssh, it expires, you can narrow it further and
> hand it to a colleague, and there is no server anywhere that issued it, can see it, or can revoke it."*

A `sheer:` share-link is a real bearer capability: signed by the exposer's own identity, offline
verifiable, attenuable, delegable. This is the one thing no incumbent offers (ngrok/CF give a guessable
URL backed by their ingress; Tailscale needs a tailnet plus a central ACL; croc is a one-shot code; SSH
`authorized_keys` cannot attenuate, expire, or delegate; iroh punts authz to the app). It runs over the
real iroh transport today.

## The verbs

```
tightbeam expose ssh=127.0.0.1:22                # gated to the signet by default, which accepts caps
tightbeam share ssh --expires 2h --delegable     # mint a sheer:<node>.<token> link
tightbeam attenuate <link> --service ssh --expires 30m   # narrow a link, offline, no key
tightbeam connect <link> --to 2222               # dial + present the token, from the link alone
```

The default signet gate already admits a presented capability, so no extra flag turns it on. The exposer
mints with its persisted `NodeId` as the biscuit root and verifies presented caps against it. No server,
no allowlist file to sync. A holder runs `attenuate` locally (offline) to narrow before handing off; the
exposer verifies the whole chain without ever seeing the delegation.

## A real run (iroh backend)

Two distinct iroh identities (an exposer and a connector), a local echo service exposed as `ssh`, gated on
a capability. The cap is minted by the exposer, narrowed twice offline (once by a holder, once by a third
party), then used by the connector. The refusals share the same live tunnel.

```
### 1. exposer publishes ssh=<echo> behind its signet gate (no allowlist anywhere)
    exposer node id: bf01mjwxs225tml3yqnrm64zrwysqxmzpkutp5w7y3j7hu3zq5qp3b6a

### 2. exposer mints a delegable ssh cap, valid 2h -> a sheer link
    sheer:bf01mjwxs225tml3yqnrm64zrwysqxmzpkutp5w7y3j7hu3zq5qp3b6a.clfaccs6biaxgcq...

### 3. a holder narrows to 30m (offline), then a THIRD PARTY narrows to ssh + 10m
    delegated: sheer:bf01mjwxs225tml3yqnrm64zrwysqxmzpkutp5w7y3j7hu3zq5qp3b6a.clfaccs6...
    (attenuation used NO key and NO network; the exposer never saw the delegation)

### 4. connect USING the delegated link alone (it dials + presents the token)
    delegated ssh cap (valid)      -> hello over a capability

### 5. the refusals (all over the same live iroh tunnel)
    no cap presented               -> REFUSED (ConnectionResetError)
    wrong-service cap (web->ssh)   -> REFUSED (ConnectionResetError)
    expired cap (1s, elapsed)      -> REFUSED (ConnectionResetError)
```

The valid, twice-narrowed, delegated cap carries `hello over a capability` back through the tunnel. A
connector with no cap, a cap minted for a different service, or an expired cap is refused. The exposer
verified every token offline against its own key, with no control plane in the loop.

## What roots the trust

The cap is a [biscuit](https://www.biscuitsec.org): an ed25519-signed, datalog-attenuable token whose
root key is the exposer's `NodeId` key. Verification is "does this token chain back to the key I am?".
Attenuation appends checks and can only ever narrow (biscuit blocks are append-only), so broadening is
impossible by construction. The crypto lives in the vetted `biscuit-auth` crate, wrapped behind
`nauthy::Cap`; tightbeam never hand-rolls it.

## Revocation

Short expiry only, for v1. The `time()` check IS the revocation story; a link expires and stops working
with no server to consult. A revocation-hint channel is a later design point, not built now.
