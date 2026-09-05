# What you can run over it

A forward carries bytes. Anything that speaks over a TCP port or a Unix socket runs over it unchanged:
the program on each end does not know the overlay is there. Below are worked examples. Each shows the
host's one line, the other machine's one line, and what happens.

## Get the binary

Not published yet, so build it from a checkout:

```sh
git clone https://github.com/theia-hq/tightbeam
cd tightbeam
cargo build --release
```

The binary lands at `target/release/tightbeam`. Put it on your `PATH`, or run it by that path. The
examples below write it as `tightbeam`.

## Try it on one machine

Before you have a second machine, you can run both ends on the one you are on and watch bytes cross.
Open two terminals in the same directory.

Terminal 1, the host. Make a file to serve, then expose it:

```sh
echo 'hello over the tunnel' > hello.txt
tightbeam expose demo=file:./hello.txt --public --public-unsafe demo \
  --key ./host.key --bind-addr 127.0.0.1:9000
```

The readiness banner prints the host's node id, a `bf01...` string. That id is `<peer>` in the next
command. Leave this terminal running.

Terminal 2, the client. Paste the host's id in place of `<peer>`:

```sh
tightbeam connect <peer> --service demo --to - \
  --key ./client.key --offline --peer <peer>=127.0.0.1:9000
```

It prints `hello over the tunnel` and exits. The bytes crossed the tunnel from one process to the other.

What each flag does:

- `--key ./host.key` and `--key ./client.key` give each side its **own** identity file (tightbeam
  creates it on first use). This is the one part a single machine forces on you: without separate keys
  both processes are the same identity, and `connect` refuses with `Connecting to ourself is not
  supported`. On two real machines each already has its own identity, so you drop `--key` entirely.
- `--bind-addr 127.0.0.1:9000` on the host pins a fixed local address so the client can point straight
  at it. It implies `--offline`.
- `--offline` with `--peer <peer>=127.0.0.1:9000` on the client skips global discovery and dials the
  host at that exact address. This is what makes the loopback (or a LAN, or Docker) work with no network
  in the path.

This local demo serves to **anyone** (`--public-unsafe`) on purpose: two separate identities on one
machine are strangers to each other, so the client cannot pass the host's private gate. On offline
loopback "anyone" is just you, so it is harmless here. Reaching a real machine uses a key instead, which
is every section from here on.

## Reaching a real machine

To reach another machine over the internet, drop `--offline`, `--peer`, and `--bind-addr`: global
discovery finds the peer by its key, across NAT, with no public IP. `<peer>` is the host's node id from
the `expose` banner, or a `sheer:` link from `tightbeam share`.

Two things hold for every example below:

- `connect` gives you a local endpoint on your machine: a plain `127.0.0.1:<port>`, or this process's
  own stdout with `--to -`. You point any local client at it.
- Who may reach a service is the host's choice, made when it runs `expose`. By default only the host's
  own devices and anyone the host hands a key can reach it. The sections split into the two ways in:
  **give someone a key** (the normal, safe way) and, at the end, **serve to anyone** (the deliberate,
  dangerous opt-out).

## Give someone a key (the safe default)

The host runs sshd and wants one other person to reach it: no port-forward, no public IP, and no account
on any middleman. The host's own devices already pass its gate. To let someone else in, mint a link to one
service and send it. The link is the grant: signed, expiring, and good for that one service only.

```sh
# on the host: expose ssh, then mint a 2-hour link to it
tightbeam expose ssh=127.0.0.1:22
tightbeam share ssh --expires 2h        # prints: sheer:<node-id>.<token>
```

```sh
# on their machine: the link carries both the host's key and the grant, so nothing else is needed
tightbeam connect sheer:<node-id>.<token> --service ssh --to 2222
ssh -p 2222 you@127.0.0.1
```

The link works only for `ssh`, expires on its own after two hours, and reaches nothing else on the host.
Revoke it early with `tightbeam revoke`; short expiry backs that up. Add `--delegable` to `share` if the
holder may narrow the link and pass it on.

Everything from here to the last section reaches the host the same way: a peer that holds the host's key
and passes its gate. The final section is the one exception, where you serve to anyone with no key at all.

## Stream a file by key

The host has a file. You want it on another machine, with no public IP, no copy, and no HTTP server to
stand up. Serve the file's bytes directly:

```sh
tightbeam expose movie=file:/srv/films/big.mkv     # on the host
```

```sh
tightbeam connect <peer> --service movie --to - | mpv -    # on your machine
```

`file:<path>` streams the file's raw bytes toward the peer, so there is no port to bind, no `cat`, and
no background process. It serves a regular file or a FIFO only: a device, a directory, or a socket at the
named path is refused at startup, before anyone connects. It reaches only a peer that holds your key; to
hand the file to anyone with no key, see the last section.

## A live feed to a player on the other side

The host has a camera or a screen you want to watch live elsewhere. Pipe the producer straight into
`expose` and read it into a player on the far side. Use low-latency flags on both ends, or the picture
lags seconds behind reality: by default ffmpeg and the player each buffer several frames.

```sh
# on the host (macOS): capture the webcam as zero-latency h264 and pipe it into expose.
# pick the camera index from: ffmpeg -f avfoundation -list_devices true -i ""
ffmpeg -f avfoundation -framerate 30 -video_size 640x480 -i "0:none" \
  -c:v libx264 -preset ultrafast -tune zerolatency -g 15 -bf 0 -pix_fmt yuv420p \
  -f mpegts -flush_packets 1 pipe:1 \
| tightbeam expose cam=stdin: --public --public-unsafe cam
```

```sh
# on your machine: read the stream into a player with its buffering turned off
tightbeam connect <peer> --service cam --to - \
| ffplay -fflags nobuffer -flags low_delay -framedrop -probesize 32 -analyzeduration 0 -i pipe:

# or mpv:
tightbeam connect <peer> --service cam --to - \
| mpv --profile=low-latency --no-cache --untimed -
```

The encoder flags emit each frame the moment it is captured (`-tune zerolatency`, no B-frames, a small
GOP, flush every packet); the player flags show frames as they arrive instead of building a queue. On
Linux the producer reads `/dev/video0` instead of the avfoundation input and pipes it in the same way.

A live capture goes through a **pipe** into `stdin:`, not `file:` a device node: `file:` is for a file on
disk, and a running camera is a producer you pipe in. `stdin:` serves whatever a producer pipes into
`expose`, so the whole live case is one pipe: no `mkfifo`, no background job, no temp path. It is
**single-consumer**: standard input is one stream, so the first peer to reach it takes it, and a second
concurrent connection is refused cleanly rather than corrupting the feed with a racing second read.

> `fifo:<path>` is the alternative when you want several serially-reconnecting readers over one named pipe
> on disk; `stdin:` is the one-shot pipe.

## Watch a whole media server over your key

The host runs Plex or Jellyfin. You want the whole library on another machine you own, without opening
the server to the public internet. Forward the server's port and open the web UI on the local port:

```sh
tightbeam expose plex=127.0.0.1:32400        # on the host (Jellyfin: jellyfin=127.0.0.1:8096)
```

```sh
tightbeam connect <peer> --service plex --to 32400    # on your machine
open http://127.0.0.1:32400                           # or point a Plex/Jellyfin app at it
```

Your whole library streams to any machine you own, addressed by key and gated to your signet. There is
no port-forward and the server never faces the public internet.

## Send a directory as it packs

Pipe `tar` straight into `expose` and unpack it on the far side as it arrives:

```sh
# on the host: pack the directory and pipe it into expose
tar -cf - ~/project | tightbeam expose bundle=stdin:
```

```sh
# on your machine: pull the stream and unpack it in place
tightbeam connect <peer> --service bundle --to - | tar -xf -
```

`--to -` streams one service against this process's own stdout (and reads its stdin) instead of binding a
port, so tightbeam becomes a transport for anything that reads stdin and writes stdout. It is the same
shape ssh uses for its `ProxyCommand` (see the README).

## Anything with a local address is reachable by key

A database port or a Unix socket. One `expose` and one `connect` each.

A Postgres server on the host, reached with `psql` from your machine:

```sh
tightbeam expose db=127.0.0.1:5432                  # on the host
tightbeam connect <peer> --service db --to 5432    # on your machine
psql -h 127.0.0.1 -p 5432 -U postgres
```

A Unix socket (here the Docker daemon) reached as a TCP port you can point tooling at:

```sh
tightbeam expose docker=unix:/var/run/docker.sock           # on the host
tightbeam connect <peer> --service docker --to 2375        # on your machine
DOCKER_HOST=tcp://127.0.0.1:2375 docker ps
```

## Serve to anyone (the deliberate, dangerous opt-out)

Everything above reaches only someone who holds the host's key. Sometimes you want the opposite: hand a
file or a live feed to anyone who connects, with no key at all, e.g. a public release artifact or a feed
you mean to broadcast. That is `--public-unsafe`, and it is exactly as dangerous as the name says: anyone
who can reach the host reads those bytes.

A raw-stream source (`file:`/`fifo:`/`stdin:`) has no way to check who is on the other end, so it is never
opened by accident. Plain `--public` refuses it and points you here:

```sh
tightbeam expose movie=file:/srv/films/big.mkv --public
# error: `movie` is a raw byte source (file:/fifo:/stdin:) with no auth of its own, so a public gate
#        will not serve it. to serve its raw bytes to anyone, name it in the unsafe raw-stream set;
#        otherwise gate it or drop it from the public set
```

Opening it is a separate, deliberate step. `--public` opens the whole node to anyone, and `--public-unsafe`
names which raw streams that open node may serve, so you pass both:

```sh
tightbeam expose movie=file:/srv/films/big.mkv --public --public-unsafe movie
```

```sh
# on anyone's machine, no key needed:
tightbeam connect <peer> --service movie --to - | mpv -
```

On startup the host prints a loud warning naming the exact bytes at risk, one line per opened stream, by
resolved absolute path:

```
UNSAFE: `movie` is serving the raw bytes of /srv/films/big.mkv to anyone, no auth
```

Read that path. It is the real file the host is about to hand to any stranger, resolved from whatever you
typed. So `--public-unsafe logs` where `logs=file:~/.ssh/id_ed25519` prints the actual key path, your cue
that you just aimed a secret at the world. If the path is not what you meant, stop the host (ctrl-c) and
fix it before anyone connects. A live source names its risk too: `stdin:` and `fifo:` report `serving this
process's piped stdin to anyone, no auth`.

`--public-unsafe` is the only way a raw stream is ever served without a key, and you name each one by hand:
there is no "open everything" switch. Everything not named stays gated to your key, exactly as in the
sections above.
