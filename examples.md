# Getting started

tightbeam reaches a service on another machine by that machine's **public key**, not its IP. No port
forwarding, no VPN, no public IP: discovery finds the peer by its key, across NAT. You address *who*, not
*where*. A connection is a plain bidirectional byte stream, so anything that speaks a TCP port or a Unix
socket rides it unchanged.

This page walks from nothing to a working tunnel, one step at a time. Every command here was run as written.

## 1. Get the binary

Not published as a prebuilt binary yet, so build it from a checkout:

```sh
git clone https://github.com/theia-hq/tightbeam
cd tightbeam
cargo build --release
```

The binary lands at `target/release/tightbeam`. Put it on your `PATH`, or run it by that path. The
examples below write it as `tightbeam`.

## 2. echo: your first success

`echo:` is a built-in reflector. It sends your bytes straight back and opens nothing on the host, so it is
the safe way to watch a tunnel work end to end before you point one at anything real.

On the machine you want to reach:

```sh
tightbeam expose demo=echo: --public
```

The banner prints this node's key, a `bf01...` string:

```
tightbeam ready. peers can reach these services at:

    bf01ksohhwnkthxk2vy2pxrtjrrqkk22iou4q5zzu7n37crh4sdnszjq   (share this key, or mint a link with `tightbeam share`)

exposing demo. gate: public (anyone, unauthenticated). ctrl-c to stop.
```

`--public` opens the service to anyone who reaches it. That is safe *here* because `echo:` exposes nothing
of yours: it only bounces your own bytes back. echo is the one source that goes public with plain `--public`
and no louder flag. A real service needs more care, which the next steps cover.

On your machine, paste the host's key in place of `<peer>` and send it a line:

```sh
echo 'hello over the tightbeam' | tightbeam connect <peer> --service demo --to -
```

It prints `hello over the tightbeam` and exits. The bytes crossed to the other machine and back. You never
typed an address: discovery found the host by its key. `--to -` streams the service over this process's own
stdout and stdin, so a pipe is all you need.

> **No internet, or trying both ends on one machine?** Two ends on one machine are two strangers, so give
> each its own identity file, and dial a fixed local address instead of using discovery:
>
> ```sh
> # host
> tightbeam expose demo=echo: --public --key ./host.key --bind-addr 127.0.0.1:9000
> # client (paste the host's key as <peer>)
> echo hi | tightbeam connect <peer> --service demo --to - --key ./client.key --offline --peer <peer>=127.0.0.1:9000
> ```
>
> `--key` gives each side its own identity (tightbeam creates the file on first use); `--bind-addr` pins a
> local address; `--offline` with `--peer` dials that exact address with no discovery. You do not need any
> of these on two real machines: each already has its own identity, and discovery finds the peer by key.

## 3. Serve your own bytes

Now serve bytes you choose. Pipe anything into `stdin:` and the peer reads it:

```sh
echo 'hello' | tightbeam expose greeting=stdin: --public --public-unsafe greeting
```

A raw byte source like `stdin:` has no way to check who is on the other end, so opening it to anyone is a
deliberate, louder step. `--public` opens the node; `--public-unsafe greeting` names which raw stream that
open node may serve. `--public` alone refuses a raw source and points you here:

```
Error: `greeting` is a raw byte source (file:/fifo:/stdin:) with no auth of its own, so a public gate will
not serve it. to serve its raw bytes to anyone, name it in the unsafe raw-stream set; otherwise gate it or
drop it from the public set
```

When you do open it, the host prints a loud line on startup naming exactly what is exposed:

```
UNSAFE: `greeting` is serving this process's piped stdin to anyone, no auth
```

Read that line. It is the real thing you are about to hand to any stranger. For a file it prints the
resolved absolute path, so `--public-unsafe logs` where `logs=file:~/.ssh/id_ed25519` prints that key's
path, your cue that you just aimed a secret at the world.

On your machine:

```sh
tightbeam connect <peer> --service greeting --to -
```

It prints `hello`.

`stdin:` is one-shot: the first reader consumes it. `file:<path>` is the same idea for a file on disk, and
it re-serves the file to each reader that connects.

## 4. A live video feed

Pipe a camera straight into `expose` and read it into a player on the other side. Use low-latency flags on
both ends, or the picture lags seconds behind reality: by default the encoder and the player each buffer
several frames.

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

**Do not use VLC to watch a live feed.** Its default network cache buffers several seconds, so the picture
runs seconds behind no matter what the sender does. That buffer is the lag trap; ffplay and mpv with the
flags above show frames as they arrive.

The encoder flags emit each frame the moment it is captured (`-tune zerolatency`, no B-frames, a small GOP,
flush every packet). On Linux the host reads `/dev/video0` instead of the avfoundation input and pipes it in
the same way. The feed goes through a **pipe** into `stdin:`, so the whole live case is one pipe: no
`mkfifo`, no background job, no temp path. It is single-consumer: the first peer to connect takes the stream,
and a second concurrent reader is refused rather than corrupting the feed with a racing read.

## 5. Give someone a key

Everything so far used `--public`: anyone who reaches the host gets in. The normal way is the opposite. A
service is **gated**, and you hand one person a **key** to it. The key is a `sheer:` link: signed, scoped to
one service, and expiring. It reaches that one service and nothing else on the host.

A node gates every service on a **signet**: the authority whose devices it trusts. For one machine that
vouches for itself, that authority is its own key. Set it once. Run `expose` to see this node's key in the
banner, stop it with ctrl-c, then trust that key:

```sh
tightbeam expose demo=echo:          # prints this node's key in the banner; ctrl-c
echo <your-node-id> > ~/.config/tightbeam/signet
```

Now expose the service gated (no `--public`) and mint a link to it:

```sh
tightbeam expose demo=echo:
tightbeam share demo --expires 2h    # prints: sheer:<node-id>.<token>
```

Send the link to your friend. It carries both your key and the grant, so nothing else is needed:

```sh
echo 'hi from a friend' | tightbeam connect sheer:<node-id>.<token> --service demo --to -
```

Their bytes echo back. The link works only for `demo`, expires on its own after two hours, and reaches
nothing else. Without it, a stranger who dials the host is refused (`service refused: refused`). Revoke a
link early with `tightbeam revoke`; short expiry backs that up. Add `--delegable` to `share` if the holder
may narrow the link and hand it on.

This is the one-machine, one-authority form. Running a single authority across several of your own devices,
so any of them can serve and be reached by name, is what [swoosh](https://github.com/theia-hq/swoosh) is for.

## Anything with a local address

Once a service is gated and you can hand out a key (step 5), the same two commands reach anything that
listens on a TCP port or a Unix socket. Expose it on the host; bind it to a local port on your machine and
point ordinary tooling at that port.

An sshd, reached with no port-forward and no public IP:

```sh
tightbeam expose ssh=127.0.0.1:22                  # on the host
tightbeam connect <peer> --service ssh --to 2222   # on your machine
ssh -p 2222 you@127.0.0.1
```

A media server (Plex here; Jellyfin is `jellyfin=127.0.0.1:8096`), watched from another machine you own
without opening it to the public internet:

```sh
tightbeam expose plex=127.0.0.1:32400              # on the host
tightbeam connect <peer> --service plex --to 32400 # on your machine
open http://127.0.0.1:32400
```

A database:

```sh
tightbeam expose db=127.0.0.1:5432                 # on the host
tightbeam connect <peer> --service db --to 5432    # on your machine
psql -h 127.0.0.1 -p 5432 -U postgres
```

A Unix socket (the Docker daemon), reached as a local TCP port:

```sh
tightbeam expose docker=unix:/var/run/docker.sock  # on the host
tightbeam connect <peer> --service docker --to 2375 # on your machine
DOCKER_HOST=tcp://127.0.0.1:2375 docker ps
```

Or stream a directory as it packs, with no port at all, using the stdout pipe from step 2:

```sh
tar -cf - ~/project | tightbeam expose bundle=stdin:  # on the host
tightbeam connect <peer> --service bundle --to - | tar -xf -   # on your machine
```

Each `<peer>` is a raw node id (with a key you were handed via `share`) or a `sheer:` link that carries the
key and the grant together.
