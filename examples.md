# What you can run over it

A forward carries bytes. Anything that speaks over a TCP port or a Unix socket runs over it unchanged:
the program on each end does not know the overlay is there. Below are worked examples. Each shows the
host's one line, the other machine's one line, and what happens.

Two facts hold for every example:

- `connect` binds a plain `127.0.0.1:<port>` on your machine. You point any local client at that port.
- A service is reachable only by a peer that holds the host's key and passes its gate (its signet by
  default, or a `sheer:` link). `--public` opens a FORWARD (`host:port`/`unix:`) to anyone, the one gate
  opt-out; a raw-stream source (`file:`/`fifo:`/`stdin:`) can not be made public, it has no auth of its own,
  so it stays gated. So the file and live-feed examples below reach only a peer that holds your key.

`<peer>` is the host's node id, printed in the `expose` readiness banner, or a `sheer:` link from
`tightbeam share`.

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
no background process. It is a read-only source: it refuses block/char devices (`/dev/zero`,
`/dev/urandom`), directories, and a symlink at the named path.

## A live feed to a player on the other side

The host has a camera or a screen you want to watch live elsewhere. Pipe the producer straight into
`expose` and read it on the far side:

```sh
# on the host: capture the camera and pipe it into expose
# (device name varies by OS: /dev/video0 on Linux, "0" with -f avfoundation on macOS)
ffmpeg -i /dev/video0 -f mpegts - | tightbeam expose cam=stdin:
```

```sh
# on your machine: read the stream straight into a player
tightbeam connect <peer> --service cam --to - | mpv -    # or: vlc -
```

`stdin:` serves whatever a producer pipes into `expose`, so the whole live case is one pipe: no `mkfifo`,
no background job, no temp path to clean up. It works the same on Linux, macOS, and Windows (it reads this
process's own standard input). It is **single-consumer**: standard input is one stream, so the first peer
to reach it takes it, and a second concurrent connection is refused cleanly rather than corrupting the
feed with a racing second read.

The live feed reaches you addressed by the host's key and gated to your signet, with no port-forward and
no camera vendor in the path.

> `fifo:<path>` is the alternative when you want several producers or several serially-reconnecting readers
> over one named pipe on disk; `stdin:` is the one-shot pipe. Streaming a *command's* own stdout with the
> host doing the spawning (`expose cam=exec:'ffmpeg ...'`) would need an `exec:` scheme, but with `stdin:`
> the caller already spawns the command and pipes it in, so `exec:` stays parked: spawning a process on the
> host is a materially bigger blast radius, and the pipe covers the case.

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
