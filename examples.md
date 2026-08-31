# What you can run over it

A forward carries bytes. Anything that speaks over a TCP port or a Unix socket runs over it unchanged:
the program on each end does not know the overlay is there. Below are worked examples. Each shows the
host's one line, the other machine's one line, and what happens.

Two facts hold for every example:

- `connect` binds a plain `127.0.0.1:<port>` on your machine. You point any local client at that port.
- A service is reachable only by a peer that holds the host's key and passes its gate (its signet by
  default, or a `sheer:` link). `--public` opens it to anyone; that is the only opt-out.

`<peer>` is the host's node id, printed in the `serve` readiness banner, or a `sheer:` link from
`tightbeam share`.

## Stream a file by key

The host has a file. You want it on another machine, with no public IP, no copy, and no HTTP server to
stand up. Serve the file's bytes directly:

```sh
tightbeam expose movie=file:/srv/films/big.mkv     # on the host
```

```sh
tightbeam connect <peer> --service movie --stdio | mpv -    # on your machine
```

`file:<path>` streams the file's raw bytes toward the peer, so there is no port to bind, no `cat`, and
no background process. It is a read-only source: it refuses block/char devices (`/dev/zero`,
`/dev/urandom`), directories, and a symlink at the named path.

## A live feed to a player on the other side

The host has a camera or a screen you want to watch live elsewhere. A live feed has a producer that must
keep running while the stream is served, so this one has a background step (the producer) that the
static-file case does not.

`fifo:<path>` serves a named pipe: whatever a producer writes into the pipe streams to the peer. Point
the producer at the pipe, serve the pipe, and read it on the far side:

```sh
# on the host: make a pipe, serve it, then capture the camera into it
# (device name varies by OS: /dev/video0 on Linux, "0" with -f avfoundation on macOS)
mkfifo /tmp/cam
tightbeam expose cam=fifo:/tmp/cam &
ffmpeg -i /dev/video0 -f mpegts /tmp/cam
```

```sh
# on your machine: read the stream straight into a player
tightbeam connect <peer> --service cam --stdio | mpv -    # or: vlc -
```

The live feed reaches you addressed by the host's key and gated to your signet, with no port-forward and
no camera vendor in the path.

> Streaming a *command's* own stdout directly (`serve cam=exec:'ffmpeg -i /dev/video0 -f mpegts -'`, with
> no pipe to make and no background producer) needs an `exec:` scheme. Spawning a process on the host is a
> materially bigger blast radius than opening a file, so it is a separate, held item pending its own
> design. When it lands, the live case collapses to one line too.

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

Pipe `tar` into a served pipe and unpack it on the far side as it arrives:

```sh
# on the host: make a pipe, serve it, then pack the directory into it
mkfifo /tmp/bundle
tightbeam expose bundle=fifo:/tmp/bundle &
tar -cf /tmp/bundle ~/project
```

```sh
# on your machine: pull the stream and unpack it in place
tightbeam connect <peer> --service bundle --stdio | tar -xf -
```

`--stdio` pipes one service stream against this process's own stdin and stdout instead of binding a port,
so tightbeam becomes a transport for anything that reads stdin and writes stdout. It is the same shape
ssh uses for its `ProxyCommand` (see the README).

## Anything with a local address is reachable by key

A database port or a Unix socket. One `serve` and one `connect` each.

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
