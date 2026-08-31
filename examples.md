# What you can run over it

A tunnel carries bytes. Anything that speaks over a TCP port or a Unix socket runs over it unchanged:
the program on each end does not know the overlay is there. Below are worked examples. Each shows the
host's one line, the other machine's one line, and what happens.

Two facts hold for every example:

- `connect` binds a plain `127.0.0.1:<port>` on your machine. You point any local client at that port.
- A service is reachable only by a peer that holds the host's key and passes its gate (its signet by
  default, or a `sheer:` link). `--public` opens it to anyone; that is the only opt-out.

`<peer>` is the host's node id, printed in the `expose` readiness banner, or a `sheer:` link from
`tightbeam share`.

## Watch a movie over your key

The host has a video file. You want to watch it from another machine, with no public IP and no file
copy.

Serve the file over HTTP on the host, expose that port, then play the local port on your machine.

```sh
# on the host: serve the folder with the movie, then expose the server
python3 -m http.server 8000 --directory ~/Videos &
tightbeam expose media=127.0.0.1:8000
```

```sh
# on your machine: bind the media server to a local port, then play from it
tightbeam connect <peer> --service media --to 8000
mpv http://127.0.0.1:8000/film.mkv        # or: vlc, ffplay, or a browser
```

The player streams the file over the overlay as it plays, seeking and all. The bytes are addressed to
the host's key, gated, and never touch a public IP or a port-forward.

Music is the same shape: point the exposed port at a music server (for example `mopidy` or a plain
folder of files) and open it with any client.

## Your whole media server over your key

The host runs Plex or Jellyfin. You want the whole library on another machine you own, without opening
the server to the public internet.

Expose the server's port on the host, bind it to a local port on your machine, then open the web UI
there.

```sh
# on the host: expose the running media server (Plex 32400, Jellyfin 8096)
tightbeam expose plex=127.0.0.1:32400        # Jellyfin: jellyfin=127.0.0.1:8096
```

```sh
# on your machine: bind it to a local port, then open the web UI or a client
tightbeam connect <peer> --service plex --to 32400
open http://127.0.0.1:32400                  # or point a Plex/Jellyfin app at it
```

Your whole library streams to any machine you own, addressed by key and gated to your signet. There is
no port-forward and the server never faces the public internet.

## A live webcam to VLC on the other side

The host has a camera. You want the live feed on another machine, with no cloud camera vendor in the
middle.

Have `ffmpeg` serve the camera on a TCP port, expose it, then open the local port in a player.

```sh
# on the host: capture the camera and serve it on a TCP port (device name varies by OS:
# /dev/video0 on Linux, "0" with -f avfoundation on macOS)
ffmpeg -i /dev/video0 -f mpegts "tcp://127.0.0.1:9002?listen" &
tightbeam expose cam=127.0.0.1:9002
```

```sh
# on your machine: bind it to a local port, then open that port in a player
tightbeam connect <peer> --service cam --to 9002
vlc tcp://127.0.0.1:9002                      # or: mpv tcp://127.0.0.1:9002
```

The live feed reaches you addressed by the host's key and gated to your signet, with no port-forward
and no camera service in the path.

## Pipe a raw stream: stdin to stdout across the overlay

`--stdio` pipes one service stream against this process's own stdin and stdout instead of binding a
port. Whatever you write on one end comes out the other. On the serve side, `file:<path>` and
`fifo:<path>` are its mirror: instead of a port, `expose` names a path whose bytes it sources to the peer
(the reverse of `connect --stdio`). Expose a named pipe (FIFO) on the host and read it from your machine:

```sh
# on the host: create a FIFO and expose it directly -- no bound port, no listener in the loop
mkfifo /tmp/beam
tightbeam expose pipe=fifo:/tmp/beam &
echo "hello from the host" > /tmp/beam
```

```sh
# on your machine: read the stream straight to your terminal
tightbeam connect <peer> --service pipe --stdio
```

`fifo:` opens the pipe (blocking until a writer appears, bounded by a timeout) and streams its bytes;
`file:<path>` does the same for a regular file, so `expose iso=file:/srv/big.iso` serves a file's bytes
with no `cat` and no port. Both are read-only sources toward the peer: they refuse block/char devices
(`/dev/zero`, `/dev/urandom`), directories, and a symlink at the named path.

For a file transfer, feed a FIFO with `tar` and expose the FIFO. The host streams a directory; you unpack
it as it arrives:

```sh
# on the host: point tar at a FIFO, expose the FIFO -- the peer reads the tarball as tar writes it
mkfifo /tmp/bundle
tightbeam expose bundle=fifo:/tmp/bundle &
tar -cf /tmp/bundle ~/project &
```

```sh
# on your machine: pull the stream and unpack it in place
tightbeam connect <peer> --service bundle --stdio | tar -xf -
```

Streaming a *command's* own stdout directly (`expose feed=exec:'tar -cf - ~/project'`, with no FIFO in
between) needs an `exec:` scheme -- spawning a process on the host is a materially bigger blast radius
than opening a file, so it is a separate, held item pending its own design, not part of `file:`/`fifo:`.

`--stdio` is the same shape ssh uses for its `ProxyCommand` (see the README). With `file:`/`fifo:` on the
serve side, tightbeam is a transport for anything that reads stdin and writes stdout, on either end.

## Anything with a local address is reachable by key

A database port, a Unix socket, a URL fetch. One `expose` and one `connect` each.

A Postgres server on the host, reached with `psql` from your machine:

```sh
tightbeam expose db=127.0.0.1:5432                 # on the host
tightbeam connect <peer> --service db --to 5432    # on your machine
psql -h 127.0.0.1 -p 5432 -U postgres
```

A Unix socket (here the Docker daemon) exposed as a TCP port you can point tooling at:

```sh
tightbeam expose docker=unix:/var/run/docker.sock          # on the host
tightbeam connect <peer> --service docker --to 2375        # on your machine
DOCKER_HOST=tcp://127.0.0.1:2375 docker ps
```

A URL fetched by the host and streamed back to you (GET/HEAD only, scoped to the URL asked for, TLS
terminating at the host, not an open proxy):

```sh
tightbeam expose fetch=fetch:                    # on the host
swoosh fetch https://example.com/big.iso --via <peer>   # on your machine, prints a local URL to pull
```
