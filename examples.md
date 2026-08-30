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
port. Whatever you write on one end comes out the other. Expose a named pipe (FIFO) on the host and read
it from your machine:

```sh
# on the host: create a FIFO, expose a reader of it, then feed it
mkfifo /tmp/beam
tightbeam expose pipe=127.0.0.1:9000 &
# feed the FIFO into the exposed port (any process that writes to the port works)
nc -l 127.0.0.1 9000 < /tmp/beam &
echo "hello from the host" > /tmp/beam
```

```sh
# on your machine: read the stream straight to your terminal
tightbeam connect <peer> --service pipe --stdio
```

For a file transfer, pair `tar` on both ends. The host streams a directory; you unpack it as it
arrives:

```sh
# on the host: expose a listener that streams a tarball of a directory
tightbeam expose bundle=127.0.0.1:9001 &
nc -l 127.0.0.1 9001 < <(tar -cf - ~/project) &
```

```sh
# on your machine: pull the stream and unpack it in place
tightbeam connect <peer> --service bundle --stdio | tar -xf -
```

`--stdio` is the same shape ssh uses for its `ProxyCommand` (see the README). It makes tightbeam a
transport for anything that reads stdin and writes stdout.

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
