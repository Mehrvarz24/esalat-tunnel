# esalat-tunnel

A minimal, dependency-free tunnel between an **Iran** box and an **abroad** box.
One static Go binary, one port, no third-party runtime, no telemetry.

```
users ──► iran:440 (client) ══TLS══► abroad:440 (server) ──► 127.0.0.1:8443
                                                             (VLESS/Reality, any service)
```

Clients point at the **Iran IP + port**. The abroad IP never appears in a client
configuration and nothing is exposed on the abroad box except the tunnel port.

* single ~1.2k-line Go program, standard library only
* own multiplexer (no smux/yamux) with real per-stream flow control
* `tls` and `ws` (websocket-upgrade, looks like ordinary `wss://`) transports
* **decoy fallback**: probes and port scanners get a real website, not a dead port
* token auth with constant-time compare, never logged
* certificate pinning (SPKI) with a certificate that survives restarts
* `-allow` target allow-list, so the server can never be used as an open relay
* hardened systemd units, `StateDirectory`, no root-only paths
* host tuning helper: BBR, fq, socket buffers, fd limits, DNS sanity check

## Quick start

**The same one-liner runs on both boxes** — the menu asks which side this machine
is (that is the only difference), and any port works; 440 in these examples is
just a habit:

```bash
# on each machine (abroad first, then iran)
curl -fsSL https://raw.githubusercontent.com/Mehrvarz24/esalat-tunnel/main/esalat.sh | sudo bash
#   menu → 1) install → which side is this box? [abroad/iran]
#     abroad: protocol, port (any free port — 443, 8443, 2053, ...), decoys
#             → prints the token and the server pin
#     iran  : abroad IP, the same port, the same token, the pin, target, sessions
```

Prefer a different port? Answer the `tunnel port` prompt, or pass it up front:

```bash
# abroad box
curl -fsSL .../esalat.sh | sudo bash -s install abroad --transport ws --port 8443 --tune
# iran box
curl -fsSL .../esalat.sh | sudo bash -s install iran --server 203.0.113.10 \
     --transport ws --port 8443 --listen :8443 --target 127.0.0.1:8443 \
     --token <token> --pin <pin> --tune
```

The port is simply the number both ends agree on; it only has to be free on each
box. Clients connect to the **Iran IP with that port**.

Other commands:

```bash
esalat.sh status                 # services + live stats
esalat.sh tune                   # BBR/fq/buffers/dns
esalat.sh pin                    # this box's certificate pin
esalat.sh uninstall              # stop + remove units, keep config
esalat.sh uninstall --purge      # remove everything
```

## Options

Server (`easalt server`):

| flag | default | meaning |
|---|---|---|
| `-listen` | `:440` | tunnel port |
| `-token` | — | shared secret (required) |
| `-transport` | `tls` | `tls` \| `ws` \| `tcp` (tcp = plaintext, testing only) |
| `-ws-path` | `/ws` | upgrade path when `-transport ws` |
| `-allow` | `127.0.0.1` | target prefixes the client may reach (open-relay guard) |
| `-decoy` | `www.cloudflare.com:80` | plain-HTTP decoy for probes |
| `-decoy-tls` | `www.cloudflare.com:443` | decoy for probes that already spoke TLS |
| `-sni` | `www.microsoft.com` | certificate name(s) |
| `-cert-dir` | `/var/lib/esalat` | where the certificate is kept (stable pin) |
| `-stats` | `127.0.0.1:9101` | JSON stats listener |

Client (`easalt client`):

| flag | default | meaning |
|---|---|---|
| `-server` | — | abroad host/IP (required) |
| `-link-port` | `440` | tunnel port on the abroad box |
| `-listen` | `:440` | where users connect on this box |
| `-target` | `127.0.0.1:8443` | service to reach on the abroad box |
| `-sessions` | `4` | parallel connections to abroad (~1.2 Gbit/s each) |
| `-pin` | — | expected server SPKI pin (recommended) |
| `-transport` / `-ws-path` / `-sni` | as above | |
| `-stats` | `127.0.0.1:9100` | JSON stats listener |

## Protocol

```
TCP → TLS → AUTH ("ET1" + token + random padding)
frames: type(1) flags(1) streamID(4) length(4), little endian
  1 OPEN (payload = target)   2 DATA   3 FIN   4 CREDIT   5 PING   6 PONG   9 AUTH
```

* each direction of a stream starts with 1 MiB of credit; the receiver grants
  more after the bytes reach the local socket → a slow stream cannot stall the
  shared connection
* a keepalive ping every 10 s; a missing pong retires the session and the pool
  dials a fresh one
* non-TLS traffic on the server port is proxied to the decoy host (over TLS for
  probes that already completed a TLS handshake)

## Measured

Single host, two local fake nodes, 2 vCPU:

| test | result |
|---|---|
| 20 MB transfers (tls / ws / tcp) | bit-identical to the source, all three |
| 24 parallel users | 24 × HTTP 200, one unique hash |
| raw throughput | 4.4 Gbit/s (1 user) → ~5 Gbit/s aggregate (4 sessions) |
| same host without the tunnel | 38.6 Gbit/s |
| wrong token / wrong pin | connection refused, nothing served |
| non-TLS probe on the tunnel port | decoy website answers |
| abroad server killed | users fail in ~2.4 s, recover ~4 s after it returns |
| hardened systemd | identical results, pin stable across restarts |

Per-session throughput is CPU-bound (~1.2 Gbit/s per core); raise `-sessions` to
scale on real links.

## Build

```bash
go build -o easalt .                    # linux/amd64, no external modules
GOARCH=arm64 go build -o easalt-arm64 .
make release                            # tarballs in dist/
```

## Security notes

* the token is a shared secret: keep `/etc/easalt/*.env` at 0600 and rotate it
  with `esalat.sh` (menu option 4) if it ever leaks
* pin the certificate (`-pin`) — otherwise a MITM that can intercept the link
  could impersonate the server
* `-allow 127.0.0.1` is deliberate: the tunnel reaches local services only
* nothing is logged beyond connection errors; payloads are never written to disk

## فارسی

تانل اختصاصی: یک باینری، صفر وابستگی. سمت ایران کلاینت است و فقط از داخل به
بیرون وصل می‌شود؛ سمت خارج سرور. کاربران به **IP ایران + پورت** وصل می‌شوند و
IP سرور خارج هیچ‌وقت در کانفیگ کسی نمی‌آید. توضیح کامل فارسی در
[`README-fa.md`](README-fa.md).

## License

MIT — see [LICENSE](LICENSE).
