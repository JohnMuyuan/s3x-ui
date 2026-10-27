# sbcore

The sing-box sidecar of S3X-UI. It serves the protocols Xray-core lacks
(AnyTLS, Hysteria, Hysteria2, TUIC, Naive, ShadowTLS, Snell) and is driven by
the panel over a loopback HTTP API guarded by a bearer token (`SBCORE_TOKEN`).

It is a separate Go module because sing-box and xray-core pin incompatible
versions of shared dependencies (quic-go, utls).

## API

All routes need `Authorization: Bearer $SBCORE_TOKEN` and answer
`{"success": bool, "msg": string, "obj": any}`.

| Route | Body | Effect |
|---|---|---|
| `GET /status` | – | `{"running": bool}` |
| `POST /start` | full sing-box config | replaces the running instance |
| `POST /stop` | – | stops the instance |
| `POST /inbound/add` | sing-box inbound | adds it live |
| `POST /inbound/del` | `{"tag"}` | removes it and closes its sessions |
| `POST /inbound/users` | sing-box inbound | swaps its users live; `{"hot": false}` means re-add instead |
| `POST /stats` | – | drains per-user / per-inbound traffic counters |
| `GET /sessions` | – | live sessions with user and source address |
| `POST /kick` | `{"user"}` | closes every session of that user |

## Build

    ./build.sh amd64    # or arm64

`scripts/smoke_test.py` drives real client traffic through every protocol on a
Linux box and checks stats, hot user swaps, runtime inbound changes and kicks.

## Credits

`core/` is adapted from [s-ui](https://github.com/alireza0/s-ui) by alireza0
(GPL-3.0, see `LICENSE.s-ui`): the box, runtime inbound manager, per-user
protocol wrappers and session tracker.
