# lxmd - LXMF Propagation Daemon

`lxmd` is a Rust port of the upstream Python `lxmd` from LXMF 1.3: it runs an
LXMF delivery destination and, optionally, an LXMF Propagation Node, and it can
query and control a running propagation node.

## Configuration

The config directory is `--config` when given; otherwise `/etc/lxmd` or
`~/.config/lxmd` when that directory contains a `config` file, else `~/.lxmd`.
A default `config` (the same text `lxmd --exampleconfig` prints, identical to
upstream's) is written when none exists.

Files in the config directory:

| Path | Purpose |
|------|---------|
| `config` | Daemon configuration (ConfigObj/INI syntax) |
| `identity` | Primary identity; created only when the file does not exist. An unreadable or invalid identity file aborts startup (exit 4) and is never replaced |
| `ignored` | Source destination hashes to ignore, one per line |
| `allowed` | Identity hashes allowed to download messages when `auth_required = yes` |
| `storage/` | Router storage (message store, peers, ...) |
| `storage/messages/` | Received messages |
| `logfile` | Log output when running with `-s/--service` (rotated to `logfile.1` past 5 MiB) |

Kilobyte limits are passed to the router in whole kilobytes; fractional values
are rounded up so the 0.38 KB minimum never becomes 0.

## Received messages

Each received message is written atomically (temporary file, fsync, rename) to
`storage/messages/<message hash>` as upstream's `LXMessage.packed_container()`:
a msgpack map with `state`, `lxmf_bytes`, `transport_encrypted`,
`transport_encryption` and `method`.

> `lxmf_bytes` is currently written as nil: the router's `LxmDelivery` does not
> expose the raw packed message yet.

When `on_inbound` (or `-i/--on-inbound`) is set, lxmd runs it like upstream,
splitting `<command> "<message path>"` with shell-style quoting, so commands
with arguments work (`on_inbound = /usr/local/bin/handler --flag`).

## Remote control

`--status`, `--peers`, `--sync HASH` and `-b/--break HASH` query or control a
propagation node over its `lxmf.propagation.control` destination, identifying
with the identity from `--identity PATH` or `<config dir>/identity` (which must
already exist; nothing is created in this mode). Without `-r` the node is the
local one; `-r HASH` takes any destination hash of the remote node and resolves
its identity (requesting a path if needed). Only the node's own identity and
the identities in `control_allowed` are allowed.

Default timeouts are 5 s for `--status`/`--peers` and 10 s for `--sync` and
`--break` (override with `--timeout`). Output and exit codes follow upstream:

| Exit code | Meaning |
|-----------|---------|
| 0 | Success |
| 200 | Timed out |
| 201 | Config directory does not exist |
| 202 | Identity file not found |
| 203 | Remote received no identity, or an invalid hash was given |
| 204 | Access denied |
| 205 | Invalid data received by remote |
| 206 | The requested peer was not found |
| 207 | Empty response received |
| 4 | Identity file could not be loaded |

## Logging

`loglevel` in the `[logging]` section uses Reticulum's levels (0 critical to
8 extreme) and defaults to 3 (notice) when unset; each `-v` raises and each
`-q` lowers it. Levels map to the `log` crate as in `rns-net`: 0-1 error,
2 warning, 3-4 info, 5-7 debug, 8 trace. Remote control commands always start
from level 3. With `-s/--service`, logs go to `<config dir>/logfile`.

### Using a Custom Logger

To use your own logger implementation, disable the default logger initialization:

```toml
[dependencies]
lxmd = { version = "x.y", default-features = false, features = [] }
```

Then initialize your logger before calling lxmd functions:

```rust
// Example: Android logcat
android_logger::init_once(android_logger::Config::default().with_tag("lxmd"));

// Example: Custom logger
struct MyLogger;
impl log::Log for MyLogger { ... }
log::set_logger(&MyLogger).unwrap();
log::set_max_level(log::LevelFilter::Info);
```

### Platform-Specific Loggers

#### Android

For Android platforms, you can use the built-in Android logger feature:

```toml
[dependencies]
lxmd = { version = "x.y", default-features = false, features = ["android-logger"] }
```

This automatically uses `android_logger` for logcat integration when running on Android.

## Features

- `init-logger` (default): Initialize `env_logger` on startup
- `android-logger`: Use Android's logcat for logging (Android only)
