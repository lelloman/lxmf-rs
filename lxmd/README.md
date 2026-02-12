# lxmd - LXMF Propagation Daemon

`lxmd` is a propagation daemon for the LXMF (LoRa eXtended Messaging Format) protocol.

## Logging

By default, `lxmd` initializes `env_logger` with configurable log levels.

### Log Levels

The log level can be controlled via:
- The `loglevel` configuration file setting (0-7)
- Command-line flags: `--verbose` and `--quiet`

| Level | Description |
|-------|-------------|
| 0-1   | Error only |
| 2-3   | Warning and above |
| 4     | Info and above (default) |
| 5-6   | Debug and above |
| 7     | Trace (most verbose) |

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
