use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::{env, fs, thread, time};

use lxmf_core::constants::*;
use lxmf_core::stamp::StampCost;
use lxmf_rs::router::{LxmDelivery, LxmRouter, LxmfCallbacks, RouterConfig};
use rns_core::destination::destination_hash;
use rns_core::msgpack::{self, Value};
use rns_core::types::{DestHash, LinkId, PacketHash};
use rns_crypto::identity::Identity;
use rns_crypto::Rng;
use rns_net::driver::Callbacks;
use rns_net::{Event, RnsNode};
use unicode_general_category::{get_general_category, GeneralCategory};
use unicode_normalization::UnicodeNormalization;

const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Delay before the deferred start jobs run (`DEFFERED_JOBS_DELAY`).
const DEFERRED_JOBS_DELAY: f64 = 10.0;
/// Interval of the lxmd announce job loop (`JOBS_INTERVAL`).
const JOBS_INTERVAL: f64 = 5.0;
/// Default log level when the config sets none (RNS `LOG_NOTICE`).
const DEFAULT_LOGLEVEL: u8 = 3;
/// Default remote request timeouts, in seconds.
const STATUS_TIMEOUT: f64 = 5.0;
const PEER_REQUEST_TIMEOUT: f64 = 10.0;
/// Timeout for resolving the remote identity (`_get_target_identity`).
const TARGET_IDENTITY_TIMEOUT: f64 = 5.0;
/// `RNS.Transport.PATHFINDER_M`: hop count reported for unknown paths.
const PATHFINDER_M: u64 = 128;
/// `RNS.LOG_MAXSIZE`: the log file is rotated once it grows past this.
const LOG_MAXSIZE: u64 = 5 * 1024 * 1024;
/// `LXMessage.GENERATING`, the state of an inbound message.
const MESSAGE_STATE_GENERATING: u64 = 0x00;

// Remote control exit codes.
const EXIT_TIMEOUT: i32 = 200;
const EXIT_NO_CONFIGDIR: i32 = 201;
const EXIT_NO_IDENTITY_FILE: i32 = 202;
const EXIT_NO_IDENTITY: i32 = 203;
const EXIT_NO_ACCESS: i32 = 204;
const EXIT_INVALID_DATA: i32 = 205;
const EXIT_NOT_FOUND: i32 = 206;
const EXIT_EMPTY_RESPONSE: i32 = 207;
// Identity exit codes.
const EXIT_IDENTITY_UNREADABLE: i32 = 4;
const EXIT_IDENTITY_NOT_CREATED: i32 = 2;

// ============================================================
// CLI argument parsing
// ============================================================

#[derive(Default)]
struct Args {
    config: Option<String>,
    rnsconfig: Option<String>,
    propagation_node: bool,
    on_inbound: Option<String>,
    verbose: u32,
    quiet: u32,
    service: bool,
    status: bool,
    peers: bool,
    sync: Option<String>,
    unpeer: Option<String>,
    timeout: Option<f64>,
    remote: Option<String>,
    identity: Option<String>,
    ready_file: Option<String>,
    exampleconfig: bool,
}

fn parse_args() -> Args {
    let args: Vec<String> = env::args().collect();
    let mut parsed = Args::default();
    let mut i = 1;

    while i < args.len() {
        match args[i].as_str() {
            "--config" => {
                i += 1;
                parsed.config = args.get(i).cloned();
            }
            "--rnsconfig" => {
                i += 1;
                parsed.rnsconfig = args.get(i).cloned();
            }
            "-p" | "--propagation-node" => parsed.propagation_node = true,
            "-i" | "--on-inbound" => {
                i += 1;
                parsed.on_inbound = args.get(i).cloned();
            }
            "-v" | "--verbose" => parsed.verbose += 1,
            "-q" | "--quiet" => parsed.quiet += 1,
            // Combined counted flags, as argparse accepts them (`-vvv`).
            flags
                if flags.len() > 2
                    && flags.starts_with('-')
                    && flags[1..].chars().all(|c| c == 'v' || c == 'q') =>
            {
                for flag in flags[1..].chars() {
                    if flag == 'v' {
                        parsed.verbose += 1;
                    } else {
                        parsed.quiet += 1;
                    }
                }
            }
            "-s" | "--service" => parsed.service = true,
            "--status" => parsed.status = true,
            "--peers" => parsed.peers = true,
            "--sync" => {
                i += 1;
                parsed.sync = args.get(i).cloned();
            }
            "-b" | "--break" => {
                i += 1;
                parsed.unpeer = args.get(i).cloned();
            }
            "--timeout" => {
                i += 1;
                match args.get(i).and_then(|s| s.parse::<f64>().ok()) {
                    Some(timeout) => parsed.timeout = Some(timeout),
                    None => {
                        eprintln!("lxmd: error: argument --timeout: invalid float value");
                        process::exit(2);
                    }
                }
            }
            "-r" | "--remote" => {
                i += 1;
                parsed.remote = args.get(i).cloned();
            }
            "--identity" => {
                i += 1;
                parsed.identity = args.get(i).cloned();
            }
            "--ready-file" => {
                i += 1;
                parsed.ready_file = args.get(i).cloned();
            }
            "--exampleconfig" => parsed.exampleconfig = true,
            "--version" => {
                println!("lxmd {}", VERSION);
                process::exit(0);
            }
            "-h" | "--help" => {
                print_help();
                process::exit(0);
            }
            other => {
                eprintln!("lxmd: error: unrecognized arguments: {}", other);
                process::exit(2);
            }
        }
        i += 1;
    }

    parsed
}

fn print_help() {
    println!("lxmd - Lightweight Extensible Messaging Daemon");
    println!();
    println!("Usage: lxmd [OPTIONS]");
    println!();
    println!("Options:");
    println!("  --config PATH          path to alternative lxmd config directory");
    println!("  --rnsconfig PATH       path to alternative Reticulum config directory");
    println!("  -p, --propagation-node run an LXMF Propagation Node");
    println!("  -i, --on-inbound PATH  executable to run when a message is received");
    println!("  -v, --verbose");
    println!("  -q, --quiet");
    println!("  -s, --service          lxmd is running as a service and should log to file");
    println!("  --status               display node status");
    println!("  --peers                display peered nodes");
    println!("  --sync SYNC            request a sync with the specified peer");
    println!("  -b, --break UNPEER     break peering with the specified peer");
    println!("  --timeout TIMEOUT      timeout in seconds for query operations");
    println!("  -r, --remote REMOTE    remote propagation node destination hash");
    println!("  --identity IDENTITY    path to identity used for remote requests");
    println!("  --ready-file PATH      write readiness marker after successful startup");
    println!("  --exampleconfig        print verbose configuration example to stdout and exit");
    println!("  --version              show program's version number and exit");
    println!("  -h, --help             show this help message and exit");
}

// ============================================================
// Configuration
// ============================================================

#[derive(Clone)]
pub struct LxmdConfig {
    // [lxmf]
    pub display_name: String,
    pub announce_at_start: bool,
    /// Delivery announce interval in seconds.
    pub announce_interval: Option<u64>,
    pub peer_stamp_cost: f64,
    pub delivery_transfer_max_accepted_size: f64,
    pub on_inbound: Option<String>,

    // [propagation]
    pub enable_node: bool,
    pub node_name: Option<String>,
    pub auth_required: bool,
    pub pn_announce_at_start: bool,
    pub autopeer: bool,
    pub autopeer_maxdepth: Option<u8>,
    pub sequential_pn_stamp_validation: bool,
    pub static_peers_bypass_sequential: bool,
    pub max_inbound_syncs: usize,
    /// Propagation node announce interval in seconds.
    pub pn_announce_interval: Option<u64>,
    pub message_storage_limit: f64,
    pub propagation_message_max_accepted_size: f64,
    pub propagation_sync_max_accepted_size: f64,
    pub propagation_stamp_cost_target: f64,
    pub propagation_stamp_cost_flexibility: f64,
    /// Throttle period for peers delivering invalid stamps, in seconds.
    pub propagation_stamp_throttle: f64,
    pub peering_cost: f64,
    pub remote_peering_cost_max: f64,
    pub prioritise_destinations: Vec<[u8; 16]>,
    pub control_allowed: Vec<[u8; 16]>,
    pub static_peers: Vec<[u8; 16]>,
    pub max_peers: Option<usize>,
    pub from_static_only: bool,

    // [logging]
    /// Configured RNS log level; `None` when unset (defaults to 3).
    pub loglevel: Option<u8>,
}

impl Default for LxmdConfig {
    fn default() -> Self {
        Self {
            display_name: "Anonymous Peer".to_string(),
            announce_at_start: false,
            announce_interval: None,
            peer_stamp_cost: 12.0,
            delivery_transfer_max_accepted_size: 1.0,
            on_inbound: None,

            enable_node: false,
            node_name: None,
            auth_required: false,
            pn_announce_at_start: false,
            autopeer: true,
            autopeer_maxdepth: None,
            sequential_pn_stamp_validation: true,
            static_peers_bypass_sequential: true,
            max_inbound_syncs: MAX_INBOUND_SYNCS,
            pn_announce_interval: None,
            message_storage_limit: 500.0,
            propagation_message_max_accepted_size: 256.0,
            propagation_sync_max_accepted_size: 256.0 * 40.0,
            propagation_stamp_cost_target: PROPAGATION_COST.as_f64(),
            propagation_stamp_cost_flexibility: PROPAGATION_COST_FLEX.as_f64(),
            propagation_stamp_throttle: PN_STAMP_THROTTLE as f64,
            peering_cost: PEERING_COST.as_f64(),
            remote_peering_cost_max: MAX_PEERING_COST.as_f64(),
            prioritise_destinations: Vec::new(),
            control_allowed: Vec::new(),
            static_peers: Vec::new(),
            max_peers: None,
            from_static_only: false,

            loglevel: None,
        }
    }
}

/// Strip a ConfigObj value: quoted values lose their quotes, and an
/// unquoted value ends at an inline `#` comment.
fn config_value(raw: &str) -> String {
    let raw = raw.trim();
    for quote in ['"', '\''] {
        if let Some(rest) = raw.strip_prefix(quote) {
            if let Some(end) = rest.find(quote) {
                return rest[..end].to_string();
            }
        }
    }
    match raw.find('#') {
        Some(comment) => raw[..comment].trim().to_string(),
        None => raw.to_string(),
    }
}

/// Parse a simple INI config file into section -> key -> value.
fn parse_ini(content: &str) -> HashMap<String, HashMap<String, String>> {
    let mut sections: HashMap<String, HashMap<String, String>> = HashMap::new();
    let mut current_section = String::new();

    for line in content.lines() {
        let line = line.trim();

        // Skip comments and empty lines
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }

        if line.starts_with('[') && line.ends_with(']') {
            current_section = line[1..line.len() - 1].trim().to_lowercase();
            sections.entry(current_section.clone()).or_default();
        } else if let Some((key, value)) = line.split_once('=') {
            let key = key.trim().to_lowercase();
            sections
                .entry(current_section.clone())
                .or_default()
                .insert(key, config_value(value));
        }
    }

    sections
}

/// Parse a float config value (ConfigObj `as_float`).
fn parse_float(s: &str) -> Option<f64> {
    s.trim().parse::<f64>().ok().filter(|v| v.is_finite())
}

fn parse_bool(s: &str) -> bool {
    matches!(s.to_lowercase().as_str(), "yes" | "true" | "1" | "on")
}

fn parse_hex_list(s: &str) -> Vec<[u8; 16]> {
    s.split(',').filter_map(parse_hex_hash).collect()
}

fn apply_config(ini: &HashMap<String, HashMap<String, String>>, config: &mut LxmdConfig) {
    if let Some(lxmf) = ini.get("lxmf") {
        if let Some(v) = lxmf.get("display_name") {
            config.display_name = v.clone();
        }
        if let Some(v) = lxmf.get("announce_at_start") {
            config.announce_at_start = parse_bool(v);
        }
        if let Some(v) = lxmf.get("announce_interval") {
            if let Ok(mins) = v.parse::<u64>() {
                config.announce_interval = Some(mins * 60);
            }
        }
        if let Some(v) = lxmf.get("stamp_cost") {
            if let Some(cost) = parse_float(v) {
                config.peer_stamp_cost = cost.max(1.0);
            }
        }
        if let Some(v) = lxmf.get("delivery_transfer_max_accepted_size") {
            if let Some(kb) = parse_float(v) {
                config.delivery_transfer_max_accepted_size = kb.max(0.38);
            }
        }
        if let Some(v) = lxmf.get("on_inbound") {
            config.on_inbound = Some(v.clone());
        }
    }

    if let Some(prop) = ini.get("propagation") {
        if let Some(v) = prop.get("enable_node") {
            config.enable_node = parse_bool(v);
        }
        if let Some(v) = prop.get("node_name") {
            config.node_name = Some(v.clone());
        }
        if let Some(v) = prop.get("auth_required") {
            config.auth_required = parse_bool(v);
        }
        if let Some(v) = prop.get("announce_at_start") {
            config.pn_announce_at_start = parse_bool(v);
        }
        if let Some(v) = prop.get("autopeer") {
            config.autopeer = parse_bool(v);
        }
        if let Some(v) = prop.get("autopeer_maxdepth") {
            if let Ok(n) = v.parse() {
                config.autopeer_maxdepth = Some(n);
            }
        }
        if let Some(v) = prop.get("sequential_pn_stamp_validation") {
            config.sequential_pn_stamp_validation = parse_bool(v);
        }
        if let Some(v) = prop.get("static_peers_bypass_sequential") {
            config.static_peers_bypass_sequential = parse_bool(v);
        }
        if let Some(v) = prop.get("max_inbound_syncs") {
            if let Ok(n) = v.parse::<usize>() {
                config.max_inbound_syncs = n.max(1);
            }
        }
        if let Some(v) = prop.get("announce_interval") {
            if let Ok(mins) = v.parse::<u64>() {
                config.pn_announce_interval = Some(mins * 60);
            }
        }
        if let Some(v) = prop.get("message_storage_limit") {
            if let Some(mb) = parse_float(v) {
                config.message_storage_limit = mb.max(0.005);
            }
        }
        // Upstream reads `propagation_transfer_max_accepted_size` but then
        // unconditionally overwrites it from (or with the default of)
        // `propagation_message_max_accepted_size`, so only the latter counts.
        if let Some(v) = prop.get("propagation_message_max_accepted_size") {
            if let Some(kb) = parse_float(v) {
                config.propagation_message_max_accepted_size = kb.max(0.38);
            }
        }
        if let Some(v) = prop.get("propagation_sync_max_accepted_size") {
            if let Some(kb) = parse_float(v) {
                config.propagation_sync_max_accepted_size = kb.max(0.38);
            }
        }
        if let Some(v) = prop.get("propagation_stamp_cost_target") {
            if let Some(n) = parse_float(v) {
                config.propagation_stamp_cost_target = n.max(PROPAGATION_COST_MIN.as_f64());
            }
        }
        if let Some(v) = prop.get("propagation_stamp_cost_flexibility") {
            if let Some(n) = parse_float(v) {
                config.propagation_stamp_cost_flexibility = n.max(0.0);
            }
        }
        if let Some(v) = prop.get("propagation_stamp_throttle") {
            if let Some(minutes) = parse_float(v) {
                config.propagation_stamp_throttle = (minutes * 60.0).max(PN_STAMP_THROTTLE as f64);
            }
        }
        if let Some(v) = prop.get("peering_cost") {
            if let Some(n) = parse_float(v) {
                config.peering_cost = n.max(0.0);
            }
        }
        if let Some(v) = prop.get("remote_peering_cost_max") {
            if let Some(n) = parse_float(v) {
                config.remote_peering_cost_max = n.max(0.0);
            }
        }
        if let Some(v) = prop.get("prioritise_destinations") {
            config.prioritise_destinations = parse_hex_list(v);
        }
        if let Some(v) = prop.get("control_allowed") {
            config.control_allowed = parse_hex_list(v);
        }
        if let Some(v) = prop.get("static_peers") {
            config.static_peers = parse_hex_list(v);
        }
        if let Some(v) = prop.get("max_peers") {
            if let Ok(n) = v.parse() {
                config.max_peers = Some(n);
            }
        }
        if let Some(v) = prop.get("from_static_only") {
            config.from_static_only = parse_bool(v);
        }
    }

    if let Some(log) = ini.get("logging") {
        if let Some(v) = log.get("loglevel") {
            if let Ok(n) = v.parse::<i64>() {
                config.loglevel = Some(n.clamp(0, i64::from(rns_net::logging::LOG_EXTREME)) as u8);
            }
        }
    }
}

/// The RNS log level lxmd runs at: the configured level (3 when unset)
/// adjusted by `-v`/`-q`.
fn effective_loglevel(configured: Option<u8>, verbose: u32, quiet: u32) -> u8 {
    rns_net::logging::adjust_log_level(
        configured.unwrap_or(DEFAULT_LOGLEVEL),
        verbose.min(u32::from(u8::MAX)) as u8,
        quiet.min(u32::from(u8::MAX)) as u8,
    )
}

// ============================================================
// Directory and path setup
// ============================================================

struct LxmdPaths {
    configpath: PathBuf,
    identitypath: PathBuf,
    storagepath: PathBuf,
    messagedir: PathBuf,
    ignoredpath: PathBuf,
    allowedpath: PathBuf,
    logfile: PathBuf,
}

impl LxmdPaths {
    fn new(configdir: PathBuf) -> Self {
        let storagepath = configdir.join("storage");
        Self {
            configpath: configdir.join("config"),
            identitypath: configdir.join("identity"),
            ignoredpath: configdir.join("ignored"),
            allowedpath: configdir.join("allowed"),
            logfile: configdir.join("logfile"),
            messagedir: storagepath.join("messages"),
            storagepath,
        }
    }
}

fn home_dir() -> PathBuf {
    PathBuf::from(env::var("HOME").unwrap_or_else(|_| ".".to_string()))
}

/// Pick the config directory as upstream does: `/etc/lxmd` or
/// `~/.config/lxmd` only when they contain a `config` file, else `~/.lxmd`.
fn detect_configdir(config_override: Option<&str>, etc_dir: &Path, home: &Path) -> PathBuf {
    if let Some(dir) = config_override {
        return PathBuf::from(dir);
    }
    let xdg_dir = home.join(".config").join("lxmd");
    if etc_dir.is_dir() && etc_dir.join("config").is_file() {
        etc_dir.to_path_buf()
    } else if xdg_dir.is_dir() && xdg_dir.join("config").is_file() {
        xdg_dir
    } else {
        home.join(".lxmd")
    }
}

fn configdir_for(config_override: Option<&str>) -> PathBuf {
    detect_configdir(config_override, Path::new("/etc/lxmd"), &home_dir())
}

// ============================================================
// Identity management
// ============================================================

/// Load an identity file. `Ok(None)` when no file exists; an existing file
/// that cannot be read or is not a valid identity is an error and is never
/// replaced.
fn load_identity_file(path: &Path) -> Result<Option<Identity>, String> {
    if !path.is_file() {
        return Ok(None);
    }
    let data = fs::read(path).map_err(|e| e.to_string())?;
    let key: [u8; 64] = data
        .as_slice()
        .try_into()
        .map_err(|_| format!("invalid identity length {}", data.len()))?;
    Ok(Some(Identity::from_private_key(&key)))
}

/// Create and save a new identity.
fn create_identity_file(path: &Path) -> Result<Identity, String> {
    let identity = Identity::new(&mut rns_crypto::OsRng);
    let prv = identity
        .get_private_key()
        .ok_or_else(|| "new identity has no private key".to_string())?;
    fs::write(path, prv).map_err(|e| e.to_string())?;
    Ok(identity)
}

/// Load the primary identity, creating it only when no file exists; exits
/// with upstream's codes otherwise.
fn load_or_create_primary_identity(path: &Path) -> Identity {
    match load_identity_file(path) {
        Ok(Some(identity)) => {
            log::info!(
                "Loaded Primary Identity {}",
                identity_display(identity.hash())
            );
            identity
        }
        Ok(None) => {
            log::info!("No Primary Identity file found, creating new...");
            match create_identity_file(path) {
                Ok(identity) => {
                    log::info!(
                        "Created new Primary Identity {}",
                        identity_display(identity.hash())
                    );
                    identity
                }
                Err(e) => {
                    log::error!("Could not create and save a new Primary Identity");
                    log::error!("The contained exception was: {}", e);
                    process::exit(EXIT_IDENTITY_NOT_CREATED);
                }
            }
        }
        Err(e) => {
            log::error!(
                "Could not load the Primary Identity from {}",
                path.display()
            );
            log::error!("The contained exception was: {}", e);
            process::exit(EXIT_IDENTITY_UNREADABLE);
        }
    }
}

/// `str(RNS.Identity)`: the identity hash as `prettyhexrep`.
fn identity_display(hash: &[u8]) -> String {
    prettyhexrep(hash)
}

/// Load hex destination hashes from a file (one per line).
fn load_hash_file(path: &Path) -> Vec<[u8; 16]> {
    let content = match fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };

    content.lines().filter_map(parse_hex_hash).collect()
}

fn write_ready_file(path: &Path) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| {
            format!(
                "failed to create ready-file parent {}: {}",
                parent.display(),
                e
            )
        })?;
    }
    fs::write(path, format!("pid={}\n", process::id()))
        .map_err(|e| format!("failed to write ready-file {}: {}", path.display(), e))
}

// ============================================================
// Inbound messages
// ============================================================

/// `LXMessage.packed_container`: the msgpack container upstream writes for
/// a received message.
fn packed_container(
    lxmf_bytes: Option<&[u8]>,
    transport_encrypted: bool,
    transport_encryption: Option<&str>,
    method: u8,
) -> Vec<u8> {
    let s = |key: &str| Value::Str(key.to_string());
    msgpack::pack(&Value::Map(vec![
        (s("state"), Value::UInt(MESSAGE_STATE_GENERATING)),
        (
            s("lxmf_bytes"),
            lxmf_bytes.map_or(Value::Nil, |bytes| Value::Bin(bytes.to_vec())),
        ),
        (s("transport_encrypted"), Value::Bool(transport_encrypted)),
        (
            s("transport_encryption"),
            transport_encryption.map_or(Value::Nil, |e| Value::Str(e.to_string())),
        ),
        (s("method"), Value::UInt(u64::from(method))),
    ]))
}

/// `LXMessage.write_to_directory`: write the container atomically to
/// `<directory>/<message hash hex>` (temporary file, fsync, rename).
fn write_to_directory(
    directory: &Path,
    message_hash: &[u8],
    container: &[u8],
) -> Result<PathBuf, String> {
    let file_path = directory.join(hexrep(message_hash));
    let mut nonce = [0u8; 8];
    rns_crypto::OsRng.fill_bytes(&mut nonce);
    let mut tmp_name = file_path.as_os_str().to_owned();
    tmp_name.push(format!(".tmp.{}.{}", process::id(), hexrep(&nonce)));
    let tmp_path = PathBuf::from(tmp_name);

    let write = || -> std::io::Result<()> {
        let mut file = fs::File::create(&tmp_path)?;
        file.write_all(container)?;
        file.flush()?;
        if let Err(e) = file.sync_all() {
            log::warn!("Error while waiting for persist fsync for message: {}", e);
        }
        fs::rename(&tmp_path, &file_path)
    };

    write().map(|()| file_path.clone()).map_err(|e| {
        let _ = fs::remove_file(&tmp_path);
        format!(
            "Error while writing LXMF message to file \"{}\". The contained exception was: {}",
            file_path.display(),
            e
        )
    })
}

/// `shlex.split` (POSIX mode, no comments).
fn shlex_split(input: &str) -> Result<Vec<String>, String> {
    let mut tokens = Vec::new();
    let mut token = String::new();
    let mut in_token = false;
    let mut chars = input.chars();

    while let Some(c) = chars.next() {
        match c {
            ' ' | '\t' | '\r' | '\n' => {
                if in_token {
                    tokens.push(std::mem::take(&mut token));
                    in_token = false;
                }
            }
            '\\' => {
                token.push(chars.next().ok_or("No escaped character")?);
                in_token = true;
            }
            '\'' => {
                in_token = true;
                loop {
                    match chars.next() {
                        Some('\'') => break,
                        Some(c) => token.push(c),
                        None => return Err("No closing quotation".to_string()),
                    }
                }
            }
            '"' => {
                in_token = true;
                loop {
                    match chars.next() {
                        Some('"') => break,
                        Some('\\') => match chars.next() {
                            Some(c @ ('"' | '\\')) => token.push(c),
                            Some(c) => {
                                token.push('\\');
                                token.push(c);
                            }
                            None => return Err("No escaped character".to_string()),
                        },
                        Some(c) => token.push(c),
                        None => return Err("No closing quotation".to_string()),
                    }
                }
            }
            c => {
                token.push(c);
                in_token = true;
            }
        }
    }
    if in_token {
        tokens.push(token);
    }
    Ok(tokens)
}

/// The argument vector upstream runs for `on_inbound`:
/// `shlex.split(command + ' "' + path + '"')`.
fn on_inbound_argv(command: &str, path: &Path) -> Result<Vec<String>, String> {
    let argv = shlex_split(&format!("{} \"{}\"", command, path.display()))?;
    if argv.is_empty() {
        return Err("empty on_inbound command".to_string());
    }
    Ok(argv)
}

fn run_on_inbound(command: &str, path: &Path) -> Result<(), String> {
    let argv = on_inbound_argv(command, path)?;
    process::Command::new(&argv[0])
        .args(&argv[1..])
        .stdout(process::Stdio::null())
        .stderr(process::Stdio::null())
        .status()
        .map(|_| ())
        .map_err(|e| e.to_string())
}

/// `lxmf_delivery` in lxmd: write the message to the message directory and
/// run the `on_inbound` program on it.
fn handle_inbound_message(message_dir: &Path, on_inbound: Option<&str>, delivery: &LxmDelivery) {
    let message = format!("<LXMessage {}>", hexrep(&delivery.message_hash));
    let container = packed_container(
        Some(&delivery.lxmf_bytes),
        delivery.transport_encrypted,
        delivery
            .transport_encrypted
            .then_some(delivery.transport_encryption.as_str()),
        delivery.method as u8,
    );
    let written_path = match write_to_directory(message_dir, &delivery.message_hash, &container) {
        Ok(path) => path,
        Err(e) => {
            log::error!("{}", e);
            log::error!(
                "Error occurred while processing received message {}. The contained exception was: no file was written",
                message
            );
            return;
        }
    };
    log::debug!("Received {} written to {}", message, written_path.display());

    match on_inbound {
        Some(command) if !command.is_empty() => {
            log::debug!("Calling external program to handle message");
            if let Err(e) = run_on_inbound(command, &written_path) {
                log::error!(
                    "Error occurred while processing received message {}. The contained exception was: {}",
                    message,
                    e
                );
            }
        }
        _ => log::debug!("No action defined for inbound messages, ignoring"),
    }
}

// ============================================================
// RNS formatting helpers
// ============================================================

/// `RNS.hexrep(data, delimit=False)`.
fn hexrep(data: &[u8]) -> String {
    data.iter().map(|b| format!("{:02x}", b)).collect()
}

/// `RNS.prettyhexrep`.
fn prettyhexrep(data: &[u8]) -> String {
    format!("<{}>", hexrep(data))
}

fn parse_hex_hash(s: &str) -> Option<[u8; 16]> {
    parse_hex_bytes(s.trim()).ok()?.try_into().ok()
}

fn parse_hex_bytes(s: &str) -> Result<Vec<u8>, String> {
    if !s.len().is_multiple_of(2) || !s.is_ascii() {
        return Err("non-hexadecimal number found in fromhex() arg".to_string());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| {
                format!(
                    "non-hexadecimal number found in fromhex() arg at position {}",
                    i
                )
            })
        })
        .collect()
}

/// `bytes.fromhex` plus upstream's destination hash length check.
fn parse_destination_hash(s: &str) -> Result<[u8; 16], String> {
    let bytes = parse_hex_bytes(s)?;
    bytes
        .try_into()
        .map_err(|_| "Destination hash length must be 32 characters".to_string())
}

/// Python's `repr(float)`.
fn py_float(v: f64) -> String {
    if v.is_nan() {
        return "nan".to_string();
    }
    if v.is_infinite() {
        return if v > 0.0 { "inf" } else { "-inf" }.to_string();
    }
    let sci = format!("{:e}", v);
    let (mantissa, exponent) = sci.split_once('e').unwrap_or((&sci, "0"));
    let exponent: i32 = exponent.parse().unwrap_or(0);
    if (-4..16).contains(&exponent) {
        let mut fixed = format!("{}", v);
        if !fixed.contains('.') {
            fixed.push_str(".0");
        }
        fixed
    } else {
        let sign = if exponent < 0 { '-' } else { '+' };
        format!("{}e{}{:02}", mantissa, sign, exponent.abs())
    }
}

/// Python's `round(v, 2)` on a float.
fn py_round2(v: f64) -> f64 {
    format!("{:.2}", v).parse().unwrap_or(v)
}

/// `str()` of a msgpack-decoded value, as Python prints it in f-strings.
fn py_str(v: &Value) -> String {
    match v {
        Value::Nil => "None".to_string(),
        Value::Bool(true) => "True".to_string(),
        Value::Bool(false) => "False".to_string(),
        Value::UInt(n) => n.to_string(),
        Value::Int(n) => n.to_string(),
        Value::Float(f) => py_float(*f),
        Value::Str(s) => s.clone(),
        Value::Bin(b) => String::from_utf8_lossy(b).into_owned(),
        other => format!("{:?}", other),
    }
}

/// Python's `round(v, 2)`, keeping ints as ints.
fn py_round2_str(v: &Value) -> String {
    match v {
        Value::Float(f) => py_float(py_round2(*f)),
        other => py_str(other),
    }
}

/// `RNS.prettysize`.
fn prettysize_suffix(num: f64, suffix: &str) -> String {
    let mut num = num;
    if suffix == "b" {
        num *= 8.0;
    }
    for unit in ["", "K", "M", "G", "T", "P", "E", "Z"] {
        if num.abs() < 1000.0 {
            return if unit.is_empty() {
                format!("{:.0} {}{}", num, unit, suffix)
            } else {
                format!("{:.2} {}{}", num, unit, suffix)
            };
        }
        num /= 1000.0;
    }
    format!("{:.2}Y{}", num, suffix)
}

fn prettysize(num: f64) -> String {
    prettysize_suffix(num, "B")
}

/// `RNS.prettyspeed`.
fn prettyspeed(num: f64) -> String {
    prettysize_suffix(num / 8.0, "b") + "ps"
}

/// `RNS.prettytime(time)` (not verbose, not compact).
fn prettytime(time: f64) -> String {
    let neg = time < 0.0;
    let time = time.abs();
    let days = (time / 86400.0).floor() as u64;
    let time = time % 86400.0;
    let hours = (time / 3600.0).floor() as u64;
    let time = time % 3600.0;
    let minutes = (time / 60.0).floor() as u64;
    let seconds = py_round2(time % 60.0);

    let mut components = Vec::new();
    if days > 0 {
        components.push(format!("{}d", days));
    }
    if hours > 0 {
        components.push(format!("{}h", hours));
    }
    if minutes > 0 {
        components.push(format!("{}m", minutes));
    }
    if seconds > 0.0 {
        components.push(format!("{}s", py_float(seconds)));
    }

    let mut tstr = String::new();
    let count = components.len();
    for (i, component) in components.iter().enumerate() {
        let i = i + 1;
        if i == 1 {
        } else if i < count {
            tstr.push_str(", ");
        } else {
            tstr.push_str(" and ");
        }
        tstr.push_str(component);
    }

    if tstr.is_empty() {
        "0s".to_string()
    } else if neg {
        format!("-{}", tstr)
    } else {
        tstr
    }
}

// ============================================================
// Status and peers output
// ============================================================

/// Characters removed by upstream's `STRIP_*_RE` patterns.
fn stripped_by_upstream_patterns(c: char) -> bool {
    matches!(
        c as u32,
        0x1F600..=0x1F64F
            | 0x1F300..=0x1F5FF
            | 0x1F680..=0x1F6FF
            | 0x1F700..=0x1F77F
            | 0x1F780..=0x1F7FF
            | 0x1F800..=0x1F8FF
            | 0x1F900..=0x1F9FF
            | 0x1FA00..=0x1FA6F
            | 0x1FA70..=0x1FAFF
            | 0x1F1E0..=0x1F1FF
            | 0x2600..=0x26FF
            | 0x2700..=0x27BF
            | 0xFE00..=0xFE0F
            | 0xE0100..=0xE01EF
            | 0x0000..=0x0008
            | 0x000B..=0x000C
            | 0x000E..=0x001F
            | 0x007F..=0x009F
            | 0x200B..=0x200F
            | 0x202A..=0x202E
            | 0x2060..=0x206F
            | 0xFEFF
            | 0xFFF0..=0xFFF8
            | 0xE000..=0xF8FF
            | 0xF900..=0xFAFF
            | 0xFE10..=0xFE2F
            | 0xF0000..=0x10FFFF
    )
}

/// Upstream `sanitize_name`.
fn sanitize_peer_name(name: &str) -> String {
    let filtered: String =
        name.nfkc()
            .filter_map(|character| {
                use GeneralCategory::*;
                match get_general_category(character) {
                    UppercaseLetter | LowercaseLetter | TitlecaseLetter | ModifierLetter
                    | OtherLetter | DecimalNumber | LetterNumber | OtherNumber
                    | ConnectorPunctuation | DashPunctuation | OpenPunctuation
                    | ClosePunctuation | InitialPunctuation | FinalPunctuation
                    | OtherPunctuation | SpacingMark => Some(character),
                    SpaceSeparator | LineSeparator | ParagraphSeparator => Some(' '),
                    _ => None,
                }
            })
            .filter(|c| !stripped_by_upstream_patterns(*c))
            .collect();

    filtered.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn field<'a>(map: &'a Value, key: &str) -> &'a Value {
    const NIL: &Value = &Value::Nil;
    map.map_get(key).unwrap_or(NIL)
}

fn number(v: &Value) -> f64 {
    v.as_number().unwrap_or(0.0)
}

fn integer(v: &Value) -> i64 {
    v.as_integer()
        .or_else(|| v.as_number().map(|n| n as i64))
        .unwrap_or(0)
}

/// Python truthiness of a number-or-None value.
fn truthy(v: &Value) -> bool {
    match v {
        Value::Nil => false,
        Value::Bool(b) => *b,
        other => number(other) != 0.0,
    }
}

/// Upstream `get_status` output for a `compile_stats` response.
fn format_status(s: &Value, show_status: bool, show_peers: bool, now: f64) -> String {
    let mut out = String::new();
    let mut line = |text: String| {
        out.push_str(&text);
        out.push('\n');
    };

    let messagestore = field(s, "messagestore");
    let ms_bytes = number(field(messagestore, "bytes"));
    let ms_limit = number(field(messagestore, "limit"));
    let mutil = if ms_limit != 0.0 {
        py_round2((ms_bytes / ms_limit) * 100.0)
    } else {
        0.0
    };
    let ms_util = format!("{}%", py_float(mutil));
    let who_str = if truthy(field(s, "from_static_only")) {
        "static peers only"
    } else {
        "all nodes"
    };

    let peers: &[(Value, Value)] = field(s, "peers").as_map().unwrap_or(&[]);
    let mut available_peers = 0;
    let mut unreachable_peers = 0;
    let mut peered_incoming = 0;
    let mut peered_outgoing = 0;
    let mut peered_rx_bytes = 0;
    let mut peered_tx_bytes = 0;
    for (_, p) in peers {
        let pm = field(p, "messages");
        peered_incoming += integer(field(pm, "incoming"));
        peered_outgoing += integer(field(pm, "outgoing"));
        peered_rx_bytes += integer(field(p, "rx_bytes"));
        peered_tx_bytes += integer(field(p, "tx_bytes"));
        if truthy(field(p, "alive")) {
            available_peers += 1;
        } else {
            unreachable_peers += 1;
        }
    }

    let clients = field(s, "clients");
    let total_incoming = peered_incoming
        + integer(field(s, "unpeered_propagation_incoming"))
        + integer(field(clients, "client_propagation_messages_received"));
    let total_rx_bytes = peered_rx_bytes + integer(field(s, "unpeered_propagation_rx_bytes"));
    let df = if total_incoming != 0 {
        py_float(py_round2(peered_outgoing as f64 / total_incoming as f64))
    } else {
        "0".to_string()
    };

    let dhs = prettyhexrep(field(s, "destination_hash").as_bin().unwrap_or(&[]));
    let uts = prettytime(number(field(s, "uptime")));
    line(format!(
        "\nLXMF Propagation Node running on {}, uptime is {}",
        dhs, uts
    ));

    if show_status {
        let msb = prettysize(ms_bytes);
        let msl = prettysize(ms_limit);
        let ptl = prettysize(number(field(s, "propagation_limit")) * 1000.0);
        let psl = prettysize(number(field(s, "sync_limit")) * 1000.0);
        let uprx = prettysize(number(field(s, "unpeered_propagation_rx_bytes")));
        let mscnt = py_str(field(messagestore, "count"));
        let stp = py_str(field(s, "total_peers"));
        let smp = py_str(field(s, "max_peers"));
        let sdp = py_str(field(s, "discovered_peers"));
        let ssp = py_str(field(s, "static_peers"));
        let cprr = py_str(field(clients, "client_propagation_messages_received"));
        let cprs = py_str(field(clients, "client_propagation_messages_served"));
        let upi = py_str(field(s, "unpeered_propagation_incoming"));
        let psc = py_str(field(s, "target_stamp_cost"));
        let scf = py_str(field(s, "stamp_cost_flexibility"));
        let pc = py_str(field(s, "peering_cost"));
        let pcm = py_str(field(s, "max_peering_cost"));
        line(format!(
            "Messagestore contains {} messages, {} ({} utilised of {})",
            mscnt, msb, ms_util, msl
        ));
        line(format!(
            "Required propagation stamp cost is {}, flexibility is {}",
            psc, scf
        ));
        line(format!(
            "Peering cost is {}, max remote peering cost is {}",
            pc, pcm
        ));
        line(format!("Accepting propagated messages from {}", who_str));
        line(format!("{} message limit, {} sync limit", ptl, psl));
        line(String::new());
        line(format!("Peers   : {} total (peer limit is {})", stp, smp));
        line(format!("          {} discovered, {} static", sdp, ssp));
        line(format!(
            "          {} available, {} unreachable",
            available_peers, unreachable_peers
        ));
        line(String::new());
        line(format!(
            "Traffic : {} messages received in total ({})",
            total_incoming,
            prettysize(total_rx_bytes as f64)
        ));
        line(format!(
            "          {} messages received from peered nodes ({})",
            peered_incoming,
            prettysize(peered_rx_bytes as f64)
        ));
        line(format!(
            "          {} messages received from unpeered nodes ({})",
            upi, uprx
        ));
        line(format!(
            "          {} messages transferred to peered nodes ({})",
            peered_outgoing,
            prettysize(peered_tx_bytes as f64)
        ));
        line(format!(
            "          {} propagation messages received directly from clients",
            cprr
        ));
        line(format!(
            "          {} propagation messages served to clients",
            cprs
        ));
        line(format!("          Distribution factor is {}", df));
        line(String::new());
    }

    if show_peers {
        if !show_status {
            line(String::new());
        }

        for (peer_id, p) in peers {
            let ind = "  ";
            let t = match field(p, "type").as_str() {
                Some("static") => "Static peer     ",
                Some("discovered") => "Discovered peer ",
                _ => "Unknown peer    ",
            };
            let a = if field(p, "alive").as_bool() == Some(true) {
                "Available"
            } else {
                "Unreachable"
            };
            let h = (now - number(field(p, "last_heard"))).max(0.0);
            let hops_value = field(p, "network_distance");
            let hops = integer(hops_value);
            let hs = if hops == PATHFINDER_M as i64 {
                "hops unknown".to_string()
            } else if hops == 1 {
                format!("{} hop away", py_str(hops_value))
            } else {
                format!("{} hops away", py_str(hops_value))
            };
            let pm = field(p, "messages");
            let unknown_if_none = |v: &Value| {
                if v.is_nil() {
                    "unknown".to_string()
                } else {
                    py_str(v)
                }
            };
            let pc = unknown_if_none(field(p, "peering_cost"));
            let psc = unknown_if_none(field(p, "target_stamp_cost"));
            let psf = unknown_if_none(field(p, "stamp_cost_flexibility"));
            let pk = match field(p, "peering_key") {
                Value::Nil => "Not generated".to_string(),
                value => format!("Generated, value is {}", py_str(value)),
            };
            let lsa = number(field(p, "last_sync_attempt"));
            let ls = if lsa != 0.0 {
                format!("last synced {} ago", prettytime((now - lsa).max(0.0)))
            } else {
                "never synced".to_string()
            };

            let sstr = prettyspeed(number(field(p, "str")));
            let sler = prettyspeed(number(field(p, "ler")));
            let transfer_limit = field(p, "transfer_limit");
            let stl = if truthy(transfer_limit) {
                prettysize(number(transfer_limit) * 1000.0)
            } else {
                "Unknown".to_string()
            };
            let sync_limit = field(p, "sync_limit");
            let ssl = if truthy(sync_limit) {
                prettysize(number(sync_limit) * 1000.0)
            } else {
                "unknown".to_string()
            };
            let srxb = prettysize(number(field(p, "rx_bytes")));
            let stxb = prettysize(number(field(p, "tx_bytes")));
            let pmo = py_str(field(pm, "offered"));
            let pmout = py_str(field(pm, "outgoing"));
            let pmi = py_str(field(pm, "incoming"));
            let pmuh = py_str(field(pm, "unhandled"));
            let ar = match field(p, "acceptance_rate") {
                Value::Float(rate) => py_round2_str(&Value::Float(rate * 100.0)),
                other => (integer(other) * 100).to_string(),
            };
            let nn = match field(p, "name") {
                Value::Nil => String::new(),
                name => sanitize_peer_name(&py_str(name)),
            };
            let nn = if nn.chars().count() > 45 {
                format!("{}...", nn.chars().take(45).collect::<String>())
            } else {
                nn
            };

            line(format!(
                "{}{}{}",
                ind,
                t,
                prettyhexrep(peer_id.as_bin().unwrap_or(&[]))
            ));
            if !nn.is_empty() {
                line(format!("{}Name       : {}", ind.repeat(2), nn));
            }
            line(format!(
                "{}Status     : {}, {}, last heard {} ago",
                ind.repeat(2),
                a,
                hs,
                prettytime(h)
            ));
            line(format!(
                "{}Costs      : Propagation {} (flex {}), peering {}",
                ind.repeat(2),
                psc,
                psf,
                pc
            ));
            line(format!("{}Sync key   : {}", ind.repeat(2), pk));
            line(format!(
                "{}Speeds     : {} STR, {} LER",
                ind.repeat(2),
                sstr,
                sler
            ));
            line(format!(
                "{}Limits     : {} message limit, {} sync limit",
                ind.repeat(2),
                stl,
                ssl
            ));
            line(format!(
                "{}Messages   : {} offered, {} outgoing, {} incoming, {}% acceptance rate",
                ind.repeat(2),
                pmo,
                pmout,
                pmi,
                ar
            ));
            line(format!(
                "{}Traffic    : {} received, {} sent",
                ind.repeat(2),
                srxb,
                stxb
            ));
            let ms = if integer(field(pm, "unhandled")) == 1 {
                ""
            } else {
                "s"
            };
            line(format!(
                "{}Sync state : {} unhandled message{}, {}",
                ind.repeat(2),
                pmuh,
                ms,
                ls
            ));
            line(String::new());
        }
    }

    out
}

// ============================================================
// Remote control client
// ============================================================

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum ControlRequest {
    Status,
    Sync,
    Unpeer,
}

impl ControlRequest {
    fn path(self) -> &'static str {
        match self {
            Self::Status => STATS_GET_PATH,
            Self::Sync => SYNC_REQUEST_PATH,
            Self::Unpeer => UNPEER_REQUEST_PATH,
        }
    }

    fn default_timeout(self) -> f64 {
        match self {
            Self::Status => STATUS_TIMEOUT,
            Self::Sync | Self::Unpeer => PEER_REQUEST_TIMEOUT,
        }
    }

    fn timeout_message(self) -> &'static str {
        match self {
            Self::Status => "Getting lxmd statistics timed out, exiting now",
            Self::Sync => "Requesting lxmd peer sync timed out, exiting now",
            Self::Unpeer => "Requesting lxmd peering break timed out, exiting now",
        }
    }
}

/// The message and exit code for a control response that upstream treats
/// as a failure; `None` when the response is a result.
fn control_failure(request: ControlRequest, response: &Value) -> Option<(&'static str, i32)> {
    if response.is_nil() {
        return Some(("Empty response received", EXIT_EMPTY_RESPONSE));
    }
    let code = match response {
        Value::UInt(code) => u8::try_from(*code).ok().and_then(PeerError::from_u8),
        Value::Int(code) => u8::try_from(*code).ok().and_then(PeerError::from_u8),
        _ => None,
    }?;
    match (code, request) {
        (PeerError::NoIdentity, _) => Some(("Remote received no identity", EXIT_NO_IDENTITY)),
        (PeerError::NoAccess, _) => Some(("Access denied", EXIT_NO_ACCESS)),
        (PeerError::InvalidData, ControlRequest::Sync | ControlRequest::Unpeer) => {
            Some(("Invalid data received by remote", EXIT_INVALID_DATA))
        }
        (PeerError::NotFound, ControlRequest::Sync | ControlRequest::Unpeer) => {
            Some(("The requested peer was not found", EXIT_NOT_FOUND))
        }
        _ => None,
    }
}

/// The message printed for a successful control request.
fn control_success_message(request: ControlRequest, peer: &[u8; 16]) -> String {
    match request {
        ControlRequest::Sync => format!("Sync requested for peer {}", prettyhexrep(peer)),
        ControlRequest::Unpeer => format!("Broke peering with {}", prettyhexrep(peer)),
        ControlRequest::Status => String::new(),
    }
}

enum ControlEvent {
    LinkEstablished([u8; 16]),
    Response([u8; 16], Vec<u8>),
}

struct ControlCallbacks {
    tx: mpsc::Sender<ControlEvent>,
}

impl Callbacks for ControlCallbacks {
    fn on_announce(&mut self, _announced: rns_net::destination::AnnouncedIdentity) {}

    fn on_path_updated(&mut self, _dest_hash: DestHash, _hops: u8) {}

    fn on_local_delivery(&mut self, _dest_hash: DestHash, _raw: Vec<u8>, _packet_hash: PacketHash) {
    }

    fn on_link_established(
        &mut self,
        link_id: LinkId,
        _dest_hash: DestHash,
        _rtt: f64,
        is_initiator: bool,
    ) {
        if is_initiator {
            let _ = self.tx.send(ControlEvent::LinkEstablished(link_id.0));
        }
    }

    fn on_response(&mut self, link_id: LinkId, _request_id: [u8; 16], data: Vec<u8>) {
        let _ = self.tx.send(ControlEvent::Response(link_id.0, data));
    }
}

/// `_remote_init`: load the identity used for remote requests. Nothing is
/// ever created in remote mode.
fn remote_init(args: &Args) -> Identity {
    let identity_path = match args.identity.as_deref() {
        Some(path) => PathBuf::from(path),
        None => {
            let configdir = configdir_for(args.config.as_deref());
            if !configdir.is_dir() {
                log::error!("Specified configuration directory does not exist, exiting now");
                process::exit(EXIT_NO_CONFIGDIR);
            }
            configdir.join("identity")
        }
    };
    if !identity_path.is_file() {
        log::error!("Identity file not found in specified configuration directory, exiting now");
        process::exit(EXIT_NO_IDENTITY_FILE);
    }
    match load_identity_file(&identity_path) {
        Ok(Some(identity)) => identity,
        _ => {
            log::error!(
                "Could not load the Primary Identity from {}",
                identity_path.display()
            );
            process::exit(EXIT_IDENTITY_UNREADABLE);
        }
    }
}

fn sleep_until_next_check(deadline: time::Instant, message: &str) {
    if time::Instant::now() > deadline {
        println!("{}", message);
        process::exit(EXIT_TIMEOUT);
    }
    thread::sleep(time::Duration::from_millis(100));
}

fn deadline_after(seconds: f64) -> time::Instant {
    time::Instant::now() + time::Duration::from_secs_f64(seconds.max(0.0))
}

/// `_get_target_identity`: the public key of the node to control, recalled
/// from any of its destination hashes (requesting a path if needed).
fn get_target_identity(node: &RnsNode, identity: &Identity, remote: Option<&str>) -> [u8; 64] {
    let Some(remote) = remote else {
        return identity
            .get_public_key()
            .expect("identity has a public key");
    };
    let destination = match parse_destination_hash(remote) {
        Ok(hash) => DestHash(hash),
        Err(e) => {
            println!("Invalid remote destination hash: {}", e);
            process::exit(EXIT_NO_IDENTITY);
        }
    };

    let recall = || {
        node.recall_identity(&destination)
            .ok()
            .flatten()
            .map(|announced| announced.public_key)
    };
    if let Some(public_key) = recall() {
        return public_key;
    }
    let deadline = deadline_after(TARGET_IDENTITY_TIMEOUT);
    let timeout_message = "Resolving remote identity timed out, exiting now";
    if !node.has_path(&destination).unwrap_or(false) {
        let _ = node.request_path(&destination);
        while !node.has_path(&destination).unwrap_or(false) {
            sleep_until_next_check(deadline, timeout_message);
        }
    }
    loop {
        if let Some(public_key) = recall() {
            return public_key;
        }
        sleep_until_next_check(deadline, timeout_message);
    }
}

/// Send one request to the remote control destination over an identified
/// link and wait for the response, as upstream's `query_status`,
/// `_request_sync` and `_request_unpeer` do.
fn control_query(
    node: &RnsNode,
    events: &mpsc::Receiver<ControlEvent>,
    identity: &Identity,
    remote_public_key: &[u8; 64],
    request: ControlRequest,
    data: &Value,
    timeout: f64,
) -> Vec<u8> {
    let deadline = deadline_after(timeout);
    let message = request.timeout_message();
    let remote_identity_hash = &rns_crypto::sha256::sha256(remote_public_key)[..16];
    let control_hash = destination_hash(
        APP_NAME,
        &["propagation", "control"],
        Some(remote_identity_hash.try_into().unwrap()),
    );
    let control_dest = DestHash(control_hash);
    log::debug!(
        "Requesting {} from {}",
        request.path(),
        prettyhexrep(&control_hash)
    );

    if !node.has_path(&control_dest).unwrap_or(false) {
        let _ = node.request_path(&control_dest);
        while !node.has_path(&control_dest).unwrap_or(false) {
            sleep_until_next_check(deadline, message);
        }
    }

    log::debug!(
        "Path to {} known, establishing link",
        prettyhexrep(&control_hash)
    );
    let sig_pub: [u8; 32] = remote_public_key[32..].try_into().unwrap();
    let link_id = loop {
        match node.create_link(control_hash, sig_pub) {
            Ok(link_id) => break link_id,
            Err(_) => sleep_until_next_check(deadline, message),
        }
    };

    let wait_for = |want: &dyn Fn(&ControlEvent) -> bool| -> ControlEvent {
        loop {
            match events.recv_timeout(time::Duration::from_millis(100)) {
                Ok(event) if want(&event) => return event,
                Ok(_) | Err(mpsc::RecvTimeoutError::Timeout) => {
                    sleep_until_next_check(deadline, message)
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    sleep_until_next_check(deadline, message)
                }
            }
        }
    };

    wait_for(&|event| matches!(event, ControlEvent::LinkEstablished(id) if *id == link_id));
    log::debug!("Link {} established, identifying", prettyhexrep(&link_id));

    let identity_prv = identity
        .get_private_key()
        .expect("identity has a private key");
    let _ = node.identify_on_link(link_id, identity_prv);
    if node
        .send_request(link_id, request.path(), &msgpack::pack(data))
        .is_err()
    {
        loop {
            sleep_until_next_check(deadline, message);
        }
    }

    let ControlEvent::Response(_, response) =
        wait_for(&|event| matches!(event, ControlEvent::Response(id, _) if *id == link_id))
    else {
        unreachable!("only responses are accepted here");
    };
    let _ = node.teardown_link(link_id);
    response
}

/// Run `--status`/`--peers`, `--sync` or `--break` against a (remote) node.
fn run_remote_control(args: &Args) -> ! {
    let (request, peer) = if args.status || args.peers {
        (ControlRequest::Status, None)
    } else if let Some(target) = args.sync.as_deref().or(args.unpeer.as_deref()) {
        let request = if args.sync.is_some() {
            ControlRequest::Sync
        } else {
            ControlRequest::Unpeer
        };
        match parse_destination_hash(target) {
            Ok(hash) => (request, Some(hash)),
            Err(e) => {
                println!("Invalid peer destination hash: {}", e);
                process::exit(EXIT_NO_IDENTITY);
            }
        }
    } else {
        unreachable!("no remote operation selected");
    };

    let identity = remote_init(args);
    let timeout = args
        .timeout
        .filter(|t| *t != 0.0)
        .unwrap_or_else(|| request.default_timeout());

    let (tx, rx) = mpsc::channel();
    let node = match RnsNode::from_config(
        args.rnsconfig.as_deref().map(Path::new),
        Box::new(ControlCallbacks { tx }),
    ) {
        Ok(node) => node,
        Err(e) => {
            log::error!("Failed to start Reticulum: {}", e);
            process::exit(1);
        }
    };

    let remote_public_key = get_target_identity(&node, &identity, args.remote.as_deref());
    let data = peer.map_or(Value::Nil, |hash| Value::Bin(hash.to_vec()));
    let raw = control_query(
        &node,
        &rx,
        &identity,
        &remote_public_key,
        request,
        &data,
        timeout,
    );
    let response = msgpack::unpack_exact(&raw).unwrap_or(Value::Nil);

    if let Some((message, code)) = control_failure(request, &response) {
        println!("{}", message);
        process::exit(code);
    }
    match peer {
        Some(peer) => println!("{}", control_success_message(request, &peer)),
        None => print!(
            "{}",
            format_status(
                &response,
                args.status,
                args.peers,
                lxmf_rs::router::now_timestamp()
            )
        ),
    }
    let _ = std::io::stdout().flush();
    node.shutdown();
    process::exit(0);
}

// ============================================================
// Logging
// ============================================================

/// Appends to the lxmd log file, rotating it to `<logfile>.1` once it grows
/// past `RNS.LOG_MAXSIZE`, as RNS does for `LOG_FILE`.
struct RotatingLogFile {
    path: PathBuf,
}

impl Write for RotatingLogFile {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let mut file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        file.write_all(buf)?;
        if file.metadata().map(|m| m.len()).unwrap_or(0) > LOG_MAXSIZE {
            let mut previous = self.path.as_os_str().to_owned();
            previous.push(".1");
            let _ = fs::remove_file(&previous);
            let _ = fs::rename(&self.path, &previous);
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[allow(unused_variables)]
fn init_logging(loglevel: u8, logfile: Option<&Path>) {
    let filter = rns_net::logging::numeric_log_filter(loglevel);

    #[cfg(all(feature = "android-logger", target_os = "android"))]
    {
        android_logger::init_once(
            android_logger::Config::default()
                .with_max_level(filter.default)
                .with_tag("lxmd"),
        );
    }

    #[cfg(all(
        feature = "init-logger",
        not(all(feature = "android-logger", target_os = "android"))
    ))]
    {
        let mut logger = env_logger::Builder::new();
        logger
            .filter_level(filter.default)
            .filter_module(rns_net::logging::PATHING_LOG_TARGET, filter.pathing);
        match logfile {
            Some(path) => {
                logger.target(env_logger::Target::Pipe(Box::new(RotatingLogFile {
                    path: path.to_path_buf(),
                })));
            }
            None => {
                logger.target(env_logger::Target::Stdout);
            }
        }
        // A logger may already be installed by an embedding application.
        let _ = logger.try_init();
    }
}

// ============================================================
// Daemon
// ============================================================

fn build_router_config(config: &LxmdConfig, paths: &LxmdPaths) -> RouterConfig {
    RouterConfig {
        storagepath: paths.storagepath.clone(),
        autopeer: config.autopeer,
        autopeer_maxdepth: config.autopeer_maxdepth.unwrap_or(AUTOPEER_MAXDEPTH),
        propagation_limit: config.propagation_message_max_accepted_size,
        delivery_limit: config.delivery_transfer_max_accepted_size,
        sync_limit: config.propagation_sync_max_accepted_size,
        enforce_ratchets: false,
        enforce_stamps: false,
        static_peers: config.static_peers.clone(),
        max_peers: config.max_peers.unwrap_or(MAX_PEERS),
        from_static_only: config.from_static_only,
        sync_strategy: DEFAULT_SYNC_STRATEGY,
        propagation_cost: StampCost::from_f64(config.propagation_stamp_cost_target),
        propagation_cost_flexibility: StampCost::from_f64(
            config.propagation_stamp_cost_flexibility,
        ),
        peering_cost: StampCost::from_f64(config.peering_cost),
        max_peering_cost: StampCost::from_f64(config.remote_peering_cost_max),
        max_inbound_syncs: config.max_inbound_syncs,
        sequential_validation: config.sequential_pn_stamp_validation,
        static_sequential: !config.static_peers_bypass_sequential,
        name: config.node_name.clone(),
        pn_stamp_throttle: config.propagation_stamp_throttle,
        message_storage_limit: Some((config.message_storage_limit * 1_000_000.0) as usize),
    }
}

/// `message_router.announce_propagation_node()`. The router waits
/// `NODE_ANNOUNCE_DELAY` itself and announces the control destination too
/// when other identities may control the node.
fn announce_propagation_node(router: &Mutex<LxmRouter>) {
    if let Ok(router) = router.lock() {
        router.announce_propagation_node();
    }
}

/// Sleep in short steps; false once the daemon is shutting down.
fn sleep_while_running(running: &AtomicBool, seconds: f64) -> bool {
    let deadline = deadline_after(seconds);
    while time::Instant::now() < deadline {
        if !running.load(Ordering::Relaxed) {
            return false;
        }
        thread::sleep(time::Duration::from_millis(100));
    }
    running.load(Ordering::Relaxed)
}

/// Whether an interval announce is due (`time.time() > last + interval`).
fn announce_due(now: f64, last: f64, interval: Option<u64>) -> bool {
    interval.is_some_and(|interval| now > last + interval as f64)
}

/// `deferred_start_jobs` followed by the `jobs` announce loop.
fn spawn_announce_jobs(
    running: Arc<AtomicBool>,
    router: Arc<Mutex<LxmRouter>>,
    delivery_identity: Identity,
    config: &LxmdConfig,
) -> thread::JoinHandle<()> {
    let peer_announce_at_start = config.announce_at_start;
    let node_announce_at_start = config.pn_announce_at_start;
    let peer_interval = config.announce_interval;
    let node_interval = config.pn_announce_interval;
    let propagation_enabled = config.enable_node;

    thread::spawn(move || {
        if !sleep_while_running(&running, DEFERRED_JOBS_DELAY) {
            return;
        }
        log::debug!("Running deferred start jobs");
        if peer_announce_at_start {
            log::trace!("Sending announce for LXMF delivery destination");
            if let Ok(router) = router.lock() {
                router.announce_delivery(&delivery_identity);
            }
        }
        if node_announce_at_start && propagation_enabled {
            log::trace!("Sending announce for LXMF Propagation Node");
            announce_propagation_node(&router);
        }

        let mut last_peer_announce = lxmf_rs::router::now_timestamp();
        let mut last_node_announce = last_peer_announce;
        while running.load(Ordering::Relaxed) {
            let now = lxmf_rs::router::now_timestamp();
            if announce_due(now, last_peer_announce, peer_interval) {
                log::debug!("Sending announce for LXMF delivery destination");
                if let Ok(router) = router.lock() {
                    router.announce_delivery(&delivery_identity);
                }
                last_peer_announce = lxmf_rs::router::now_timestamp();
            }
            if propagation_enabled && announce_due(now, last_node_announce, node_interval) {
                log::debug!("Sending announce for LXMF Propagation Node");
                announce_propagation_node(&router);
                last_node_announce = lxmf_rs::router::now_timestamp();
            }
            if !sleep_while_running(&running, JOBS_INTERVAL) {
                break;
            }
        }
    })
}

fn main() {
    let args = parse_args();

    if args.exampleconfig {
        println!("{}", EXAMPLE_CONFIG);
        return;
    }

    if args.status || args.peers || args.sync.is_some() || args.unpeer.is_some() {
        // Remote mode never reads the lxmd config; the level is 3 adjusted
        // by -v/-q.
        init_logging(effective_loglevel(None, args.verbose, args.quiet), None);
        run_remote_control(&args);
    }

    run_daemon(&args);
}

fn run_daemon(args: &Args) {
    let paths = LxmdPaths::new(configdir_for(args.config.as_deref()));
    let dirs_created = fs::create_dir_all(&paths.messagedir);

    let mut created_default_config = false;
    let mut config_error = None;
    if !paths.configpath.is_file() {
        created_default_config = fs::write(&paths.configpath, EXAMPLE_CONFIG).is_ok();
    }
    let mut config = LxmdConfig::default();
    match fs::read_to_string(&paths.configpath) {
        Ok(content) => apply_config(&parse_ini(&content), &mut config),
        Err(e) => config_error = Some(e),
    }

    // CLI flags take precedence over the config file.
    if args.propagation_node {
        config.enable_node = true;
    }
    if args.on_inbound.is_some() {
        config.on_inbound = args.on_inbound.clone();
    }

    let loglevel = effective_loglevel(config.loglevel, args.verbose, args.quiet);
    init_logging(loglevel, args.service.then_some(paths.logfile.as_path()));

    if let Err(e) = dirs_created {
        log::error!(
            "Could not create storage directory {}: {}",
            paths.messagedir.display(),
            e
        );
        process::exit(1);
    }
    if created_default_config {
        log::info!("Could not load config file, creating default configuration file...");
        log::info!(
            "Default config file created. Make any necessary changes in {} and restart lxmd if needed.",
            paths.configpath.display()
        );
    }
    if let Some(e) = config_error {
        log::error!(
            "Could not parse the configuration at {}",
            paths.configpath.display()
        );
        log::error!("Check your configuration file for errors! ({})", e);
        process::exit(255);
    }
    log::debug!("Configuration loaded from {}", paths.configpath.display());

    let identity = load_or_create_primary_identity(&paths.identitypath);
    let identity_prv = identity
        .get_private_key()
        .expect("Identity must include private key");

    let ignored = load_hash_file(&paths.ignoredpath);
    let allowed = load_hash_file(&paths.allowedpath);

    let router_config = build_router_config(&config, &paths);
    let mut router = LxmRouter::new(Identity::from_private_key(&identity_prv), router_config);
    router.ignored_list = ignored;

    if config.auth_required {
        router.auth_required = true;
        if allowed.is_empty() {
            log::warn!(
                "Clint authentication was enabled, but no identity hashes could be loaded from {}. Nobody will be able to sync messages from this propagation node.",
                paths.allowedpath.display()
            );
        }
        router.allowed_list = allowed;
    }

    let message_dir = paths.messagedir.clone();
    let on_inbound = config.on_inbound.clone();
    router.set_delivery_callback(Box::new(move |delivery| {
        handle_inbound_message(&message_dir, on_inbound.as_deref(), delivery);
    }));

    let router = Arc::new(Mutex::new(router));
    let node = match RnsNode::from_config(
        args.rnsconfig.as_deref().map(Path::new),
        Box::new(LxmfCallbacks::new(router.clone())),
    ) {
        Ok(n) => Arc::new(n),
        Err(e) => {
            log::error!("Failed to start Reticulum: {}", e);
            process::exit(1);
        }
    };

    {
        let mut router_guard = router.lock().unwrap();
        router_guard.set_node(node.clone());
        router_guard.register_delivery_identity(
            &identity,
            Some(config.peer_stamp_cost),
            Some(config.display_name.clone()),
        );
        if let Some(delivery_hash) = router_guard.delivery_dest_hash {
            log::info!(
                "LXMF Router ready to receive on {}",
                prettyhexrep(&delivery_hash)
            );
        }

        if config.enable_node {
            router_guard.prioritised_list = config.prioritise_destinations.clone();
            router_guard.enable_propagation();
            for hash in &config.control_allowed {
                if !router_guard.control_allowed_list.contains(hash) {
                    router_guard.control_allowed_list.push(*hash);
                }
            }
            if let Err(error) =
                LxmRouter::register_propagation_request_handlers(&node, router.clone())
            {
                log::error!("Failed to register LXMF propagation handlers: {:?}", error);
                process::exit(1);
            }
            log::info!(
                "LXMF Propagation Node started on {}",
                prettyhexrep(&router_guard.propagation_dest_hash)
            );
        }
    }

    log::info!("Started lxmd version {}", VERSION);

    if let Some(path) = args.ready_file.as_deref() {
        if let Err(e) = write_ready_file(Path::new(path)) {
            log::error!("{}", e);
            process::exit(1);
        }
    }

    let running = Arc::new(AtomicBool::new(true));
    if let Err(e) = setup_signal_handler(running.clone()) {
        log::warn!("Failed to setup signal handler: {}", e);
    }

    let announcer = spawn_announce_jobs(
        running.clone(),
        router.clone(),
        Identity::from_private_key(&identity_prv),
        &config,
    );

    let jobs_running = running.clone();
    let jobs_router = router.clone();
    let worker = thread::spawn(move || {
        let mut last_jobs = lxmf_rs::router::now_timestamp();
        while jobs_running.load(Ordering::Relaxed) {
            let now = lxmf_rs::router::now_timestamp();
            if now - last_jobs >= PROCESSING_INTERVAL as f64 {
                if let Ok(mut guard) = jobs_router.lock() {
                    guard.jobs();
                }
                last_jobs = now;
            }
            thread::sleep(time::Duration::from_millis(200));
        }
    });

    while running.load(Ordering::Relaxed) {
        thread::sleep(time::Duration::from_secs(1));
    }

    log::info!("Shutting down...");

    let _ = worker.join();
    let _ = announcer.join();

    if let Ok(mut guard) = router.lock() {
        guard.exit_handler();
    }

    match Arc::try_unwrap(node) {
        Ok(node) => node.shutdown(),
        Err(node) => {
            let _ = node.event_sender().send(Event::Shutdown);
        }
    }
}

fn setup_signal_handler(running: Arc<AtomicBool>) -> Result<(), String> {
    static SIGNAL_RECEIVED: AtomicBool = AtomicBool::new(false);

    #[cfg(unix)]
    {
        extern "C" {
            fn signal(sig: i32, handler: extern "C" fn(i32)) -> usize;
        }

        extern "C" fn handler(_sig: i32) {
            SIGNAL_RECEIVED.store(true, Ordering::Relaxed);
        }

        unsafe {
            signal(2, handler); // SIGINT
            signal(15, handler); // SIGTERM
        }
    }

    // Spawn a thread to propagate the signal to the running flag
    thread::spawn(move || {
        while !SIGNAL_RECEIVED.load(Ordering::Relaxed) {
            thread::sleep(time::Duration::from_millis(100));
        }
        running.store(false, Ordering::Relaxed);
    });

    Ok(())
}

// ============================================================
// Example config
// ============================================================

/// Upstream's `__default_lxmd_config__`, verbatim.
const EXAMPLE_CONFIG: &str = r#"# This is an example LXM Daemon config file.
# You should probably edit it to suit your
# intended usage.

[propagation]

# Whether to enable propagation node

enable_node = no

# You can specify identity hashes for remotes
# that are allowed to control and query status
# for this propagation node.

# control_allowed = 7d7e542829b40f32364499b27438dba8, 437229f8e29598b2282b88bad5e44698

# An optional name for this node, included
# in announces.

# node_name = Anonymous Propagation Node

# Automatic announce interval in minutes.
# 6 hours by default.

announce_interval = 360

# Whether to announce when the node starts.

announce_at_start = yes

# Wheter to automatically peer with other
# propagation nodes on the network.

autopeer = yes

# The maximum peering depth (in hops) for
# automatically peered nodes.

autopeer_maxdepth = 6

# The maximum amount of storage to use for
# the LXMF Propagation Node message store,
# specified in megabytes. When this limit
# is reached, LXMF will periodically remove
# messages in its message store. By default,
# LXMF prioritises keeping messages that are
# new and small. Large and old messages will
# be removed first. This setting is optional
# and defaults to 500 megabytes.

# message_storage_limit = 500

# The maximum accepted transfer size per in-
# coming propagation message, in kilobytes.
# This sets the upper limit for the size of
# single messages accepted onto this node.

# propagation_message_max_accepted_size = 256

# The maximum accepted transfer size per in-
# coming propagation node sync.
#
# If a node wants to propagate a larger number
# of messages to this node, than what can fit
# within this limit, it will prioritise sending
# the smallest messages first, and try again
# with any remaining messages at a later point.

# propagation_sync_max_accepted_size = 10240

# You can configure the target stamp cost
# required to deliver messages via this node.

# propagation_stamp_cost_target = 16.0

# If set higher than 0, the stamp cost flexi-
# bility option will make this node accept
# messages with a lower stamp cost than the
# target from other propagation nodes (but
# not from peers directly). This allows the
# network to gradually adjust stamp cost.

# propagation_stamp_cost_flexibility = 3.0

# If a peer delivers messages with stamp costs
# not conforming to this node's targets, it'll
# be throttled, by default for 5 minutes. You
# can configure the throttle period, and for
# constrained nodes, it may be a good idea to
# set a much higher throttle time. Real LXMF
# propagation nodes will never deliver messages
# with lower stamp values than required by the
# receiving node.

# propagation_stamp_throttle = 5

# The peering_cost option configures the target
# value required for a remote node to peer with
# and deliver messages to this node.

# peering_cost = 18.0

# You can configure the maximum peering cost
# of remote nodes that this node will peer with.
# Setting this to a higher number will allow
# this node to peer with other nodes requiring
# a higher peering key value, but will require
# more computation time during initial peering
# when generating the peering key.

# remote_peering_cost_max = 26.0

# You can tell the LXMF message router to
# prioritise storage for one or more
# destinations. If the message store reaches
# the specified limit, LXMF will prioritise
# keeping messages for destinations specified
# with this option. This setting is optional,
# and generally you do not need to use it.

# prioritise_destinations = 41d20c727598a3fbbdf9106133a3a0ed, d924b81822ca24e68e2effea99bcb8cf

# You can configure the maximum number of other
# propagation nodes that this node will peer
# with automatically. The default is 20.

# max_peers = 20

# You can configure a list of static propagation
# node peers, that this node will always be
# peered with, by specifying a list of
# destination hashes.

# static_peers = e17f833c4ddf8890dd3a79a6fea8161d, 5a2d0029b6e5ec87020abaea0d746da4

# You can configure the propagation node to
# only accept incoming propagation messages
# from configured static peers.

# from_static_only = True

# By default, stamp validation jobs for PN
# sync batches will run sequentially. If
# a peer offers messages while another batch
# is already processing, it will receive a
# throttle response to indicate that it can
# retry later. If you have a fast system, you
# can disable this to accept and validate
# everything as soon as it is offered.

# sequential_pn_stamp_validation = yes

# You can configure whether static peers are
# allowed have their PN syncs processed as
# soon as they are offered, regardless of
# whether another batch is already validating.

# static_peers_bypass_sequential = yes

# You can configure how many concurrent inbound
# propagation sync transfers will be accepted.
# Once this number is reached, nodes offering
# messages will receive a throttle response to
# indicate that they can retry later. On a slow
# system, it's a good idea to change this to 1.

# max_inbound_syncs = 3

# By default, any destination is allowed to
# connect and download messages, but you can
# optionally restrict this. If you enable
# authentication, you must provide a list of
# allowed identity hashes in the a file named
# "allowed" in the lxmd config directory.

auth_required = no


[lxmf]

# The LXM Daemon will create an LXMF destination
# that it can receive messages on. This option sets
# the announced display name for this destination.

display_name = Anonymous Peer

# It is possible to announce the internal LXMF
# destination when the LXM Daemon starts up.

announce_at_start = no

# You can also announce the delivery destination
# at a specified interval. This is not enabled by
# default.

# announce_interval = 360

# You can configure the required stamp cost for
# incoming messages.

# stamp_cost = 12

# The maximum accepted unpacked size for mes-
# sages received directly from other peers,
# specified in kilobytes. Messages larger than
# this will be rejected before the transfer
# begins.

delivery_transfer_max_accepted_size = 1

# You can configure an external program to be run
# every time a message is received. The program
# will receive as an argument the full path to the
# message saved as a file. The example below will
# simply result in the message getting deleted as
# soon as it has been received.

# on_inbound = rm


[logging]
# Valid log levels are 0 through 7:
#   0: Log only critical information
#   1: Log errors and lower log levels
#   2: Log warnings and lower log levels
#   3: Log notices and lower log levels
#   4: Log info and lower (this is the default)
#   5: Verbose logging
#   6: Debug logging
#   7: Extreme logging

loglevel = 4

"#;

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(name: &str) -> PathBuf {
        let dir = env::temp_dir().join(format!(
            "lxmd-test-{}-{}-{}",
            name,
            process::id(),
            time::SystemTime::now()
                .duration_since(time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn config_from(text: &str) -> LxmdConfig {
        let mut config = LxmdConfig::default();
        apply_config(&parse_ini(text), &mut config);
        config
    }

    fn s(key: &str) -> Value {
        Value::Str(key.to_string())
    }

    #[test]
    fn write_ready_file_creates_parent_and_marker() {
        let base = temp_dir("ready");
        let ready = base.join("nested").join("lxmd.ready");

        write_ready_file(&ready).unwrap();

        let content = fs::read_to_string(&ready).unwrap();
        assert!(content.starts_with("pid="));
        let _ = fs::remove_dir_all(base);
    }

    #[test]
    fn new_upstream_controls_have_safe_defaults() {
        let config = LxmdConfig::default();

        assert_eq!(config.peer_stamp_cost, 12.0);
        assert!(config.sequential_pn_stamp_validation);
        assert!(config.static_peers_bypass_sequential);
        assert_eq!(config.max_inbound_syncs, 3);
        assert_eq!(config.propagation_sync_max_accepted_size, 10240.0);
    }

    #[test]
    fn direct_delivery_resource_limit_defaults_to_one_kilobyte() {
        let config = LxmdConfig::default();

        assert_eq!(config.delivery_transfer_max_accepted_size, 1.0);
        assert!(EXAMPLE_CONFIG.contains("\ndelivery_transfer_max_accepted_size = 1\n"));
    }

    #[test]
    fn configured_direct_delivery_resource_limit_keeps_upstream_minimum() {
        let config = config_from("[lxmf]\ndelivery_transfer_max_accepted_size = 0.01\n");

        assert_eq!(config.delivery_transfer_max_accepted_size, 0.38);
        let paths = LxmdPaths::new(temp_dir("delivery-limit"));
        assert_eq!(build_router_config(&config, &paths).delivery_limit, 0.38);
    }

    #[test]
    fn fractional_kilobyte_limits_are_never_truncated_to_zero() {
        let config = config_from(
            "[propagation]\npropagation_message_max_accepted_size = 0.1\npropagation_sync_max_accepted_size = 256.5\n",
        );
        assert_eq!(config.propagation_message_max_accepted_size, 0.38);
        assert_eq!(config.propagation_sync_max_accepted_size, 256.5);

        let paths = LxmdPaths::new(temp_dir("kb-limits"));
        let router_config = build_router_config(&config, &paths);
        assert_eq!(router_config.propagation_limit, 0.38);
        assert_eq!(router_config.sync_limit, 256.5);
    }

    #[test]
    fn propagation_transfer_size_is_overridden_like_upstream() {
        // Upstream overwrites propagation_transfer_max_accepted_size with
        // propagation_message_max_accepted_size (or its default).
        let config = config_from("[propagation]\npropagation_transfer_max_accepted_size = 32\n");
        assert_eq!(config.propagation_message_max_accepted_size, 256.0);
    }

    #[test]
    fn new_upstream_controls_parse_and_clamp_minimums() {
        let config = config_from(
            r#"
[lxmf]
stamp_cost = 0

[propagation]
sequential_pn_stamp_validation = no
static_peers_bypass_sequential = no
max_inbound_syncs = 0
"#,
        );

        assert_eq!(config.peer_stamp_cost, 1.0);
        assert!(!config.sequential_pn_stamp_validation);
        assert!(!config.static_peers_bypass_sequential);
        assert_eq!(config.max_inbound_syncs, 1);
    }

    #[test]
    fn delivery_stamp_cost_is_independent_from_propagation_target() {
        let config = config_from(
            "[lxmf]\nstamp_cost = 7\n\n[propagation]\npropagation_stamp_cost_target = 19\n",
        );

        assert_eq!(config.peer_stamp_cost, 7.0);
        assert_eq!(config.propagation_stamp_cost_target, 19.0);
    }

    #[test]
    fn fractional_costs_and_stamp_throttle_follow_upstream_bounds() {
        let config = config_from(
            r#"
[lxmf]
stamp_cost = 8.5

[propagation]
propagation_stamp_cost_target = 16.25
propagation_stamp_cost_flexibility = -2
peering_cost = 18.75
remote_peering_cost_max = 26.5
propagation_stamp_throttle = 10
"#,
        );

        assert_eq!(config.peer_stamp_cost, 8.5);
        assert_eq!(config.propagation_stamp_cost_target, 16.25);
        assert_eq!(config.propagation_stamp_cost_flexibility, 0.0);
        assert_eq!(config.peering_cost, 18.75);
        assert_eq!(config.remote_peering_cost_max, 26.5);
        assert_eq!(config.propagation_stamp_throttle, 600.0);

        let paths = LxmdPaths::new(temp_dir("fractional-costs"));
        let router_config = build_router_config(&config, &paths);
        assert_eq!(router_config.propagation_cost, StampCost::from_f64(16.25));
        assert_eq!(router_config.peering_cost, StampCost::from_f64(18.75));
        assert_eq!(router_config.pn_stamp_throttle, 600.0);

        // Targets below the minimum and throttles below five minutes clamp.
        let config = config_from(
            "[propagation]\npropagation_stamp_cost_target = 4\npropagation_stamp_throttle = 1\n",
        );
        assert_eq!(
            config.propagation_stamp_cost_target,
            PROPAGATION_COST_MIN.as_f64()
        );
        assert_eq!(config.propagation_stamp_throttle, PN_STAMP_THROTTLE as f64);
    }

    #[test]
    fn router_config_receives_inbound_sync_controls() {
        let paths = LxmdPaths::new(temp_dir("router-config"));
        let config = LxmdConfig {
            sequential_pn_stamp_validation: false,
            static_peers_bypass_sequential: false,
            max_inbound_syncs: 7,
            ..LxmdConfig::default()
        };

        let router_config = build_router_config(&config, &paths);

        assert!(!router_config.sequential_validation);
        assert!(router_config.static_sequential);
        assert_eq!(router_config.max_inbound_syncs, 7);
    }

    #[test]
    fn config_values_are_unquoted_and_lose_inline_comments() {
        let config = config_from(
            r#"
[lxmf]
display_name = "My Node # one"
on_inbound = '/usr/bin/handler --flag'
announce_at_start = yes # announce right away
"#,
        );
        assert_eq!(config.display_name, "My Node # one");
        assert_eq!(
            config.on_inbound.as_deref(),
            Some("/usr/bin/handler --flag")
        );
        assert!(config.announce_at_start);
    }

    #[test]
    fn loglevel_defaults_to_notice_and_follows_verbosity() {
        assert_eq!(LxmdConfig::default().loglevel, None);
        assert_eq!(effective_loglevel(None, 0, 0), 3);
        assert_eq!(effective_loglevel(None, 2, 0), 5);
        assert_eq!(effective_loglevel(Some(4), 0, 1), 3);
        assert_eq!(effective_loglevel(Some(0), 0, 3), 0);
        assert_eq!(effective_loglevel(Some(7), 5, 0), 8);

        assert_eq!(config_from("[logging]\nloglevel = 6\n").loglevel, Some(6));
        assert_eq!(config_from("[logging]\nloglevel = 42\n").loglevel, Some(8));

        let filter = rns_net::logging::numeric_log_filter(effective_loglevel(None, 0, 0));
        assert_eq!(filter.default, log::LevelFilter::Info);
        let filter = rns_net::logging::numeric_log_filter(2);
        assert_eq!(filter.default, log::LevelFilter::Warn);
    }

    #[test]
    fn configdir_needs_a_config_file_to_be_picked() {
        let root = temp_dir("configdir");
        let etc = root.join("etc-lxmd");
        let home = root.join("home");
        let xdg = home.join(".config").join("lxmd");
        fs::create_dir_all(&etc).unwrap();
        fs::create_dir_all(&xdg).unwrap();

        // Existing directories without a config file are skipped.
        assert_eq!(detect_configdir(None, &etc, &home), home.join(".lxmd"));

        fs::write(xdg.join("config"), "").unwrap();
        assert_eq!(detect_configdir(None, &etc, &home), xdg);

        fs::write(etc.join("config"), "").unwrap();
        assert_eq!(detect_configdir(None, &etc, &home), etc);

        assert_eq!(
            detect_configdir(Some("/srv/lxmd"), &etc, &home),
            PathBuf::from("/srv/lxmd")
        );
        assert_eq!(
            LxmdPaths::new(PathBuf::from("/c")).messagedir,
            PathBuf::from("/c/storage/messages")
        );
        assert_eq!(
            LxmdPaths::new(PathBuf::from("/c")).logfile,
            PathBuf::from("/c/logfile")
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn identity_is_created_only_when_missing() {
        let dir = temp_dir("identity");
        let path = dir.join("identity");

        assert!(load_identity_file(&path).unwrap().is_none());
        let created = create_identity_file(&path).unwrap();
        assert_eq!(fs::read(&path).unwrap().len(), 64);
        let loaded = load_identity_file(&path).unwrap().unwrap();
        assert_eq!(loaded.hash(), created.hash());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn corrupt_identity_is_an_error_and_left_untouched() {
        let dir = temp_dir("identity-corrupt");
        let path = dir.join("identity");
        fs::write(&path, b"not an identity").unwrap();

        assert!(load_identity_file(&path).is_err());
        assert_eq!(fs::read(&path).unwrap(), b"not an identity");
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn packed_container_matches_upstream_layout() {
        let container = packed_container(Some(b"lxmf"), true, Some("Curve25519"), 0x02);
        let value = msgpack::unpack_exact(&container).unwrap();
        let keys: Vec<_> = value
            .as_map()
            .unwrap()
            .iter()
            .map(|(k, _)| k.as_str().unwrap().to_string())
            .collect();
        assert_eq!(
            keys,
            [
                "state",
                "lxmf_bytes",
                "transport_encrypted",
                "transport_encryption",
                "method"
            ]
        );
        assert_eq!(value.map_get("state"), Some(&Value::UInt(0)));
        assert_eq!(
            value.map_get("lxmf_bytes").unwrap().as_bin(),
            Some(&b"lxmf"[..])
        );
        assert_eq!(
            value.map_get("transport_encrypted"),
            Some(&Value::Bool(true))
        );
        assert_eq!(
            value.map_get("transport_encryption").unwrap().as_str(),
            Some("Curve25519")
        );
        assert_eq!(value.map_get("method"), Some(&Value::UInt(2)));

        // Unencrypted messages store `None` as their encryption description.
        let value = msgpack::unpack_exact(&packed_container(None, false, None, 0x01)).unwrap();
        assert!(value.map_get("transport_encryption").unwrap().is_nil());
        assert!(value.map_get("lxmf_bytes").unwrap().is_nil());
    }

    #[test]
    fn messages_are_written_atomically_under_their_hash() {
        let dir = temp_dir("messages");
        let hash = [0xab; 32];
        let path = write_to_directory(&dir, &hash, b"container").unwrap();

        assert_eq!(path, dir.join(hexrep(&hash)));
        assert_eq!(fs::read(&path).unwrap(), b"container");
        let entries: Vec<_> = fs::read_dir(&dir).unwrap().collect();
        assert_eq!(entries.len(), 1, "no temporary files are left behind");

        assert!(write_to_directory(&dir.join("missing"), &hash, b"x").is_err());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn on_inbound_command_is_split_like_shlex() {
        let path = Path::new("/var/lxmd/messages/abcd");
        assert_eq!(
            on_inbound_argv("rm", path).unwrap(),
            ["rm", "/var/lxmd/messages/abcd"]
        );
        assert_eq!(
            on_inbound_argv("/usr/bin/handler --mode 'fast mode' -x\\ y", path).unwrap(),
            [
                "/usr/bin/handler",
                "--mode",
                "fast mode",
                "-x y",
                "/var/lxmd/messages/abcd"
            ]
        );
        assert_eq!(
            shlex_split(r#"a "b \" \\ \n" c#d"#).unwrap(),
            ["a", r#"b " \ \n"#, "c#d"]
        );
        assert!(shlex_split("unterminated 'quote").is_err());
    }

    #[test]
    fn on_inbound_runs_commands_with_arguments() {
        let dir = temp_dir("on-inbound");
        let message = dir.join("message");
        fs::write(&message, b"data").unwrap();

        run_on_inbound(r#"sh -c 'cp "$0" "$0.copy"'"#, &message).unwrap();

        assert_eq!(fs::read(dir.join("message.copy")).unwrap(), b"data");
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn pretty_helpers_match_rns() {
        assert_eq!(prettysize(0.0), "0 B");
        assert_eq!(prettysize(999.0), "999 B");
        assert_eq!(prettysize(1000.0), "1.00 KB");
        assert_eq!(prettysize(2048.0), "2.05 KB");
        assert_eq!(prettysize(10_240_000.0), "10.24 MB");
        assert_eq!(prettysize(5e24), "5.00YB");
        assert_eq!(prettyspeed(0.0), "0 bps");
        assert_eq!(prettyspeed(8000.0), "8.00 Kbps");

        assert_eq!(prettytime(0.0), "0s");
        assert_eq!(prettytime(30.0), "30.0s");
        assert_eq!(prettytime(120.0), "2m");
        assert_eq!(prettytime(3661.5), "1h, 1m and 1.5s");
        assert_eq!(prettytime(90061.0), "1d, 1h, 1m and 1.0s");
        assert_eq!(prettytime(59.999), "60.0s");
        assert_eq!(prettytime(-61.0), "-1m and 1.0s");

        assert_eq!(prettyhexrep(&[0x00, 0xab]), "<00ab>");

        assert_eq!(py_float(16.0), "16.0");
        assert_eq!(py_float(0.1), "0.1");
        assert_eq!(py_float(12.34), "12.34");
        assert_eq!(py_float(1e16), "1e+16");
        assert_eq!(py_float(1.5e-5), "1.5e-05");
        assert_eq!(py_round2(0.125), 0.12);
        assert_eq!(py_round2(2.675), 2.67);
        assert_eq!(py_round2(0.0004096), 0.0);
    }

    #[test]
    fn remote_hashes_are_validated_like_upstream() {
        assert_eq!(
            parse_destination_hash("00112233445566778899aabbccddeeff").unwrap()[15],
            0xff
        );
        assert_eq!(
            parse_destination_hash("0011").unwrap_err(),
            "Destination hash length must be 32 characters"
        );
        assert!(parse_destination_hash("zz112233445566778899aabbccddeeff")
            .unwrap_err()
            .starts_with("non-hexadecimal number found in fromhex() arg"));
    }

    #[test]
    fn control_responses_map_to_upstream_exit_codes() {
        let code = |request, response: Value| control_failure(request, &response);
        let error = |e: PeerError| Value::UInt(e as u64);

        for request in [
            ControlRequest::Status,
            ControlRequest::Sync,
            ControlRequest::Unpeer,
        ] {
            assert_eq!(
                code(request, error(PeerError::NoIdentity)),
                Some(("Remote received no identity", 203))
            );
            assert_eq!(
                code(request, error(PeerError::NoAccess)),
                Some(("Access denied", 204))
            );
            assert_eq!(
                code(request, Value::Nil),
                Some(("Empty response received", 207))
            );
        }
        for request in [ControlRequest::Sync, ControlRequest::Unpeer] {
            assert_eq!(
                code(request, error(PeerError::InvalidData)),
                Some(("Invalid data received by remote", 205))
            );
            assert_eq!(
                code(request, error(PeerError::NotFound)),
                Some(("The requested peer was not found", 206))
            );
            assert_eq!(code(request, Value::Bool(true)), None);
        }
        assert_eq!(code(ControlRequest::Status, Value::Map(vec![])), None);

        let peer = [0x5a; 16];
        assert_eq!(
            control_success_message(ControlRequest::Sync, &peer),
            format!("Sync requested for peer <{}>", "5a".repeat(16))
        );
        assert_eq!(
            control_success_message(ControlRequest::Unpeer, &peer),
            format!("Broke peering with <{}>", "5a".repeat(16))
        );

        assert_eq!(ControlRequest::Status.path(), "/pn/get/stats");
        assert_eq!(ControlRequest::Sync.path(), "/pn/peer/sync");
        assert_eq!(ControlRequest::Unpeer.path(), "/pn/peer/unpeer");
        assert_eq!(ControlRequest::Status.default_timeout(), 5.0);
        assert_eq!(ControlRequest::Sync.default_timeout(), 10.0);
        assert_eq!(ControlRequest::Unpeer.default_timeout(), 10.0);
    }

    fn sample_stats(now: f64) -> Value {
        let peer = Value::Map(vec![
            (s("type"), s("static")),
            (s("state"), Value::UInt(0)),
            (s("alive"), Value::Bool(true)),
            (s("name"), s("Test\u{202e} Node 🚀")),
            (s("last_heard"), Value::Int((now - 30.0) as i64)),
            (s("next_sync_attempt"), Value::Float(0.0)),
            (s("last_sync_attempt"), Value::Float(now - 120.0)),
            (s("sync_backoff"), Value::Float(0.0)),
            (s("peering_timebase"), Value::Float(0.0)),
            (s("ler"), Value::Int(8000)),
            (s("str"), Value::Int(16000)),
            (s("transfer_limit"), Value::Float(256.0)),
            (s("sync_limit"), Value::UInt(10240)),
            (s("target_stamp_cost"), Value::Float(16.0)),
            (s("stamp_cost_flexibility"), Value::Float(3.0)),
            (s("peering_cost"), Value::Float(18.0)),
            (s("peering_key"), Value::Float(19.0)),
            (s("network_distance"), Value::UInt(2)),
            (s("rx_bytes"), Value::UInt(5000)),
            (s("tx_bytes"), Value::UInt(1500)),
            (s("acceptance_rate"), Value::Float(0.5)),
            (
                s("messages"),
                Value::Map(vec![
                    (s("offered"), Value::UInt(4)),
                    (s("outgoing"), Value::UInt(2)),
                    (s("incoming"), Value::UInt(5)),
                    (s("unhandled"), Value::UInt(1)),
                ]),
            ),
        ]);
        let unknown_peer = Value::Map(vec![
            (s("type"), s("discovered")),
            (s("alive"), Value::Bool(false)),
            (s("name"), Value::Nil),
            (s("last_heard"), Value::Int(0)),
            (s("last_sync_attempt"), Value::Float(0.0)),
            (s("ler"), Value::Int(0)),
            (s("str"), Value::Int(0)),
            (s("transfer_limit"), Value::Nil),
            (s("sync_limit"), Value::Nil),
            (s("target_stamp_cost"), Value::Nil),
            (s("stamp_cost_flexibility"), Value::Nil),
            (s("peering_cost"), Value::Nil),
            (s("peering_key"), Value::Nil),
            (s("network_distance"), Value::UInt(128)),
            (s("rx_bytes"), Value::UInt(0)),
            (s("tx_bytes"), Value::UInt(0)),
            (s("acceptance_rate"), Value::UInt(0)),
            (
                s("messages"),
                Value::Map(vec![
                    (s("offered"), Value::UInt(0)),
                    (s("outgoing"), Value::UInt(0)),
                    (s("incoming"), Value::UInt(0)),
                    (s("unhandled"), Value::UInt(0)),
                ]),
            ),
        ]);
        Value::Map(vec![
            (s("identity_hash"), Value::Bin(vec![0x33; 16])),
            (s("destination_hash"), Value::Bin(vec![0x11; 16])),
            (s("uptime"), Value::Float(3725.5)),
            (s("delivery_limit"), Value::Float(1.0)),
            (s("propagation_limit"), Value::UInt(256)),
            (s("sync_limit"), Value::UInt(10240)),
            (s("target_stamp_cost"), Value::Float(16.0)),
            (s("stamp_cost_flexibility"), Value::Float(3.0)),
            (s("peering_cost"), Value::Float(18.0)),
            (s("max_peering_cost"), Value::Float(26.0)),
            (s("autopeer_maxdepth"), Value::UInt(4)),
            (s("from_static_only"), Value::Bool(false)),
            (
                s("messagestore"),
                Value::Map(vec![
                    (s("count"), Value::UInt(3)),
                    (s("bytes"), Value::UInt(2048)),
                    (s("limit"), Value::UInt(500_000_000)),
                ]),
            ),
            (
                s("clients"),
                Value::Map(vec![
                    (s("client_propagation_messages_received"), Value::UInt(2)),
                    (s("client_propagation_messages_served"), Value::UInt(3)),
                ]),
            ),
            (s("unpeered_propagation_incoming"), Value::UInt(1)),
            (s("unpeered_propagation_rx_bytes"), Value::UInt(700)),
            (s("static_peers"), Value::UInt(1)),
            (s("discovered_peers"), Value::UInt(1)),
            (s("total_peers"), Value::UInt(2)),
            (s("max_peers"), Value::UInt(20)),
            (
                s("peers"),
                Value::Map(vec![
                    (Value::Bin(vec![0x22; 16]), peer),
                    (Value::Bin(vec![0x44; 16]), unknown_peer),
                ]),
            ),
        ])
    }

    const SAMPLE_STATUS: &str = "
LXMF Propagation Node running on <11111111111111111111111111111111>, uptime is 1h, 2m and 5.5s
Messagestore contains 3 messages, 2.05 KB (0.0% utilised of 500.00 MB)
Required propagation stamp cost is 16.0, flexibility is 3.0
Peering cost is 18.0, max remote peering cost is 26.0
Accepting propagated messages from all nodes
256.00 KB message limit, 10.24 MB sync limit

Peers   : 2 total (peer limit is 20)
          1 discovered, 1 static
          1 available, 1 unreachable

Traffic : 8 messages received in total (5.70 KB)
          5 messages received from peered nodes (5.00 KB)
          1 messages received from unpeered nodes (700 B)
          2 messages transferred to peered nodes (1.50 KB)
          2 propagation messages received directly from clients
          3 propagation messages served to clients
          Distribution factor is 0.25

";

    const SAMPLE_PEERS: &str = "  Static peer     <22222222222222222222222222222222>
    Name       : Test Node
    Status     : Available, 2 hops away, last heard 30.0s ago
    Costs      : Propagation 16.0 (flex 3.0), peering 18.0
    Sync key   : Generated, value is 19.0
    Speeds     : 16.00 Kbps STR, 8.00 Kbps LER
    Limits     : 256.00 KB message limit, 10.24 MB sync limit
    Messages   : 4 offered, 2 outgoing, 5 incoming, 50.0% acceptance rate
    Traffic    : 5.00 KB received, 1.50 KB sent
    Sync state : 1 unhandled message, last synced 2m ago

  Discovered peer <44444444444444444444444444444444>
    Status     : Unreachable, hops unknown, last heard 11d, 13h, 46m and 40.0s ago
    Costs      : Propagation unknown (flex unknown), peering unknown
    Sync key   : Not generated
    Speeds     : 0 bps STR, 0 bps LER
    Limits     : Unknown message limit, unknown sync limit
    Messages   : 0 offered, 0 outgoing, 0 incoming, 0% acceptance rate
    Traffic    : 0 B received, 0 B sent
    Sync state : 0 unhandled messages, never synced

";

    #[test]
    fn status_output_matches_upstream_format() {
        let now = 1_000_000.0;
        let stats = sample_stats(now);

        assert_eq!(format_status(&stats, true, false, now), SAMPLE_STATUS);
        assert_eq!(
            format_status(&stats, true, true, now),
            format!("{}{}", SAMPLE_STATUS, SAMPLE_PEERS)
        );

        let header = SAMPLE_STATUS.lines().take(2).collect::<Vec<_>>().join("\n");
        assert_eq!(
            format_status(&stats, false, true, now),
            format!("{}\n\n{}", header, SAMPLE_PEERS)
        );
    }

    #[test]
    fn peer_name_sanitizer_normalizes_and_preserves_safe_text() {
        assert_eq!(
            sanitize_peer_name("  ＬＸＭＦ   Café—東京 42  "),
            "LXMF Café—東京 42"
        );
        assert_eq!(sanitize_peer_name("Node_(EU), v2.0!"), "Node_(EU), v2.0!");
    }

    #[test]
    fn peer_name_sanitizer_removes_terminal_and_direction_controls() {
        assert_eq!(
            sanitize_peer_name("safe\u{1b}[31m red\u{7f}\u{202e}evil\u{2066}"),
            "safe[31m redevil"
        );
        assert_eq!(
            sanitize_peer_name("left\u{200b}\u{200d}right\u{feff}"),
            "leftright"
        );
    }

    #[test]
    fn peer_name_sanitizer_removes_symbols_private_use_and_emoji() {
        assert_eq!(
            sanitize_peer_name("Node 🚀 ☀ \u{e000} © + = arrows→"),
            "Node arrows"
        );
        // Dingbat punctuation and numbers are stripped by upstream's block
        // patterns even though their categories are kept.
        assert_eq!(sanitize_peer_name("a\u{2768}b\u{2776}c"), "abc");
    }

    #[test]
    fn peer_name_sanitizer_collapses_all_separator_whitespace() {
        assert_eq!(
            sanitize_peer_name("one\u{00a0}\u{2003}two\u{2028}three\u{2029}four"),
            "one two three four"
        );
    }

    #[test]
    fn interval_announces_follow_upstream_comparison() {
        assert!(!announce_due(100.0, 0.0, None));
        assert!(!announce_due(60.0, 0.0, Some(60)));
        assert!(announce_due(60.5, 0.0, Some(60)));
        // A zero interval announces on every jobs pass.
        assert!(announce_due(5.0, 0.0, Some(0)));
        assert_eq!(JOBS_INTERVAL, 5.0);
        assert_eq!(DEFERRED_JOBS_DELAY, 10.0);
    }

    #[test]
    fn example_config_is_upstream_default() {
        assert!(EXAMPLE_CONFIG.starts_with("# This is an example LXM Daemon config file.\n"));
        assert!(EXAMPLE_CONFIG.ends_with("\nloglevel = 4\n\n"));
        for commented in [
            "# control_allowed = 7d7e542829b40f32364499b27438dba8, 437229f8e29598b2282b88bad5e44698",
            "# node_name = Anonymous Propagation Node",
            "# message_storage_limit = 500",
            "# propagation_message_max_accepted_size = 256",
            "# propagation_sync_max_accepted_size = 10240",
            "# propagation_stamp_cost_target = 16.0",
            "# propagation_stamp_cost_flexibility = 3.0",
            "# propagation_stamp_throttle = 5",
            "# peering_cost = 18.0",
            "# remote_peering_cost_max = 26.0",
            "# max_peers = 20",
            "# from_static_only = True",
            "# sequential_pn_stamp_validation = yes",
            "# static_peers_bypass_sequential = yes",
            "# max_inbound_syncs = 3",
            "# announce_interval = 360",
            "# stamp_cost = 12",
            "# on_inbound = rm",
        ] {
            assert!(
                EXAMPLE_CONFIG.contains(&format!("\n{}\n", commented)),
                "missing {commented}"
            );
        }

        let config = config_from(EXAMPLE_CONFIG);
        assert!(!config.enable_node);
        assert_eq!(config.pn_announce_interval, Some(360 * 60));
        assert!(config.pn_announce_at_start);
        assert!(config.autopeer);
        assert_eq!(config.autopeer_maxdepth, Some(6));
        assert!(!config.auth_required);
        assert_eq!(config.display_name, "Anonymous Peer");
        assert!(!config.announce_at_start);
        assert_eq!(config.announce_interval, None);
        assert_eq!(config.delivery_transfer_max_accepted_size, 1.0);
        assert_eq!(config.on_inbound, None);
        assert_eq!(config.loglevel, Some(4));
    }
}
