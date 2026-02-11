use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::{env, fs, thread, time};

use lxmf_core::constants::*;

const VERSION: &str = env!("CARGO_PKG_VERSION");

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
                parsed.timeout = args.get(i).and_then(|s| s.parse().ok());
            }
            "-r" | "--remote" => {
                i += 1;
                parsed.remote = args.get(i).cloned();
            }
            "--identity" => {
                i += 1;
                parsed.identity = args.get(i).cloned();
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
                eprintln!("Unknown argument: {}", other);
                process::exit(1);
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
    println!("  --config PATH          Path to alternative lxmd config directory");
    println!("  --rnsconfig PATH       Path to alternative Reticulum config directory");
    println!("  -p, --propagation-node Run an LXMF Propagation Node");
    println!("  -i, --on-inbound PATH  Executable to run when a message is received");
    println!("  -v, --verbose          Increase verbosity (can be repeated)");
    println!("  -q, --quiet            Decrease verbosity (can be repeated)");
    println!("  -s, --service          Run as a service (log to file)");
    println!("  --status               Display node status");
    println!("  --peers                Display peered nodes");
    println!("  --sync HASH            Request sync with specified peer");
    println!("  -b, --break HASH       Break peering with specified peer");
    println!("  --timeout SECONDS      Timeout for query operations");
    println!("  -r, --remote HASH      Remote propagation node destination hash");
    println!("  --identity PATH        Path to identity for remote requests");
    println!("  --exampleconfig        Print example configuration and exit");
    println!("  --version              Show version and exit");
    println!("  -h, --help             Show this help message");
}

// ============================================================
// Configuration
// ============================================================

#[derive(Clone)]
pub struct LxmdConfig {
    // [lxmf]
    pub display_name: String,
    pub announce_at_start: bool,
    pub announce_interval: Option<u64>,
    pub delivery_transfer_max_accepted_size: f64,
    pub on_inbound: Option<String>,

    // [propagation]
    pub enable_node: bool,
    pub node_name: Option<String>,
    pub auth_required: bool,
    pub pn_announce_at_start: bool,
    pub autopeer: bool,
    pub autopeer_maxdepth: Option<u8>,
    pub pn_announce_interval: Option<u64>,
    pub message_storage_limit: f64,
    pub propagation_transfer_max_accepted_size: f64,
    pub propagation_message_max_accepted_size: f64,
    pub propagation_sync_max_accepted_size: f64,
    pub propagation_stamp_cost_target: u8,
    pub propagation_stamp_cost_flexibility: u8,
    pub peering_cost: u8,
    pub remote_peering_cost_max: u8,
    pub prioritise_destinations: Vec<[u8; 16]>,
    pub control_allowed: Vec<[u8; 16]>,
    pub static_peers: Vec<[u8; 16]>,
    pub max_peers: Option<usize>,
    pub from_static_only: bool,

    // [logging]
    pub loglevel: u8,
}

impl Default for LxmdConfig {
    fn default() -> Self {
        Self {
            display_name: "Anonymous Peer".to_string(),
            announce_at_start: false,
            announce_interval: None,
            delivery_transfer_max_accepted_size: 1000.0,
            on_inbound: None,

            enable_node: false,
            node_name: None,
            auth_required: false,
            pn_announce_at_start: false,
            autopeer: true,
            autopeer_maxdepth: None,
            pn_announce_interval: None,
            message_storage_limit: 500.0,
            propagation_transfer_max_accepted_size: 256.0,
            propagation_message_max_accepted_size: 256.0,
            propagation_sync_max_accepted_size: 10240.0,
            propagation_stamp_cost_target: PROPAGATION_COST,
            propagation_stamp_cost_flexibility: PROPAGATION_COST_FLEX,
            peering_cost: PEERING_COST,
            remote_peering_cost_max: MAX_PEERING_COST,
            prioritise_destinations: Vec::new(),
            control_allowed: Vec::new(),
            static_peers: Vec::new(),
            max_peers: None,
            from_static_only: false,

            loglevel: 4,
        }
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
            let value = value.trim().to_string();
            sections
                .entry(current_section.clone())
                .or_default()
                .insert(key, value);
        }
    }

    sections
}

fn parse_bool(s: &str) -> bool {
    matches!(
        s.to_lowercase().as_str(),
        "yes" | "true" | "1" | "on"
    )
}

fn parse_hex_list(s: &str) -> Vec<[u8; 16]> {
    s.split(',')
        .filter_map(|h| {
            let h = h.trim();
            if h.len() != 32 {
                return None;
            }
            let mut result = [0u8; 16];
            for i in 0..16 {
                result[i] = u8::from_str_radix(&h[i * 2..i * 2 + 2], 16).ok()?;
            }
            Some(result)
        })
        .collect()
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
        if let Some(v) = lxmf.get("delivery_transfer_max_accepted_size") {
            if let Ok(kb) = v.parse::<f64>() {
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
        if let Some(v) = prop.get("announce_interval") {
            if let Ok(mins) = v.parse::<u64>() {
                config.pn_announce_interval = Some(mins * 60);
            }
        }
        if let Some(v) = prop.get("message_storage_limit") {
            if let Ok(mb) = v.parse::<f64>() {
                config.message_storage_limit = mb.max(0.005);
            }
        }
        if let Some(v) = prop.get("propagation_transfer_max_accepted_size") {
            if let Ok(kb) = v.parse::<f64>() {
                config.propagation_transfer_max_accepted_size = kb.max(0.38);
            }
        }
        if let Some(v) = prop.get("propagation_message_max_accepted_size") {
            if let Ok(kb) = v.parse::<f64>() {
                config.propagation_message_max_accepted_size = kb.max(0.38);
            }
        }
        if let Some(v) = prop.get("propagation_sync_max_accepted_size") {
            if let Ok(kb) = v.parse::<f64>() {
                config.propagation_sync_max_accepted_size = kb.max(0.38);
            }
        }
        if let Some(v) = prop.get("propagation_stamp_cost_target") {
            if let Ok(n) = v.parse::<u8>() {
                config.propagation_stamp_cost_target = n.max(PROPAGATION_COST_MIN);
            }
        }
        if let Some(v) = prop.get("propagation_stamp_cost_flexibility") {
            if let Ok(n) = v.parse() {
                config.propagation_stamp_cost_flexibility = n;
            }
        }
        if let Some(v) = prop.get("peering_cost") {
            if let Ok(n) = v.parse() {
                config.peering_cost = n;
            }
        }
        if let Some(v) = prop.get("remote_peering_cost_max") {
            if let Ok(n) = v.parse() {
                config.remote_peering_cost_max = n;
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
            if let Ok(n) = v.parse::<u8>() {
                if n <= 7 {
                    config.loglevel = n;
                }
            }
        }
    }
}

// ============================================================
// Directory and path setup
// ============================================================

struct LxmdPaths {
    configdir: PathBuf,
    configpath: PathBuf,
    identitypath: PathBuf,
    storagepath: PathBuf,
    messagedir: PathBuf,
    ignoredpath: PathBuf,
    allowedpath: PathBuf,
}

fn setup_paths(config_override: Option<&str>) -> LxmdPaths {
    let configdir = if let Some(dir) = config_override {
        PathBuf::from(dir)
    } else if Path::new("/etc/lxmd").is_dir() {
        PathBuf::from("/etc/lxmd")
    } else {
        let home = env::var("HOME").unwrap_or_else(|_| ".".to_string());
        let xdg_config = PathBuf::from(&home).join(".config").join("lxmd");
        if xdg_config.is_dir() {
            xdg_config
        } else {
            PathBuf::from(&home).join(".lxmd")
        }
    };

    let _ = fs::create_dir_all(&configdir);

    let storagepath = configdir.join("storage");
    let _ = fs::create_dir_all(&storagepath);

    let messagedir = configdir.join("messages");
    let _ = fs::create_dir_all(&messagedir);

    LxmdPaths {
        configpath: configdir.join("config"),
        identitypath: configdir.join("identity"),
        ignoredpath: configdir.join("ignored"),
        allowedpath: configdir.join("allowed"),
        storagepath,
        messagedir,
        configdir,
    }
}

// ============================================================
// Identity management
// ============================================================

fn load_or_create_identity(path: &Path) -> rns_crypto::identity::Identity {
    use rns_crypto::identity::Identity;

    if path.exists() {
        if let Ok(data) = fs::read(path) {
            if data.len() == 64 {
                let mut key = [0u8; 64];
                key.copy_from_slice(&data);
                let id = Identity::from_private_key(&key);
                log::info!("Loaded identity from {}", path.display());
                return id;
            }
        }
        log::warn!("Failed to load identity from {}, creating new", path.display());
    }

    let mut rng = rns_crypto::OsRng;
    let id = Identity::new(&mut rng);
    if let Some(prv) = id.get_private_key() {
        if let Err(e) = fs::write(path, &prv) {
            log::error!("Failed to save identity to {}: {}", path.display(), e);
        } else {
            log::info!("Created new identity, saved to {}", path.display());
        }
    }
    id
}

/// Load hex destination hashes from a file (one per line).
fn load_hash_file(path: &Path) -> Vec<[u8; 16]> {
    let content = match fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };

    content
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                return None;
            }
            if line.len() != 32 {
                return None;
            }
            let mut result = [0u8; 16];
            for i in 0..16 {
                result[i] = u8::from_str_radix(&line[i * 2..i * 2 + 2], 16).ok()?;
            }
            Some(result)
        })
        .collect()
}

// ============================================================
// On-inbound message handler
// ============================================================

fn handle_inbound_message(message_dir: &Path, on_inbound: Option<&str>, message_data: &[u8]) {
    // Write message to file
    let hash = rns_crypto::sha256::sha256(message_data);
    let hex: String = hash.iter().map(|b| format!("{:02x}", b)).collect();
    let filepath = message_dir.join(&hex);

    if let Err(e) = fs::write(&filepath, message_data) {
        log::error!("Failed to write message to {}: {}", filepath.display(), e);
        return;
    }

    log::debug!("Received message written to {}", filepath.display());

    // Execute on_inbound command if configured
    if let Some(command) = on_inbound {
        log::debug!("Calling external program to handle message");
        let filepath_str = filepath.to_string_lossy();
        match process::Command::new(command)
            .arg(filepath_str.as_ref())
            .stdout(process::Stdio::null())
            .stderr(process::Stdio::null())
            .spawn()
        {
            Ok(mut child) => {
                let _ = child.wait();
            }
            Err(e) => {
                log::error!("Failed to execute on_inbound command '{}': {}", command, e);
            }
        }
    }
}

// ============================================================
// Hex display helpers
// ============================================================

fn hex_display(hash: &[u8]) -> String {
    hash.iter().map(|b| format!("{:02x}", b)).collect()
}

fn parse_hex_hash(s: &str) -> Option<[u8; 16]> {
    let s = s.trim();
    if s.len() != 32 {
        return None;
    }
    let mut result = [0u8; 16];
    for i in 0..16 {
        result[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(result)
}

fn pretty_size(bytes: u64) -> String {
    if bytes >= 1_000_000_000 {
        format!("{:.2} GB", bytes as f64 / 1_000_000_000.0)
    } else if bytes >= 1_000_000 {
        format!("{:.2} MB", bytes as f64 / 1_000_000.0)
    } else if bytes >= 1_000 {
        format!("{:.2} KB", bytes as f64 / 1_000.0)
    } else {
        format!("{} bytes", bytes)
    }
}

fn pretty_time(seconds: f64) -> String {
    if seconds >= 86400.0 {
        format!("{:.1} days", seconds / 86400.0)
    } else if seconds >= 3600.0 {
        format!("{:.1} hours", seconds / 3600.0)
    } else if seconds >= 60.0 {
        format!("{:.1} minutes", seconds / 60.0)
    } else {
        format!("{:.1} seconds", seconds)
    }
}

// ============================================================
// Remote control operations
// ============================================================

fn display_status(stats: &rns_core::msgpack::Value) {
    let map = match stats.as_map() {
        Some(m) => m,
        None => {
            println!("Invalid status data");
            return;
        }
    };

    let find = |key: &str| -> Option<&rns_core::msgpack::Value> {
        map.iter()
            .find(|(k, _)| k.as_str() == Some(key))
            .map(|(_, v)| v)
    };

    println!("LXMF Propagation Node Status");
    println!("============================");

    if let Some(v) = find("identity_hash") {
        if let Some(b) = v.as_bin() {
            println!("Identity     : {}", hex_display(b));
        }
    }
    if let Some(v) = find("destination_hash") {
        if let Some(b) = v.as_bin() {
            println!("Destination  : {}", hex_display(b));
        }
    }
    if let Some(v) = find("uptime") {
        if let Some(f) = v.as_float().or_else(|| v.as_number()) {
            println!("Uptime       : {}", pretty_time(f));
        }
    }

    // Message store
    if let Some(ms) = find("messagestore") {
        if let Some(ms_map) = ms.as_map() {
            let ms_find = |key: &str| -> Option<&rns_core::msgpack::Value> {
                ms_map
                    .iter()
                    .find(|(k, _)| k.as_str() == Some(key))
                    .map(|(_, v)| v)
            };
            println!();
            println!("Message Store");
            println!("-------------");
            if let Some(v) = ms_find("count") {
                println!("  Messages   : {}", v.as_uint().unwrap_or(0));
            }
            if let Some(v) = ms_find("bytes") {
                println!("  Size       : {}", pretty_size(v.as_uint().unwrap_or(0)));
            }
            if let Some(v) = ms_find("limit") {
                println!("  Limit      : {}", pretty_size(v.as_uint().unwrap_or(0)));
            }
        }
    }

    // Stamp costs
    if let Some(v) = find("target_stamp_cost") {
        println!();
        println!("Stamp Configuration");
        println!("-------------------");
        println!("  Target cost    : {}", v.as_uint().unwrap_or(0));
    }
    if let Some(v) = find("stamp_cost_flexibility") {
        println!("  Flexibility    : {}", v.as_uint().unwrap_or(0));
    }
    if let Some(v) = find("peering_cost") {
        println!("  Peering cost   : {}", v.as_uint().unwrap_or(0));
    }

    // Peers
    if let Some(v) = find("total_peers") {
        println!();
        println!("Peering");
        println!("-------");
        print!("  Total peers    : {}", v.as_uint().unwrap_or(0));
        if let Some(max) = find("max_peers") {
            print!(" / {}", max.as_uint().unwrap_or(0));
        }
        println!();
    }

    // Client stats
    if let Some(clients) = find("clients") {
        if let Some(c_map) = clients.as_map() {
            let c_find = |key: &str| -> Option<&rns_core::msgpack::Value> {
                c_map
                    .iter()
                    .find(|(k, _)| k.as_str() == Some(key))
                    .map(|(_, v)| v)
            };
            println!();
            println!("Client Traffic");
            println!("--------------");
            if let Some(v) = c_find("client_propagation_messages_received") {
                println!("  Received     : {}", v.as_uint().unwrap_or(0));
            }
            if let Some(v) = c_find("client_propagation_messages_served") {
                println!("  Served       : {}", v.as_uint().unwrap_or(0));
            }
        }
    }
}

fn display_peers(stats: &rns_core::msgpack::Value) {
    let map = match stats.as_map() {
        Some(m) => m,
        None => {
            println!("Invalid status data");
            return;
        }
    };

    let peers = map
        .iter()
        .find(|(k, _)| k.as_str() == Some("peers"))
        .and_then(|(_, v)| v.as_map());

    let peers = match peers {
        Some(p) => p,
        None => {
            println!("No peer data available");
            return;
        }
    };

    if peers.is_empty() {
        println!("No peers configured");
        return;
    }

    println!("Peered Nodes");
    println!("============");

    for (key, value) in peers {
        let hash = match key.as_bin() {
            Some(b) => hex_display(b),
            None => continue,
        };

        let peer_map = match value.as_map() {
            Some(m) => m,
            None => continue,
        };

        let pfind = |name: &str| -> Option<&rns_core::msgpack::Value> {
            peer_map
                .iter()
                .find(|(k, _)| k.as_str() == Some(name))
                .map(|(_, v)| v)
        };

        println!();
        println!("  {}", hash);

        if let Some(v) = pfind("alive") {
            let status = if v.as_bool() == Some(true) {
                "alive"
            } else {
                "unknown"
            };
            println!("    Status       : {}", status);
        }

        if let Some(v) = pfind("offered") {
            println!("    Offered      : {}", v.as_uint().unwrap_or(0));
        }
        if let Some(v) = pfind("outgoing") {
            println!("    Outgoing     : {}", v.as_uint().unwrap_or(0));
        }
        if let Some(v) = pfind("incoming") {
            println!("    Incoming     : {}", v.as_uint().unwrap_or(0));
        }
        if let Some(v) = pfind("tx_bytes") {
            println!("    TX           : {}", pretty_size(v.as_uint().unwrap_or(0)));
        }
        if let Some(v) = pfind("rx_bytes") {
            println!("    RX           : {}", pretty_size(v.as_uint().unwrap_or(0)));
        }
    }
}

// ============================================================
// Main daemon
// ============================================================

fn main() {
    let args = parse_args();

    if args.exampleconfig {
        print!("{}", EXAMPLE_CONFIG);
        return;
    }

    // Remote control operations
    if args.status || args.peers {
        eprintln!("Remote status/peers query not yet implemented");
        eprintln!("This requires an active RNS link to the control destination");
        process::exit(1);
    }

    if args.sync.is_some() {
        eprintln!("Remote sync request not yet implemented");
        process::exit(1);
    }

    if args.unpeer.is_some() {
        eprintln!("Remote unpeer request not yet implemented");
        process::exit(1);
    }

    // Setup paths and config
    let paths = setup_paths(args.config.as_deref());
    let mut config = LxmdConfig::default();

    // CLI overrides
    if args.propagation_node {
        config.enable_node = true;
    }
    if args.on_inbound.is_some() {
        config.on_inbound = args.on_inbound.clone();
    }

    // Load config file
    if paths.configpath.exists() {
        match fs::read_to_string(&paths.configpath) {
            Ok(content) => {
                let ini = parse_ini(&content);
                apply_config(&ini, &mut config);
            }
            Err(e) => {
                eprintln!(
                    "Failed to read config file {}: {}",
                    paths.configpath.display(),
                    e
                );
            }
        }
    } else {
        // Write default config
        let _ = fs::write(&paths.configpath, EXAMPLE_CONFIG);
        log::info!(
            "Created default config at {}",
            paths.configpath.display()
        );
    }

    // Apply CLI overrides after config file (CLI takes precedence)
    if args.propagation_node {
        config.enable_node = true;
    }
    if args.on_inbound.is_some() {
        config.on_inbound = args.on_inbound;
    }

    // Determine log level
    let base_level = config.loglevel as i8;
    let adjusted = (base_level + args.verbose as i8 - args.quiet as i8).clamp(0, 7);
    let log_level = match adjusted {
        0 => log::LevelFilter::Error,
        1 => log::LevelFilter::Error,
        2 => log::LevelFilter::Warn,
        3 => log::LevelFilter::Info,
        4 => log::LevelFilter::Info,
        5 => log::LevelFilter::Debug,
        6 => log::LevelFilter::Debug,
        _ => log::LevelFilter::Trace,
    };
    // Simple stderr logger
    log::set_max_level(log_level);

    println!("lxmd v{} starting...", VERSION);

    // Load or create identity
    let identity = load_or_create_identity(&paths.identitypath);
    let identity_hash = identity.hash();
    println!("Identity  : {}", hex_display(identity_hash));

    // Load ignored/allowed lists
    let _ignored = load_hash_file(&paths.ignoredpath);
    let _allowed = load_hash_file(&paths.allowedpath);

    // Display configuration
    println!("Display   : {}", config.display_name);
    if config.enable_node {
        println!("Mode      : Propagation Node");
        if let Some(ref name) = config.node_name {
            println!("Node name : {}", name);
        }
        println!(
            "Storage   : {:.0} MB limit",
            config.message_storage_limit
        );
        println!("Stamp cost: {} (flex: {})", config.propagation_stamp_cost_target, config.propagation_stamp_cost_flexibility);
        println!("Peer cost : {} (max remote: {})", config.peering_cost, config.remote_peering_cost_max);
        if config.autopeer {
            print!("Autopeer  : enabled");
            if let Some(depth) = config.autopeer_maxdepth {
                print!(" (max depth: {})", depth);
            }
            println!();
        }
        if !config.static_peers.is_empty() {
            println!("Static    : {} peers", config.static_peers.len());
        }
    } else {
        println!("Mode      : Client");
    }

    if config.on_inbound.is_some() {
        println!("On inbound: {}", config.on_inbound.as_ref().unwrap());
    }

    println!("Config    : {}", paths.configdir.display());
    println!("Storage   : {}", paths.storagepath.display());
    println!();

    // Setup signal handler for graceful shutdown
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();

    if let Err(e) = setup_signal_handler(r) {
        log::warn!("Failed to setup signal handler: {}", e);
    }

    println!("lxmd running. Press Ctrl+C to exit.");

    // Main loop
    while running.load(Ordering::Relaxed) {
        thread::sleep(time::Duration::from_secs(1));
    }

    println!();
    println!("Shutting down...");
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
            signal(2, handler);  // SIGINT
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

# Whether to automatically peer with other
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
# propagation_message_max_accepted_size = 256

# The maximum accepted transfer size per in-
# coming propagation node sync.
# propagation_sync_max_accepted_size = 10240

# You can configure the target stamp cost
# required to deliver messages via this node.
# propagation_stamp_cost_target = 16

# Stamp cost flexibility for messages from
# other propagation nodes.
# propagation_stamp_cost_flexibility = 3

# Peering cost for remote nodes.
# peering_cost = 18

# Maximum peering cost accepted from remote nodes.
# remote_peering_cost_max = 26

# Prioritise storage for specific destinations.
# prioritise_destinations = 41d20c727598a3fbbdf9106133a3a0ed

# Maximum number of auto-peered nodes.
# max_peers = 20

# Static peers to always maintain peering with.
# static_peers = e17f833c4ddf8890dd3a79a6fea8161d

# Only accept propagation from static peers.
# from_static_only = True

# Require authentication for message retrieval.
auth_required = no


[lxmf]

# Announced display name for this destination.
display_name = Anonymous Peer

# Announce delivery destination at start.
announce_at_start = no

# Announce interval in minutes.
# announce_interval = 360

# Maximum accepted message size in KB.
delivery_transfer_max_accepted_size = 1000

# External program to run on message receipt.
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
