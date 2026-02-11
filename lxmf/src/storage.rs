use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use rns_core::msgpack::{self, Value};

/// Storage paths relative to the LXMF storage directory.
pub struct StoragePaths {
    pub base: PathBuf,
    pub messagestore: PathBuf,
    pub ratchets: PathBuf,
    pub peers: PathBuf,
    pub local_deliveries: PathBuf,
    pub locally_processed: PathBuf,
    pub outbound_stamp_costs: PathBuf,
    pub available_tickets: PathBuf,
    pub node_stats: PathBuf,
}

impl StoragePaths {
    pub fn new(storagepath: &Path) -> Self {
        let base = storagepath.join("lxmf");
        Self {
            messagestore: base.join("messagestore"),
            ratchets: base.join("ratchets"),
            peers: base.join("peers"),
            local_deliveries: base.join("local_deliveries"),
            locally_processed: base.join("locally_processed"),
            outbound_stamp_costs: base.join("outbound_stamp_costs"),
            available_tickets: base.join("available_tickets"),
            node_stats: base.join("node_stats"),
            base,
        }
    }

    pub fn ensure_dirs(&self) -> std::io::Result<()> {
        fs::create_dir_all(&self.base)?;
        fs::create_dir_all(&self.messagestore)?;
        fs::create_dir_all(&self.ratchets)?;
        Ok(())
    }
}

/// Save a msgpack-encoded value to a file.
pub fn save_msgpack(path: &Path, value: &Value) -> std::io::Result<()> {
    let data = msgpack::pack(value);
    fs::write(path, data)
}

/// Load a msgpack-encoded value from a file.
pub fn load_msgpack(path: &Path) -> Option<Value> {
    let data = fs::read(path).ok()?;
    msgpack::unpack_exact(&data).ok()
}

/// Save peers to storage as a msgpack array of peer dicts.
pub fn save_peers(path: &Path, peers: &[Value]) -> std::io::Result<()> {
    let value = Value::Array(peers.to_vec());
    save_msgpack(path, &value)
}

/// Load peers from storage.
pub fn load_peers(path: &Path) -> Vec<Value> {
    match load_msgpack(path) {
        Some(Value::Array(peers)) => peers,
        _ => Vec::new(),
    }
}

/// Save transient ID cache as msgpack dict: hash -> timestamp.
pub fn save_transient_ids(path: &Path, ids: &HashMap<[u8; 32], f64>) -> std::io::Result<()> {
    let entries: Vec<(Value, Value)> = ids
        .iter()
        .map(|(k, v)| (Value::Bin(k.to_vec()), Value::Float(*v)))
        .collect();
    save_msgpack(path, &Value::Map(entries))
}

/// Load transient ID cache from storage.
pub fn load_transient_ids(path: &Path) -> HashMap<[u8; 32], f64> {
    let mut map = HashMap::new();
    if let Some(Value::Map(entries)) = load_msgpack(path) {
        for (k, v) in entries {
            if let (Some(key_bytes), Some(ts)) = (k.as_bin(), v.as_number()) {
                if key_bytes.len() == 32 {
                    let mut key = [0u8; 32];
                    key.copy_from_slice(key_bytes);
                    map.insert(key, ts);
                }
            }
        }
    }
    map
}

/// Save stamp costs: dest_hash -> [timestamp, cost].
pub fn save_stamp_costs(
    path: &Path,
    costs: &HashMap<[u8; 16], (f64, u8)>,
) -> std::io::Result<()> {
    let entries: Vec<(Value, Value)> = costs
        .iter()
        .map(|(k, (ts, cost))| {
            (
                Value::Bin(k.to_vec()),
                Value::Array(vec![Value::Float(*ts), Value::UInt(*cost as u64)]),
            )
        })
        .collect();
    save_msgpack(path, &Value::Map(entries))
}

/// Load stamp costs from storage.
pub fn load_stamp_costs(path: &Path) -> HashMap<[u8; 16], (f64, u8)> {
    let mut map = HashMap::new();
    if let Some(Value::Map(entries)) = load_msgpack(path) {
        for (k, v) in entries {
            if let (Some(key_bytes), Some(arr)) = (k.as_bin(), v.as_array()) {
                if key_bytes.len() == 16 && arr.len() >= 2 {
                    let mut key = [0u8; 16];
                    key.copy_from_slice(key_bytes);
                    if let (Some(ts), Some(cost)) = (arr[0].as_number(), arr[1].as_uint()) {
                        map.insert(key, (ts, cost as u8));
                    }
                }
            }
        }
    }
    map
}

/// Save node statistics.
pub fn save_node_stats(
    path: &Path,
    stats: &HashMap<String, u64>,
) -> std::io::Result<()> {
    let entries: Vec<(Value, Value)> = stats
        .iter()
        .map(|(k, v)| (Value::Str(k.clone()), Value::UInt(*v)))
        .collect();
    save_msgpack(path, &Value::Map(entries))
}

/// Load node statistics.
pub fn load_node_stats(path: &Path) -> HashMap<String, u64> {
    let mut map = HashMap::new();
    if let Some(Value::Map(entries)) = load_msgpack(path) {
        for (k, v) in entries {
            if let (Some(key), Some(val)) = (k.as_str(), v.as_uint()) {
                map.insert(key.to_string(), val);
            }
        }
    }
    map
}

/// Save tickets: dict with "outbound", "inbound", "last_deliveries".
pub fn save_tickets(path: &Path, value: &Value) -> std::io::Result<()> {
    save_msgpack(path, value)
}

/// Load tickets from storage.
pub fn load_tickets(path: &Path) -> Option<Value> {
    load_msgpack(path)
}
