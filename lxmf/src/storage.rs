use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use rns_core::msgpack::{self, Value};

static NEXT_TMP_WRITE_ID: AtomicU64 = AtomicU64::new(1);

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
    atomic_write(path, &data)
}

/// Write bytes through a unique sibling temporary file and atomically replace
/// the destination.
pub(crate) fn atomic_write(path: &Path, data: &[u8]) -> io::Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let filename = path.file_name().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "atomic write path has no filename",
        )
    })?;
    let tmp_id = NEXT_TMP_WRITE_ID.fetch_add(1, Ordering::Relaxed);
    let tmp_filename = format!(
        ".tmp.{}.{}.{}",
        std::process::id(),
        tmp_id,
        filename.to_string_lossy()
    );
    let tmp_path = parent.join(tmp_filename);

    let result = (|| {
        let mut file = File::create(&tmp_path)?;
        file.write_all(data)?;
        file.sync_all()?;
        fs::rename(&tmp_path, path)
    })();

    if result.is_err() {
        let _ = fs::remove_file(&tmp_path);
    }

    result
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
pub fn save_stamp_costs(path: &Path, costs: &HashMap<[u8; 16], (f64, u8)>) -> std::io::Result<()> {
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
pub fn save_node_stats(path: &Path, stats: &HashMap<String, u64>) -> std::io::Result<()> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;
    use std::thread;

    static NEXT_TEST_DIR: AtomicU64 = AtomicU64::new(1);

    fn temp_dir(name: &str) -> PathBuf {
        let id = NEXT_TEST_DIR.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("lxmf_storage_{name}_{}_{}", std::process::id(), id));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).unwrap();
        path
    }

    fn temp_files(path: &Path) -> Vec<PathBuf> {
        fs::read_dir(path)
            .unwrap()
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|path| {
                path.file_name()
                    .is_some_and(|name| name.to_string_lossy().starts_with(".tmp."))
            })
            .collect()
    }

    #[test]
    fn save_msgpack_atomically_replaces_existing_value() {
        let dir = temp_dir("replace");
        let path = dir.join("state");
        save_msgpack(&path, &Value::Str("old".into())).unwrap();
        save_msgpack(&path, &Value::Str("new".into())).unwrap();

        assert_eq!(load_msgpack(&path), Some(Value::Str("new".into())));
        assert!(temp_files(&dir).is_empty());

        fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn save_msgpack_replaces_symlink_instead_of_overwriting_its_target() {
        use std::os::unix::fs::symlink;

        let dir = temp_dir("symlink");
        let target = dir.join("target");
        let state = dir.join("state");
        fs::write(&target, b"target must remain unchanged").unwrap();
        symlink(&target, &state).unwrap();

        save_msgpack(&state, &Value::Str("new state".into())).unwrap();

        assert_eq!(fs::read(&target).unwrap(), b"target must remain unchanged");
        assert!(!fs::symlink_metadata(&state)
            .unwrap()
            .file_type()
            .is_symlink());
        assert_eq!(load_msgpack(&state), Some(Value::Str("new state".into())));
        assert!(temp_files(&dir).is_empty());

        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn failed_atomic_replacement_cleans_temporary_file() {
        let dir = temp_dir("failed_replace");
        let destination_directory = dir.join("state");
        fs::create_dir(&destination_directory).unwrap();

        let result = save_msgpack(
            &destination_directory,
            &Value::Str("cannot replace a directory".into()),
        );

        assert!(result.is_err());
        assert!(destination_directory.is_dir());
        assert!(temp_files(&dir).is_empty());

        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn concurrent_saves_leave_one_complete_msgpack_value() {
        let dir = temp_dir("concurrent");
        let path = Arc::new(dir.join("state"));
        let payloads: Vec<Value> = (0..12)
            .map(|index| {
                Value::Array(vec![
                    Value::UInt(index),
                    Value::Bin(vec![index as u8; 128 * 1024]),
                ])
            })
            .collect();

        let handles: Vec<_> = payloads
            .iter()
            .cloned()
            .map(|value| {
                let path = path.clone();
                thread::spawn(move || save_msgpack(&path, &value))
            })
            .collect();

        for handle in handles {
            handle.join().unwrap().unwrap();
        }

        let stored = load_msgpack(&path).expect("one complete value should remain");
        assert!(payloads.contains(&stored));
        assert!(temp_files(&dir).is_empty());

        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn all_state_helpers_round_trip_through_atomic_writer() {
        let dir = temp_dir("helpers");
        let paths = StoragePaths::new(&dir);
        paths.ensure_dirs().unwrap();

        let peer = Value::Map(vec![(
            Value::Str("destination_hash".into()),
            Value::Bin(vec![0x11; 16]),
        )]);
        save_peers(&paths.peers, std::slice::from_ref(&peer)).unwrap();
        assert_eq!(load_peers(&paths.peers), vec![peer]);

        let transient_ids = HashMap::from([([0x22; 32], 1234.5)]);
        save_transient_ids(&paths.local_deliveries, &transient_ids).unwrap();
        assert_eq!(load_transient_ids(&paths.local_deliveries), transient_ids);

        let costs = HashMap::from([([0x33; 16], (2345.5, 17))]);
        save_stamp_costs(&paths.outbound_stamp_costs, &costs).unwrap();
        assert_eq!(load_stamp_costs(&paths.outbound_stamp_costs), costs);

        let stats = HashMap::from([("received".to_string(), 42)]);
        save_node_stats(&paths.node_stats, &stats).unwrap();
        assert_eq!(load_node_stats(&paths.node_stats), stats);

        let tickets = Value::Map(vec![(
            Value::Str("outbound".into()),
            Value::Map(Vec::new()),
        )]);
        save_tickets(&paths.available_tickets, &tickets).unwrap();
        assert_eq!(load_tickets(&paths.available_tickets), Some(tickets));

        assert!(temp_files(&paths.base).is_empty());
        fs::remove_dir_all(dir).unwrap();
    }
}
