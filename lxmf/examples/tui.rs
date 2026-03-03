//! LXMF TUI — minimal terminal UI for sending/receiving LXMF messages over LoRa.
//!
//! Connects to an ESP32 RNode via USB serial (KISS protocol) and provides a
//! simple chat-like interface for LXMF messaging.
//!
//! Usage:
//!   RUST_LOG=info cargo run --example tui -- [serial_port] [frequency_mhz]
//!
//! Defaults: /dev/ttyUSB0, 868 MHz

use std::io;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crossterm::event::{self, Event, KeyCode, KeyModifiers};
use crossterm::terminal::{self, EnterAlternateScreen, LeaveAlternateScreen};
use crossterm::{execute};
use ratatui::prelude::*;
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph};

use lxmf_core::constants::*;
use lxmf_core::message;
use lxmf_rs::router::{LxmDelivery, LxmRouter, LxmfCallbacks, OutboundMessage, RouterConfig};
use rns_core::types::{DestHash, IdentityHash, LinkId, PacketHash};
use rns_crypto::identity::Identity;
use rns_net::destination::AnnouncedIdentity;
use rns_net::driver::Callbacks;
use rns_net::node::{InterfaceConfig, InterfaceVariant, NodeConfig, RnsNode};
use rns_net::{InterfaceId, ManagementConfig, RNodeConfig, RNodeSubConfig};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn short_hex(bytes: &[u8]) -> String {
    hex(&bytes[..4.min(bytes.len())])
}

fn parse_hex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

fn now_hhmm() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    // Simple UTC time — good enough for a demo
    let h = (secs / 3600) % 24;
    let m = (secs / 60) % 60;
    format!("{:02}:{:02}", h, m)
}

// ---------------------------------------------------------------------------
// App events from network callbacks
// ---------------------------------------------------------------------------

enum AppEvent {
    MessageReceived {
        source_hash: [u8; 16],
        title: Vec<u8>,
        content: Vec<u8>,
        method: DeliveryMethod,
    },
    Announce(AnnouncedIdentity),
}

// ---------------------------------------------------------------------------
// Callbacks wrapper (same pattern as echo.rs)
// ---------------------------------------------------------------------------

struct AppCallbacks {
    inner: LxmfCallbacks,
    tx: mpsc::Sender<AppEvent>,
}

impl Callbacks for AppCallbacks {
    fn on_announce(&mut self, announced: AnnouncedIdentity) {
        let _ = self.tx.send(AppEvent::Announce(announced.clone()));
        self.inner.on_announce(announced);
    }
    fn on_path_updated(&mut self, dest_hash: DestHash, hops: u8) {
        self.inner.on_path_updated(dest_hash, hops);
    }
    fn on_local_delivery(&mut self, dest_hash: DestHash, raw: Vec<u8>, packet_hash: PacketHash) {
        self.inner.on_local_delivery(dest_hash, raw, packet_hash);
    }
    fn on_link_established(&mut self, link_id: LinkId, dest_hash: DestHash, rtt: f64, is_initiator: bool) {
        self.inner.on_link_established(link_id, dest_hash, rtt, is_initiator);
    }
    fn on_link_closed(&mut self, link_id: LinkId, reason: Option<rns_core::link::TeardownReason>) {
        self.inner.on_link_closed(link_id, reason);
    }
    fn on_remote_identified(&mut self, link_id: LinkId, identity_hash: IdentityHash, public_key: [u8; 64]) {
        self.inner.on_remote_identified(link_id, identity_hash, public_key);
    }
    fn on_resource_received(&mut self, link_id: LinkId, data: Vec<u8>, metadata: Option<Vec<u8>>) {
        self.inner.on_resource_received(link_id, data, metadata);
    }
    fn on_resource_completed(&mut self, link_id: LinkId) {
        self.inner.on_resource_completed(link_id);
    }
    fn on_resource_failed(&mut self, link_id: LinkId, error: String) {
        self.inner.on_resource_failed(link_id, error);
    }
    fn on_response(&mut self, link_id: LinkId, request_id: [u8; 16], data: Vec<u8>) {
        self.inner.on_response(link_id, request_id, data);
    }
    fn on_proof(&mut self, dest_hash: DestHash, packet_hash: PacketHash, rtt: f64) {
        self.inner.on_proof(dest_hash, packet_hash, rtt);
    }
    fn on_proof_requested(&mut self, dest_hash: DestHash, packet_hash: PacketHash) -> bool {
        self.inner.on_proof_requested(dest_hash, packet_hash)
    }
    fn on_link_data(&mut self, link_id: LinkId, context: u8, data: Vec<u8>) {
        self.inner.on_link_data(link_id, context, data);
    }
}

// ---------------------------------------------------------------------------
// UI state
// ---------------------------------------------------------------------------

#[derive(PartialEq)]
enum InputField {
    Target,
    Message,
}

struct App {
    log: Vec<String>,
    log_offset: usize,
    target_input: String,
    message_input: String,
    focus: InputField,
    running: bool,
}

impl App {
    fn new() -> Self {
        Self {
            log: Vec::new(),
            log_offset: 0,
            target_input: String::new(),
            message_input: String::new(),
            focus: InputField::Target,
            running: true,
        }
    }

    fn push_log(&mut self, msg: String) {
        self.log.push(msg);
        // Auto-scroll to bottom
        self.log_offset = self.log.len().saturating_sub(1);
    }

    fn scroll_up(&mut self, n: usize) {
        self.log_offset = self.log_offset.saturating_sub(n);
    }

    fn scroll_down(&mut self, n: usize) {
        let max = self.log.len().saturating_sub(1);
        self.log_offset = (self.log_offset + n).min(max);
    }
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

fn render(frame: &mut Frame, app: &App, identity_hex: &str, dest_hex: &str, port: &str) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),  // header
            Constraint::Min(5),    // message log
            Constraint::Length(5), // input area
        ])
        .split(frame.area());

    // Header
    let header_text = format!(
        " Identity: {}  Dest: {}  [RNode {}]",
        &identity_hex[..8.min(identity_hex.len())],
        &dest_hex[..8.min(dest_hex.len())],
        port
    );
    let header = Paragraph::new(header_text)
        .block(Block::default().borders(Borders::ALL).title(" lxmf-tui "));
    frame.render_widget(header, chunks[0]);

    // Message log
    let visible_height = chunks[1].height.saturating_sub(2) as usize;
    let start = if app.log.len() > visible_height {
        let max_start = app.log.len() - visible_height;
        app.log_offset.min(max_start)
    } else {
        0
    };
    let items: Vec<ListItem> = app.log[start..]
        .iter()
        .take(visible_height)
        .map(|s| ListItem::new(s.as_str()))
        .collect();
    let log_widget = List::new(items)
        .block(Block::default().borders(Borders::ALL).title(" Messages "));
    frame.render_widget(log_widget, chunks[1]);

    // Input area
    let input_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(1), Constraint::Length(1)])
        .margin(1)
        .split(chunks[2]);

    let target_style = if app.focus == InputField::Target {
        Style::default().fg(Color::Yellow)
    } else {
        Style::default().fg(Color::DarkGray)
    };
    let msg_style = if app.focus == InputField::Message {
        Style::default().fg(Color::Yellow)
    } else {
        Style::default().fg(Color::DarkGray)
    };

    let target_line = Paragraph::new(format!("To: {}", app.target_input)).style(target_style);
    let msg_line = Paragraph::new(format!(" > {}", app.message_input)).style(msg_style);

    let input_block = Block::default().borders(Borders::ALL).title(" Input (Tab to switch) ");
    frame.render_widget(input_block, chunks[2]);
    frame.render_widget(target_line, input_chunks[0]);
    frame.render_widget(msg_line, input_chunks[1]);

    // Cursor position
    match app.focus {
        InputField::Target => {
            frame.set_cursor_position((
                input_chunks[0].x + 4 + app.target_input.len() as u16,
                input_chunks[0].y,
            ));
        }
        InputField::Message => {
            frame.set_cursor_position((
                input_chunks[1].x + 3 + app.message_input.len() as u16,
                input_chunks[1].y,
            ));
        }
    }
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let port = args.get(1).cloned().unwrap_or_else(|| "/dev/ttyUSB0".into());
    let freq_mhz: f64 = args
        .get(2)
        .and_then(|s| s.parse().ok())
        .unwrap_or(868.0);
    let frequency = (freq_mhz * 1_000_000.0) as u32;

    // Persistent identity
    let data_dir = dirs_or_home().join(".lxmf-tui");
    let _ = std::fs::create_dir_all(&data_dir);
    let id_path = data_dir.join("identity");
    let identity = if id_path.exists() {
        let bytes = std::fs::read(&id_path).expect("read identity");
        let mut key = [0u8; 64];
        key.copy_from_slice(&bytes);
        Identity::from_private_key(&key)
    } else {
        let id = Identity::new(&mut rns_crypto::OsRng);
        std::fs::write(&id_path, id.get_private_key().unwrap()).expect("save identity");
        id
    };

    let identity_hex = hex(identity.hash());
    let delivery_dest_hash = rns_core::destination::destination_hash(
        APP_NAME,
        &["delivery"],
        Some(identity.hash()),
    );
    let dest_hex = hex(&delivery_dest_hash);
    let src_hash = delivery_dest_hash;

    // Router
    let (tx, rx) = mpsc::channel::<AppEvent>();
    let mut router = LxmRouter::new(
        Identity::from_private_key(&identity.get_private_key().unwrap()),
        RouterConfig {
            storagepath: data_dir.clone(),
            ..RouterConfig::default()
        },
    );
    let delivery_tx = tx.clone();
    router.set_delivery_callback(Box::new(move |d: &LxmDelivery| {
        let _ = delivery_tx.send(AppEvent::MessageReceived {
            source_hash: d.source_hash,
            title: d.title.clone(),
            content: d.content.clone(),
            method: d.method,
        });
    }));

    let router = Arc::new(Mutex::new(router));
    let app_callbacks = AppCallbacks {
        inner: LxmfCallbacks::new(router.clone()),
        tx,
    };

    // RNS node with RNode interface
    let node = Arc::new(
        RnsNode::start(
            NodeConfig {
                transport_enabled: false,
                identity: Some(Identity::new(&mut rns_crypto::OsRng)),
                interfaces: vec![InterfaceConfig {
                    variant: InterfaceVariant::RNode(RNodeConfig {
                        name: format!("RNode {}", port),
                        port: port.clone(),
                        speed: 115200,
                        subinterfaces: vec![RNodeSubConfig {
                            name: "LoRa".into(),
                            frequency,
                            bandwidth: 125000,
                            txpower: 14,
                            spreading_factor: 8,
                            coding_rate: 5,
                            flow_control: false,
                            st_alock: None,
                            lt_alock: None,
                        }],
                        id_interval: None,
                        id_callsign: None,
                        base_interface_id: InterfaceId(1),
                    }),
                    mode: rns_core::constants::MODE_FULL,
                    ifac: None,
                    discovery: None,
                }],
                share_instance: false,
                instance_name: "default".into(),
                shared_instance_port: 37428,
                rpc_port: 0,
                cache_dir: Some(data_dir.clone()),
                management: ManagementConfig::default(),
                probe_port: None,
                probe_addrs: vec![],
                probe_protocol: rns_core::holepunch::ProbeProtocol::Rnsp,
                device: None,
                hooks: vec![],
                discover_interfaces: false,
                discovery_required_value: None,
                respond_to_probes: false,
                prefer_shorter_path: false,
                max_paths_per_destination: 1,
            },
            Box::new(app_callbacks),
        )
        .expect("Failed to start RNS node"),
    );

    // Wire up router
    {
        let mut r = router.lock().unwrap();
        r.set_node(node.clone());
        r.register_delivery_identity(&identity, None, Some("lxmf-tui".to_string()));
    }

    // Wait for RNode detection + configuration (takes ~4-5s)
    std::thread::sleep(Duration::from_secs(6));
    {
        let r = router.lock().unwrap();
        r.announce_delivery(&identity);
    }

    let sign_identity = Identity::from_private_key(&identity.get_private_key().unwrap());

    // Set up terminal
    terminal::enable_raw_mode().expect("enable raw mode");
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen).expect("enter alternate screen");
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend).expect("create terminal");

    let mut app = App::new();
    app.push_log(format!(
        "[{}] Started. Identity: {} Dest: {}",
        now_hhmm(),
        &identity_hex[..8],
        &dest_hex[..8]
    ));
    app.push_log(format!(
        "[{}] RNode on {} at {} MHz. Announced.",
        now_hhmm(),
        port,
        freq_mhz
    ));

    let mut last_jobs = Instant::now();

    while app.running {
        // Render
        terminal
            .draw(|f| render(f, &app, &identity_hex, &dest_hex, &port))
            .expect("draw");

        // Poll keyboard (100ms timeout for ~10fps)
        if event::poll(Duration::from_millis(100)).unwrap_or(false) {
            if let Ok(Event::Key(key)) = event::read() {
                match key.code {
                    KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                        app.running = false;
                    }
                    KeyCode::Char('q') if app.focus == InputField::Target && app.target_input.is_empty() => {
                        app.running = false;
                    }
                    KeyCode::Tab => {
                        app.focus = match app.focus {
                            InputField::Target => InputField::Message,
                            InputField::Message => InputField::Target,
                        };
                    }
                    KeyCode::Up => app.scroll_up(1),
                    KeyCode::Down => app.scroll_down(1),
                    KeyCode::PageUp => app.scroll_up(10),
                    KeyCode::PageDown => app.scroll_down(10),
                    KeyCode::Backspace => match app.focus {
                        InputField::Target => { app.target_input.pop(); }
                        InputField::Message => { app.message_input.pop(); }
                    },
                    KeyCode::Enter => {
                        if app.focus == InputField::Target {
                            app.focus = InputField::Message;
                        } else if !app.message_input.is_empty() && !app.target_input.is_empty() {
                            // Send message
                            let target_hex_str = app.target_input.trim().to_string();
                            let content = app.message_input.clone();
                            app.message_input.clear();

                            if target_hex_str.len() != 32 {
                                app.push_log(format!(
                                    "[{}] ERROR: dest hash must be 32 hex chars (got {})",
                                    now_hhmm(),
                                    target_hex_str.len()
                                ));
                            } else if let Some(bytes) = parse_hex(&target_hex_str) {
                                let mut dest = [0u8; 16];
                                dest.copy_from_slice(&bytes);

                                let timestamp = std::time::SystemTime::now()
                                    .duration_since(std::time::UNIX_EPOCH)
                                    .unwrap()
                                    .as_secs_f64();

                                match message::pack(
                                    &dest,
                                    &src_hash,
                                    timestamp,
                                    b"",
                                    content.as_bytes(),
                                    vec![],
                                    None,
                                    |data| sign_identity.sign(data).map_err(|_| message::Error::SignError),
                                ) {
                                    Ok(packed) => {
                                        let mut r = router.lock().unwrap();
                                        r.handle_outbound(OutboundMessage {
                                            destination_hash: dest,
                                            source_hash: src_hash,
                                            packed: packed.packed,
                                            message_hash: packed.message_hash,
                                            method: DeliveryMethod::Opportunistic,
                                            state: MessageState::Outbound,
                                            representation: Representation::Unknown,
                                            attempts: 0,
                                            last_attempt: 0.0,
                                            stamp: None,
                                            stamp_cost: None,
                                            propagation_packed: None,
                                            propagation_stamp: None,
                                            transient_id: None,
                                            delivery_callback: None,
                                            failed_callback: None,
                                            progress_callback: None,
                                            link_id: None,
                                            packet_hash: None,
                                        });
                                        app.push_log(format!(
                                            "[{}] SEND to={} \"{}\"",
                                            now_hhmm(),
                                            short_hex(&dest),
                                            content
                                        ));
                                    }
                                    Err(e) => {
                                        app.push_log(format!(
                                            "[{}] ERROR: failed to pack message: {:?}",
                                            now_hhmm(),
                                            e
                                        ));
                                    }
                                }
                            } else {
                                app.push_log(format!(
                                    "[{}] ERROR: invalid hex in dest hash",
                                    now_hhmm()
                                ));
                            }
                        }
                    }
                    KeyCode::Char(c) => match app.focus {
                        InputField::Target => {
                            if c.is_ascii_hexdigit() && app.target_input.len() < 32 {
                                app.target_input.push(c);
                            }
                        }
                        InputField::Message => {
                            app.message_input.push(c);
                        }
                    },
                    _ => {}
                }
            }
        }

        // Drain network events
        while let Ok(event) = rx.try_recv() {
            match event {
                AppEvent::MessageReceived {
                    source_hash,
                    title,
                    content,
                    method,
                } => {
                    let title_str = String::from_utf8_lossy(&title);
                    let content_str = String::from_utf8_lossy(&content);
                    let method_str = match method {
                        DeliveryMethod::Opportunistic => "opp",
                        DeliveryMethod::Direct => "dir",
                        DeliveryMethod::Propagated => "prop",
                        _ => "?",
                    };
                    let line = if title.is_empty() {
                        format!(
                            "[{}] RECV from={} ({}) \"{}\"",
                            now_hhmm(),
                            short_hex(&source_hash),
                            method_str,
                            content_str
                        )
                    } else {
                        format!(
                            "[{}] RECV from={} ({}) [{}] \"{}\"",
                            now_hhmm(),
                            short_hex(&source_hash),
                            method_str,
                            title_str,
                            content_str
                        )
                    };
                    app.push_log(line);
                }
                AppEvent::Announce(announced) => {
                    let app_str = announced
                        .app_data
                        .as_ref()
                        .and_then(|d| std::str::from_utf8(d).ok())
                        .unwrap_or("");
                    let line = if app_str.is_empty() {
                        format!(
                            "[{}] ANN  dest={} hops={}",
                            now_hhmm(),
                            short_hex(&announced.dest_hash.0),
                            announced.hops
                        )
                    } else {
                        format!(
                            "[{}] ANN  dest={} hops={} \"{}\"",
                            now_hhmm(),
                            short_hex(&announced.dest_hash.0),
                            announced.hops,
                            app_str
                        )
                    };
                    app.push_log(line);
                }
            }
        }

        // Periodic jobs (~every 4 seconds)
        if last_jobs.elapsed() >= Duration::from_secs(4) {
            router.lock().unwrap().jobs();
            last_jobs = Instant::now();
        }
    }

    // Cleanup terminal
    terminal::disable_raw_mode().expect("disable raw mode");
    execute!(terminal.backend_mut(), LeaveAlternateScreen).expect("leave alternate screen");

    // Drop router (which holds an Arc<RnsNode> clone) so we can shut down the node
    drop(router);
    if let Ok(node) = Arc::try_unwrap(node) {
        node.shutdown();
    }
}

fn dirs_or_home() -> std::path::PathBuf {
    std::env::var("HOME")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::env::temp_dir())
}
