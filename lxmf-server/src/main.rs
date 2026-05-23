use std::collections::{HashMap, VecDeque};
use std::env;
use std::fs;
use std::fs::Metadata;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, RwLock};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

const VERSION: &str = env!("CARGO_PKG_VERSION");
const DEFAULT_HTTP_HOST: &str = "127.0.0.1";
const DEFAULT_HTTP_PORT: u16 = 37529;
const DEFAULT_RNS_SHARED_PORT: u16 = 37428;
const MAX_LOG_LINES: usize = 1_000;
const LXMD_READY_TIMEOUT: Duration = Duration::from_secs(30);

fn main() {
    let args = Args::parse();

    if args.has("version") {
        println!("lxmf-server {}", VERSION);
        return;
    }

    if args.has("help") || args.positional.is_empty() {
        print_help();
        return;
    }

    init_logging(&args);

    match args.positional[0].as_str() {
        "start" => run_start(args),
        other => {
            eprintln!("Unknown subcommand: {}", other);
            print_help();
            std::process::exit(1);
        }
    }
}

fn run_start(args: Args) {
    let config = ServerConfig::from_args(&args);
    if let Err(err) = config.ensure_runtime_bootstrap() {
        eprintln!("lxmf-server: {}", err);
        std::process::exit(1);
    }

    if args.has("dry-run") {
        for spec in config.process_specs() {
            println!("{}", spec.command_line());
        }
        if config.http.enabled {
            println!("http://{}:{}", config.http.host, config.http.port);
        }
        return;
    }

    let (control_tx, control_rx) = mpsc::channel();
    let state = SharedState::default();
    {
        let mut guard = state.write().unwrap();
        guard.config = Some(config.snapshot());
    }

    let supervisor = Supervisor::new(config.supervisor_config(state.clone(), control_rx));
    match supervisor.run_with_started_hook(|| {
        if config.http.enabled {
            start_http(&config, state.clone(), control_tx.clone())?;
        }
        Ok(())
    }) {
        Ok(code) => std::process::exit(code),
        Err(err) => {
            eprintln!("lxmf-server: {}", err);
            std::process::exit(1);
        }
    }
}

fn init_logging(args: &Args) {
    let level = if args.quiet > 0 {
        match args.quiet {
            1 => log::LevelFilter::Warn,
            _ => log::LevelFilter::Error,
        }
    } else {
        match args.verbosity {
            0 => log::LevelFilter::Info,
            1 => log::LevelFilter::Debug,
            _ => log::LevelFilter::Trace,
        }
    };

    let mut builder = env_logger::Builder::new();
    builder.filter_level(level).format_timestamp_secs();
    let _ = builder.try_init();
}

fn print_help() {
    println!(
        "lxmf-server - LXMF daemon supervisor and control server

USAGE:
    lxmf-server start [OPTIONS]

OPTIONS:
    -c, --config PATH        Path to config directory
        --lxmd-bin PATH      Advanced override for lxmd executable
        --http-host HOST     Host for embedded control HTTP server
        --http-port PORT     Port for embedded control HTTP server
        --http-token TOKEN   Auth token for embedded control HTTP server
        --disable-auth       Disable auth on embedded control HTTP server
        --no-http            Disable the embedded control HTTP server
        --dry-run            Print the child process plan and exit
    -v                       Increase verbosity (repeat for more)
    -q                       Decrease verbosity (repeat for more)
    -h, --help               Show this help
        --version            Show version"
    );
}

#[derive(Debug, Default, Clone)]
struct Args {
    positional: Vec<String>,
    values: HashMap<String, String>,
    flags: HashMap<String, bool>,
    verbosity: u8,
    quiet: u8,
}

impl Args {
    fn parse() -> Self {
        Self::parse_from(env::args().skip(1))
    }

    fn parse_from<I, S>(iter: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let mut args = Args::default();
        let mut iter = iter.into_iter().map(Into::into).peekable();
        while let Some(arg) = iter.next() {
            match arg.as_str() {
                "-c" | "--config" => {
                    if let Some(value) = iter.next() {
                        args.values.insert("config".into(), value);
                    }
                }
                "--lxmd-bin" => {
                    if let Some(value) = iter.next() {
                        args.values.insert("lxmd-bin".into(), value);
                    }
                }
                "--http-host" => {
                    if let Some(value) = iter.next() {
                        args.values.insert("http-host".into(), value);
                    }
                }
                "--http-port" => {
                    if let Some(value) = iter.next() {
                        args.values.insert("http-port".into(), value);
                    }
                }
                "--http-token" => {
                    if let Some(value) = iter.next() {
                        args.values.insert("http-token".into(), value);
                    }
                }
                "--disable-auth" => {
                    args.flags.insert("disable-auth".into(), true);
                }
                "--no-http" => {
                    args.flags.insert("no-http".into(), true);
                }
                "--dry-run" => {
                    args.flags.insert("dry-run".into(), true);
                }
                "-v" => args.verbosity = args.verbosity.saturating_add(1),
                "-q" => args.quiet = args.quiet.saturating_add(1),
                "-h" | "--help" => {
                    args.flags.insert("help".into(), true);
                }
                "--version" => {
                    args.flags.insert("version".into(), true);
                }
                other => args.positional.push(other.to_string()),
            }
        }
        args
    }

    fn has(&self, key: &str) -> bool {
        self.flags.get(key).copied().unwrap_or(false)
    }

    fn get(&self, key: &str) -> Option<&str> {
        self.values.get(key).map(String::as_str)
    }
}

#[derive(Debug, Clone)]
struct ServerConfig {
    config_path: Option<PathBuf>,
    resolved_config_dir: PathBuf,
    server_config_file_path: PathBuf,
    server_config_file_present: bool,
    file_config: ServerConfigFile,
    lxmd_bin: PathBuf,
    lxmd: LxmdRuntimeConfig,
    rns: RnsRuntimeConfig,
    http: HttpConfig,
    sidecars: Vec<SidecarConfig>,
}

#[derive(Debug, Clone)]
struct LxmdRuntimeConfig {
    config_dir: PathBuf,
    rns_config_dir: PathBuf,
    propagation_node: bool,
    on_inbound: Option<String>,
    ready_file: PathBuf,
}

#[derive(Debug, Clone)]
struct RnsRuntimeConfig {
    shared_instance_port: u16,
}

#[derive(Debug, Clone, Serialize)]
struct HttpConfig {
    enabled: bool,
    host: String,
    port: u16,
    auth_token: Option<String>,
    disable_auth: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct ServerConfigFile {
    #[serde(default)]
    lxmd_bin: Option<String>,
    #[serde(default)]
    lxmd: LxmdConfigFile,
    #[serde(default)]
    rns: RnsConfigFile,
    #[serde(default)]
    http: HttpConfigFile,
    #[serde(default)]
    sidecars: Vec<SidecarConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct LxmdConfigFile {
    #[serde(default)]
    config_dir: Option<String>,
    #[serde(default)]
    rns_config_dir: Option<String>,
    #[serde(default)]
    propagation_node: Option<bool>,
    #[serde(default)]
    on_inbound: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct RnsConfigFile {
    #[serde(default)]
    shared_instance_port: Option<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct HttpConfigFile {
    #[serde(default)]
    enabled: Option<bool>,
    #[serde(default)]
    host: Option<String>,
    #[serde(default)]
    port: Option<u16>,
    #[serde(default)]
    auth_token: Option<String>,
    #[serde(default)]
    disable_auth: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SidecarConfig {
    name: String,
    bin: String,
    #[serde(default)]
    args: Vec<String>,
    #[serde(default)]
    env: HashMap<String, String>,
    #[serde(default)]
    cwd: Option<String>,
    #[serde(default)]
    restart: bool,
    #[serde(default)]
    ready_file: Option<String>,
}

impl ServerConfig {
    fn from_args(args: &Args) -> Self {
        let config_path = args.get("config").map(PathBuf::from);
        let resolved_config_dir = resolve_config_dir(config_path.as_deref());
        let server_config_file_path = resolved_config_dir.join("lxmf-server.json");
        let (file_config, server_config_file_present) =
            Self::load_config_file(&server_config_file_path).unwrap_or_else(|err| {
                log::warn!(
                    "failed to load server config file {}: {}",
                    server_config_file_path.display(),
                    err
                );
                (ServerConfigFile::default(), false)
            });

        Self::build(
            config_path,
            resolved_config_dir,
            server_config_file_path,
            server_config_file_present,
            file_config,
            Some(args),
        )
    }

    fn parse_config_json(body: &[u8]) -> Result<ServerConfigFile, String> {
        serde_json::from_slice(body).map_err(|e| format!("invalid lxmf-server config JSON: {}", e))
    }

    fn build(
        config_path: Option<PathBuf>,
        resolved_config_dir: PathBuf,
        server_config_file_path: PathBuf,
        server_config_file_present: bool,
        file_config: ServerConfigFile,
        args: Option<&Args>,
    ) -> Self {
        let lxmd_bin = args
            .and_then(|a| a.get("lxmd-bin").map(PathBuf::from))
            .or_else(|| file_config.lxmd_bin.as_ref().map(PathBuf::from))
            .unwrap_or_else(|| PathBuf::from("lxmd"));

        let lxmd_config_dir = file_config
            .lxmd
            .config_dir
            .as_ref()
            .map(PathBuf::from)
            .unwrap_or_else(|| resolved_config_dir.join("lxmd"));
        let lxmd_rns_config_dir = file_config
            .lxmd
            .rns_config_dir
            .as_ref()
            .map(PathBuf::from)
            .unwrap_or_else(|| resolved_config_dir.join("rns-client"));
        let ready_file = resolved_config_dir.join("run").join("lxmd.ready");

        let http = HttpConfig {
            enabled: if args.map(|a| a.has("no-http")).unwrap_or(false) {
                false
            } else {
                file_config.http.enabled.unwrap_or(true)
            },
            host: args
                .and_then(|a| a.get("http-host").map(str::to_owned))
                .or_else(|| file_config.http.host.clone())
                .unwrap_or_else(|| DEFAULT_HTTP_HOST.into()),
            port: args
                .and_then(|a| a.get("http-port").and_then(|p| p.parse::<u16>().ok()))
                .or(file_config.http.port)
                .unwrap_or(DEFAULT_HTTP_PORT),
            auth_token: args
                .and_then(|a| a.get("http-token").map(str::to_owned))
                .or_else(|| file_config.http.auth_token.clone()),
            disable_auth: if args.map(|a| a.has("disable-auth")).unwrap_or(false) {
                true
            } else {
                file_config.http.disable_auth.unwrap_or(false)
            },
        };

        Self {
            config_path,
            resolved_config_dir,
            server_config_file_path,
            server_config_file_present,
            lxmd_bin,
            lxmd: LxmdRuntimeConfig {
                config_dir: lxmd_config_dir,
                rns_config_dir: lxmd_rns_config_dir,
                propagation_node: file_config.lxmd.propagation_node.unwrap_or(false),
                on_inbound: file_config.lxmd.on_inbound.clone(),
                ready_file,
            },
            rns: RnsRuntimeConfig {
                shared_instance_port: file_config
                    .rns
                    .shared_instance_port
                    .unwrap_or(DEFAULT_RNS_SHARED_PORT),
            },
            http,
            sidecars: file_config.sidecars.clone(),
            file_config,
        }
    }

    fn load_config_file(path: &Path) -> Result<(ServerConfigFile, bool), String> {
        if !path.exists() {
            return Ok((ServerConfigFile::default(), false));
        }
        let content =
            fs::read(path).map_err(|e| format!("failed to read {}: {}", path.display(), e))?;
        Ok((Self::parse_config_json(&content)?, true))
    }

    fn with_file_config(&self, file_config: ServerConfigFile) -> Self {
        Self::build(
            self.config_path.clone(),
            self.resolved_config_dir.clone(),
            self.server_config_file_path.clone(),
            true,
            file_config,
            None,
        )
    }

    fn ensure_runtime_bootstrap(&self) -> Result<(), String> {
        fs::create_dir_all(&self.resolved_config_dir).map_err(|e| {
            format!(
                "failed to create config dir {}: {}",
                self.resolved_config_dir.display(),
                e
            )
        })?;
        fs::create_dir_all(&self.lxmd.config_dir).map_err(|e| {
            format!(
                "failed to create lxmd config dir {}: {}",
                self.lxmd.config_dir.display(),
                e
            )
        })?;
        fs::create_dir_all(&self.lxmd.rns_config_dir).map_err(|e| {
            format!(
                "failed to create RNS client config dir {}: {}",
                self.lxmd.rns_config_dir.display(),
                e
            )
        })?;
        if let Some(parent) = self.lxmd.ready_file.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| format!("failed to create runtime dir {}: {}", parent.display(), e))?;
        }
        self.ensure_rns_client_config()
    }

    fn ensure_rns_client_config(&self) -> Result<(), String> {
        let config_path = self.lxmd.rns_config_dir.join("config");
        if config_path.exists() {
            return Ok(());
        }
        let content = format!(
            "[reticulum]\n\
enable_transport = false\n\
share_instance = false\n\n\
[[RNS Shared Instance]]\n\
type = LocalClientInterface\n\
instance_name = default\n\
port = {}\n",
            self.rns.shared_instance_port
        );
        fs::write(&config_path, content)
            .map_err(|e| format!("failed to write {}: {}", config_path.display(), e))
    }

    fn process_specs(&self) -> Vec<ProcessSpec> {
        let mut specs = vec![ProcessSpec {
            name: "lxmd".into(),
            command: self.lxmd_bin.clone(),
            args: self.lxmd_args(),
            env: HashMap::new(),
            cwd: None,
            restart: true,
            ready_file: Some(self.lxmd.ready_file.clone()),
        }];

        for sidecar in &self.sidecars {
            specs.push(ProcessSpec {
                name: sidecar.name.clone(),
                command: PathBuf::from(&sidecar.bin),
                args: sidecar.args.clone(),
                env: sidecar.env.clone(),
                cwd: sidecar.cwd.as_ref().map(PathBuf::from),
                restart: sidecar.restart,
                ready_file: sidecar.ready_file.as_ref().map(PathBuf::from),
            });
        }
        specs
    }

    fn lxmd_args(&self) -> Vec<String> {
        let mut args = vec![
            "--config".into(),
            self.lxmd.config_dir.display().to_string(),
            "--rnsconfig".into(),
            self.lxmd.rns_config_dir.display().to_string(),
            "--ready-file".into(),
            self.lxmd.ready_file.display().to_string(),
        ];
        if self.lxmd.propagation_node {
            args.push("--propagation-node".into());
        }
        if let Some(on_inbound) = self.lxmd.on_inbound.as_ref() {
            args.push("--on-inbound".into());
            args.push(on_inbound.clone());
        }
        args
    }

    fn supervisor_config(
        &self,
        state: SharedState,
        control_rx: mpsc::Receiver<ProcessControlCommand>,
    ) -> SupervisorConfig {
        SupervisorConfig {
            specs: self.process_specs(),
            state,
            control_rx,
            log_dir: self.resolved_config_dir.join("logs"),
        }
    }

    fn snapshot(&self) -> ConfigSnapshot {
        ConfigSnapshot {
            config_path: self.config_path.as_deref().map(display_path),
            resolved_config_dir: display_path(&self.resolved_config_dir),
            server_config_file_path: display_path(&self.server_config_file_path),
            server_config_file_present: self.server_config_file_present,
            server_config_file_json: serde_json::to_string_pretty(&self.file_config)
                .unwrap_or_else(|_| "{}".into()),
            lxmd_bin: display_path(&self.lxmd_bin),
            lxmd_config_dir: display_path(&self.lxmd.config_dir),
            lxmd_rns_config_dir: display_path(&self.lxmd.rns_config_dir),
            lxmd_ready_file: display_path(&self.lxmd.ready_file),
            rns_shared_instance_port: self.rns.shared_instance_port,
            http: self.http.clone(),
            launch_plan: self
                .process_specs()
                .into_iter()
                .map(|spec| LaunchProcessSnapshot {
                    name: spec.name.clone(),
                    bin: display_path(&spec.command),
                    args: spec.args.clone(),
                    command_line: spec.command_line(),
                })
                .collect(),
        }
    }

    fn validate_json_with_current_context(
        &self,
        body: &[u8],
    ) -> Result<ConfigValidationSnapshot, String> {
        let candidate = Self::parse_config_json(body)?;
        let next = self.with_file_config(candidate);
        Ok(ConfigValidationSnapshot {
            valid: true,
            config: next.snapshot(),
            warnings: vec![format!(
                "Validation used config dir {} and did not write any files.",
                self.resolved_config_dir.display()
            )],
        })
    }

    fn save_json_with_current_context(
        &self,
        body: &[u8],
        apply: bool,
        control_tx: Option<mpsc::Sender<ProcessControlCommand>>,
    ) -> Result<ConfigMutationResult, String> {
        let candidate = Self::parse_config_json(body)?;
        let next = self.with_file_config(candidate.clone());
        fs::create_dir_all(&self.resolved_config_dir).map_err(|e| {
            format!(
                "failed to create config dir {}: {}",
                self.resolved_config_dir.display(),
                e
            )
        })?;
        let serialized = serde_json::to_vec_pretty(&candidate)
            .map_err(|e| format!("failed to serialize lxmf-server config JSON: {}", e))?;
        fs::write(&self.server_config_file_path, serialized).map_err(|e| {
            format!(
                "failed to write {}: {}",
                self.server_config_file_path.display(),
                e
            )
        })?;
        if apply {
            next.ensure_runtime_bootstrap()?;
        }
        let processes_to_restart: Vec<String> =
            next.process_specs().into_iter().map(|s| s.name).collect();
        if apply {
            if let Some(tx) = control_tx {
                tx.send(ProcessControlCommand::Reload {
                    specs: next.process_specs(),
                    config: Box::new(next.snapshot()),
                })
                .map_err(|_| "failed to queue config reload".to_string())?;
            }
        }
        Ok(ConfigMutationResult {
            action: if apply { "apply".into() } else { "save".into() },
            config: next.snapshot(),
            processes_to_restart,
        })
    }
}

fn resolve_config_dir(config_path: Option<&Path>) -> PathBuf {
    if let Some(path) = config_path {
        return path.to_path_buf();
    }
    if let Ok(home) = env::var("HOME") {
        let xdg = PathBuf::from(&home).join(".config").join("lxmf-server");
        return xdg;
    }
    PathBuf::from(".lxmf-server")
}

fn display_path(path: &Path) -> String {
    path.display().to_string()
}

#[derive(Debug, Clone)]
struct ProcessSpec {
    name: String,
    command: PathBuf,
    args: Vec<String>,
    env: HashMap<String, String>,
    cwd: Option<PathBuf>,
    restart: bool,
    ready_file: Option<PathBuf>,
}

impl ProcessSpec {
    fn command_line(&self) -> String {
        let mut parts = vec![self.command.display().to_string()];
        parts.extend(self.args.iter().cloned());
        parts.join(" ")
    }
}

struct SupervisorConfig {
    specs: Vec<ProcessSpec>,
    state: SharedState,
    control_rx: mpsc::Receiver<ProcessControlCommand>,
    log_dir: PathBuf,
}

struct Supervisor {
    specs: Vec<ProcessSpec>,
    state: SharedState,
    control_rx: mpsc::Receiver<ProcessControlCommand>,
    log_dir: PathBuf,
}

struct ManagedChild {
    name: String,
    child: Child,
}

impl Supervisor {
    fn new(config: SupervisorConfig) -> Self {
        Self {
            specs: config.specs,
            state: config.state,
            control_rx: config.control_rx,
            log_dir: config.log_dir,
        }
    }

    fn run_with_started_hook<F>(&self, on_started: F) -> Result<i32, String>
    where
        F: FnOnce() -> Result<(), String>,
    {
        fs::create_dir_all(&self.log_dir)
            .map_err(|e| format!("failed to create log dir {}: {}", self.log_dir.display(), e))?;

        let mut specs = self.specs.clone();
        let mut children = Vec::<ManagedChild>::new();
        for spec in &specs {
            let child = self.spawn(spec)?;
            children.push(child);
            if spec.name == "lxmd" {
                self.wait_for_ready(spec)?;
            }
        }

        on_started()?;
        let stop_rx = install_signal_handlers();

        loop {
            if stop_rx.try_recv().is_ok() {
                log::info!("shutdown requested");
                self.terminate_all(&mut children, &specs);
                return Ok(0);
            }

            if let Ok(command) = self.control_rx.try_recv() {
                self.handle_control_command(command, &mut children, &mut specs)?;
            }

            self.refresh_readiness(&specs);

            if let Some((name, status)) = check_exits(&mut children)? {
                self.record_stopped(&name, status.code());
                let Some(spec) = specs.iter().find(|s| s.name == name) else {
                    continue;
                };
                if spec.restart {
                    self.append_log(&name, "supervisor", "unexpected exit; restarting");
                    let child = self.spawn(spec)?;
                    children.push(child);
                    if spec.name == "lxmd" {
                        self.wait_for_ready(spec)?;
                    }
                    self.bump_restart(&name);
                } else {
                    self.append_log(&name, "supervisor", "unexpected exit; leaving stopped");
                }
            }

            thread::sleep(Duration::from_millis(200));
        }
    }

    fn handle_control_command(
        &self,
        command: ProcessControlCommand,
        children: &mut Vec<ManagedChild>,
        specs: &mut Vec<ProcessSpec>,
    ) -> Result<(), String> {
        match command {
            ProcessControlCommand::Start(name) => self.start_process(&name, children, specs),
            ProcessControlCommand::Stop(name) => self.stop_process(&name, children),
            ProcessControlCommand::Restart(name) => {
                let _ = self.stop_process(&name, children);
                self.start_process(&name, children, specs)
            }
            ProcessControlCommand::Reload {
                specs: next_specs,
                config,
            } => {
                self.terminate_all(children, specs);
                *specs = next_specs;
                {
                    let mut state = self.state.write().unwrap();
                    state.config = Some(*config);
                }
                for spec in specs.iter() {
                    let child = self.spawn(spec)?;
                    children.push(child);
                    if spec.name == "lxmd" {
                        self.wait_for_ready(spec)?;
                    }
                }
                Ok(())
            }
        }
    }

    fn start_process(
        &self,
        name: &str,
        children: &mut Vec<ManagedChild>,
        specs: &[ProcessSpec],
    ) -> Result<(), String> {
        if children.iter().any(|c| c.name == name) {
            return Ok(());
        }
        let spec = specs
            .iter()
            .find(|s| s.name == name)
            .ok_or_else(|| format!("unknown process '{}'", name))?;
        let child = self.spawn(spec)?;
        children.push(child);
        if spec.name == "lxmd" {
            self.wait_for_ready(spec)?;
        }
        Ok(())
    }

    fn stop_process(&self, name: &str, children: &mut Vec<ManagedChild>) -> Result<(), String> {
        if let Some(index) = children.iter().position(|c| c.name == name) {
            let mut child = children.remove(index);
            terminate_child(&mut child.child);
            self.record_stopped(name, None);
        }
        Ok(())
    }

    fn spawn(&self, spec: &ProcessSpec) -> Result<ManagedChild, String> {
        if let Some(ready_file) = &spec.ready_file {
            let _ = fs::remove_file(ready_file);
        }
        let mut command = Command::new(&spec.command);
        command.args(&spec.args);
        command.stdout(Stdio::piped()).stderr(Stdio::piped());
        if let Some(cwd) = &spec.cwd {
            command.current_dir(cwd);
        }
        for (key, value) in &spec.env {
            command.env(key, value);
        }

        let mut child = command
            .spawn()
            .map_err(|e| format!("failed to spawn '{}': {}", spec.name, e))?;
        let pid = child.id();
        self.record_running(spec, pid);

        if let Some(stdout) = child.stdout.take() {
            spawn_log_reader(
                self.state.clone(),
                spec.name.clone(),
                "stdout",
                stdout,
                self.log_dir.join(format!("{}.log", spec.name)),
            );
        }
        if let Some(stderr) = child.stderr.take() {
            spawn_log_reader(
                self.state.clone(),
                spec.name.clone(),
                "stderr",
                stderr,
                self.log_dir.join(format!("{}.log", spec.name)),
            );
        }

        Ok(ManagedChild {
            name: spec.name.clone(),
            child,
        })
    }

    fn wait_for_ready(&self, spec: &ProcessSpec) -> Result<(), String> {
        let Some(ready_file) = spec.ready_file.as_ref() else {
            return Ok(());
        };
        let started = Instant::now();
        while started.elapsed() < LXMD_READY_TIMEOUT {
            self.refresh_readiness(std::slice::from_ref(spec));
            if ready_file.exists() {
                self.record_ready(&spec.name, true);
                return Ok(());
            }
            thread::sleep(Duration::from_millis(100));
        }
        Err(format!(
            "process '{}' did not become ready via {} within {:?}",
            spec.name,
            ready_file.display(),
            LXMD_READY_TIMEOUT
        ))
    }

    fn refresh_readiness(&self, specs: &[ProcessSpec]) {
        for spec in specs {
            if let Some(ready_file) = &spec.ready_file {
                self.record_ready(&spec.name, ready_file.exists());
            }
        }
    }

    fn terminate_all(&self, children: &mut Vec<ManagedChild>, specs: &[ProcessSpec]) {
        let order: Vec<String> = specs.iter().rev().map(|s| s.name.clone()).collect();
        for name in order {
            let _ = self.stop_process(&name, children);
        }
    }

    fn record_running(&self, spec: &ProcessSpec, pid: u32) {
        let mut state = self.state.write().unwrap();
        let entry = state
            .processes
            .entry(spec.name.clone())
            .or_insert_with(|| ProcessState::new(&spec.name, spec.ready_file.is_none()));
        entry.status = "running".into();
        entry.pid = Some(pid);
        entry.exit_code = None;
        entry.started_at_ms = Some(now_ms());
        entry.ready = spec.ready_file.is_none();
        entry.ready_file = spec.ready_file.as_deref().map(display_path);
        entry.command_line = spec.command_line();
    }

    fn record_stopped(&self, name: &str, exit_code: Option<i32>) {
        let mut state = self.state.write().unwrap();
        let entry = state
            .processes
            .entry(name.into())
            .or_insert_with(|| ProcessState::new(name, false));
        entry.status = "stopped".into();
        entry.pid = None;
        entry.ready = false;
        entry.exit_code = exit_code;
    }

    fn record_ready(&self, name: &str, ready: bool) {
        let mut state = self.state.write().unwrap();
        if let Some(entry) = state.processes.get_mut(name) {
            entry.ready = ready;
        }
    }

    fn bump_restart(&self, name: &str) {
        let mut state = self.state.write().unwrap();
        if let Some(entry) = state.processes.get_mut(name) {
            entry.restart_count += 1;
        }
    }

    fn append_log(&self, name: &str, stream: &str, line: &str) {
        append_process_log(&self.state, name, stream, line);
    }
}

fn spawn_log_reader<R: Read + Send + 'static>(
    state: SharedState,
    name: String,
    stream: &'static str,
    reader: R,
    log_path: PathBuf,
) {
    thread::spawn(move || {
        let mut file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)
            .ok();
        let reader = BufReader::new(reader);
        for line in reader.lines().map_while(Result::ok) {
            if let Some(file) = file.as_mut() {
                let _ = writeln!(file, "[{}] {}", stream, line);
            }
            append_process_log(&state, &name, stream, &line);
            let mut guard = state.write().unwrap();
            if let Some(process) = guard.processes.get_mut(&name) {
                process.log_path = Some(display_path(&log_path));
            }
        }
    });
}

fn append_process_log(state: &SharedState, name: &str, stream: &str, line: &str) {
    let mut guard = state.write().unwrap();
    let entry = guard
        .processes
        .entry(name.into())
        .or_insert_with(|| ProcessState::new(name, false));
    if entry.logs.len() >= MAX_LOG_LINES {
        entry.logs.pop_front();
    }
    entry.logs.push_back(LogLine {
        ts_ms: now_ms(),
        stream: stream.into(),
        line: line.into(),
    });
}

fn check_exits(children: &mut Vec<ManagedChild>) -> Result<Option<(String, ExitStatus)>, String> {
    let mut exited = None;
    let mut index = 0;
    while index < children.len() {
        match children[index].child.try_wait() {
            Ok(Some(status)) => {
                let child = children.remove(index);
                exited = Some((child.name, status));
                break;
            }
            Ok(None) => index += 1,
            Err(e) => return Err(format!("failed to poll child: {}", e)),
        }
    }
    Ok(exited)
}

fn terminate_child(child: &mut Child) {
    #[cfg(unix)]
    unsafe {
        libc::kill(child.id() as i32, libc::SIGTERM);
    }
    let started = Instant::now();
    while started.elapsed() < Duration::from_secs(5) {
        if child.try_wait().ok().flatten().is_some() {
            return;
        }
        thread::sleep(Duration::from_millis(100));
    }
    let _ = child.kill();
    let _ = child.wait();
}

fn install_signal_handlers() -> mpsc::Receiver<()> {
    static SIGNAL_RECEIVED: AtomicBool = AtomicBool::new(false);
    let (tx, rx) = mpsc::channel();

    #[cfg(unix)]
    {
        extern "C" fn handler(_sig: i32) {
            SIGNAL_RECEIVED.store(true, Ordering::Relaxed);
        }
        unsafe {
            libc::signal(libc::SIGINT, handler as *const () as usize);
            libc::signal(libc::SIGTERM, handler as *const () as usize);
        }
    }

    thread::spawn(move || {
        while !SIGNAL_RECEIVED.load(Ordering::Relaxed) {
            thread::sleep(Duration::from_millis(100));
        }
        let _ = tx.send(());
    });
    rx
}

#[derive(Debug)]
enum ProcessControlCommand {
    Start(String),
    Stop(String),
    Restart(String),
    Reload {
        specs: Vec<ProcessSpec>,
        config: Box<ConfigSnapshot>,
    },
}

type SharedState = Arc<RwLock<ServerState>>;

#[derive(Debug, Default)]
struct ServerState {
    processes: HashMap<String, ProcessState>,
    config: Option<ConfigSnapshot>,
}

#[derive(Debug, Clone, Serialize)]
struct ProcessState {
    name: String,
    status: String,
    pid: Option<u32>,
    ready: bool,
    ready_file: Option<String>,
    command_line: String,
    restart_count: usize,
    exit_code: Option<i32>,
    started_at_ms: Option<u128>,
    log_path: Option<String>,
    #[serde(skip)]
    logs: VecDeque<LogLine>,
}

impl ProcessState {
    fn new(name: &str, ready: bool) -> Self {
        Self {
            name: name.into(),
            status: "stopped".into(),
            pid: None,
            ready,
            ready_file: None,
            command_line: String::new(),
            restart_count: 0,
            exit_code: None,
            started_at_ms: None,
            log_path: None,
            logs: VecDeque::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
struct LogLine {
    ts_ms: u128,
    stream: String,
    line: String,
}

#[derive(Debug, Clone, Serialize)]
struct ConfigSnapshot {
    config_path: Option<String>,
    resolved_config_dir: String,
    server_config_file_path: String,
    server_config_file_present: bool,
    server_config_file_json: String,
    lxmd_bin: String,
    lxmd_config_dir: String,
    lxmd_rns_config_dir: String,
    lxmd_ready_file: String,
    rns_shared_instance_port: u16,
    http: HttpConfig,
    launch_plan: Vec<LaunchProcessSnapshot>,
}

#[derive(Debug, Clone, Serialize)]
struct LaunchProcessSnapshot {
    name: String,
    bin: String,
    args: Vec<String>,
    command_line: String,
}

#[derive(Debug, Serialize)]
struct ConfigValidationSnapshot {
    valid: bool,
    config: ConfigSnapshot,
    warnings: Vec<String>,
}

#[derive(Debug, Serialize)]
struct ConfigMutationResult {
    action: String,
    config: ConfigSnapshot,
    processes_to_restart: Vec<String>,
}

fn now_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

fn start_http(
    config: &ServerConfig,
    state: SharedState,
    control_tx: mpsc::Sender<ProcessControlCommand>,
) -> Result<(), String> {
    let listener =
        TcpListener::bind((config.http.host.as_str(), config.http.port)).map_err(|e| {
            format!(
                "failed to bind embedded control plane {}:{}: {}",
                config.http.host, config.http.port, e
            )
        })?;
    let ctx = HttpContext {
        config: config.clone(),
        state,
        control_tx,
    };

    thread::Builder::new()
        .name("lxmf-server-http".into())
        .spawn(move || {
            for stream in listener.incoming() {
                match stream {
                    Ok(stream) => {
                        let ctx = ctx.clone();
                        thread::spawn(move || {
                            if let Err(e) = handle_http_connection(stream, ctx) {
                                log::warn!("control HTTP connection failed: {}", e);
                            }
                        });
                    }
                    Err(e) => log::warn!("control HTTP accept failed: {}", e),
                }
            }
        })
        .map_err(|e| format!("failed to spawn control HTTP thread: {}", e))?;
    Ok(())
}

#[derive(Clone)]
struct HttpContext {
    config: ServerConfig,
    state: SharedState,
    control_tx: mpsc::Sender<ProcessControlCommand>,
}

fn handle_http_connection(mut stream: TcpStream, ctx: HttpContext) -> io::Result<()> {
    let request = parse_request(&mut stream)?;
    let response = route_request(request, ctx);
    write_response(&mut stream, &response)
}

fn route_request(request: HttpRequest, ctx: HttpContext) -> HttpResponse {
    if request.path.starts_with("/api/") && !authorized(&request, &ctx.config.http) {
        return HttpResponse::unauthorized("missing or invalid bearer token");
    }

    match (request.method.as_str(), request.path.as_str()) {
        ("GET", "/healthz") => HttpResponse::ok(serde_json::json!({"status": "ok"})),
        ("GET", "/readyz") => {
            let ready = all_processes_ready(&ctx.state);
            HttpResponse::json(
                if ready { 200 } else { 503 },
                if ready { "OK" } else { "Service Unavailable" },
                &serde_json::json!({"ready": ready}),
            )
        }
        ("GET", "/api/info") => {
            let state = ctx.state.read().unwrap();
            HttpResponse::ok(serde_json::json!({
                "name": "lxmf-server",
                "version": VERSION,
                "config": state.config,
            }))
        }
        ("GET", "/api/processes") => {
            let state = ctx.state.read().unwrap();
            let mut processes: Vec<_> = state.processes.values().cloned().collect();
            processes.sort_by(|a, b| a.name.cmp(&b.name));
            HttpResponse::ok(serde_json::json!({ "processes": processes }))
        }
        ("GET", "/api/diagnostics") => HttpResponse::ok(serde_json::json!(diagnostics(&ctx))),
        ("GET", "/api/config") => {
            let state = ctx.state.read().unwrap();
            HttpResponse::ok(serde_json::json!({ "config": state.config }))
        }
        ("GET", "/api/config/schema") => HttpResponse::ok(config_schema()),
        ("POST", "/api/config/validate") => {
            match ctx.config.validate_json_with_current_context(&request.body) {
                Ok(snapshot) => HttpResponse::ok(serde_json::json!(snapshot)),
                Err(err) => HttpResponse::bad_request(&err),
            }
        }
        ("POST", "/api/config/save") => {
            match ctx
                .config
                .save_json_with_current_context(&request.body, false, None)
            {
                Ok(result) => HttpResponse::ok(serde_json::json!(result)),
                Err(err) => HttpResponse::bad_request(&err),
            }
        }
        ("POST", "/api/config/apply") => match ctx.config.save_json_with_current_context(
            &request.body,
            true,
            Some(ctx.control_tx.clone()),
        ) {
            Ok(result) => HttpResponse::ok(serde_json::json!(result)),
            Err(err) => HttpResponse::bad_request(&err),
        },
        _ => route_process_request(request, ctx),
    }
}

fn route_process_request(request: HttpRequest, ctx: HttpContext) -> HttpResponse {
    let Some(rest) = request.path.strip_prefix("/api/processes/") else {
        return HttpResponse::not_found();
    };
    let mut parts = rest.split('/');
    let Some(name) = parts.next() else {
        return HttpResponse::not_found();
    };
    let action = parts.next().unwrap_or("");

    match (request.method.as_str(), action) {
        ("GET", "logs") => {
            let tail = parse_query(&request.query)
                .get("tail")
                .and_then(|v| v.parse::<usize>().ok())
                .unwrap_or(100);
            let state = ctx.state.read().unwrap();
            let Some(process) = state.processes.get(name) else {
                return HttpResponse::not_found();
            };
            let logs: Vec<_> = process
                .logs
                .iter()
                .rev()
                .take(tail)
                .cloned()
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .collect();
            HttpResponse::ok(serde_json::json!({ "name": name, "logs": logs }))
        }
        ("POST", "start") => {
            if !process_exists(&ctx.state, name) {
                return HttpResponse::not_found();
            }
            send_process_command(ctx.control_tx, ProcessControlCommand::Start(name.into()))
        }
        ("POST", "stop") => {
            if !process_exists(&ctx.state, name) {
                return HttpResponse::not_found();
            }
            send_process_command(ctx.control_tx, ProcessControlCommand::Stop(name.into()))
        }
        ("POST", "restart") => {
            if !process_exists(&ctx.state, name) {
                return HttpResponse::not_found();
            }
            send_process_command(ctx.control_tx, ProcessControlCommand::Restart(name.into()))
        }
        _ => HttpResponse::not_found(),
    }
}

fn process_exists(state: &SharedState, name: &str) -> bool {
    state.read().unwrap().processes.contains_key(name)
}

fn send_process_command(
    tx: mpsc::Sender<ProcessControlCommand>,
    command: ProcessControlCommand,
) -> HttpResponse {
    match tx.send(command) {
        Ok(()) => HttpResponse::ok(serde_json::json!({"queued": true})),
        Err(_) => HttpResponse::internal_error("supervisor control channel is closed"),
    }
}

fn diagnostics(ctx: &HttpContext) -> DiagnosticsSnapshot {
    let state = ctx.state.read().unwrap();
    let mut processes: Vec<_> = state.processes.values().cloned().collect();
    processes.sort_by(|a, b| a.name.cmp(&b.name));
    let lxmd_process = state.processes.get("lxmd").cloned();
    let recent_logs = lxmd_process
        .as_ref()
        .map(|p| p.logs.iter().cloned().collect::<Vec<_>>())
        .unwrap_or_default();
    drop(state);

    let lxmd = LxmdDiagnostics::from_config(&ctx.config, &recent_logs);
    let mut checks = Vec::new();
    let lxmd_ready = lxmd_process
        .as_ref()
        .map(|p| p.status == "running" && p.ready)
        .unwrap_or(false);
    checks.push(DiagnosticCheck::new(
        "lxmd_process_ready",
        lxmd_ready,
        if lxmd_ready {
            "lxmd is running and its ready marker is present".into()
        } else {
            "lxmd is missing, stopped, or not ready".into()
        },
    ));

    let rns_error_free = lxmd.recent_logs.rns_shared_instance_errors == 0;
    checks.push(DiagnosticCheck::new(
        "recent_rns_shared_instance_errors",
        rns_error_free,
        if rns_error_free {
            "no recent shared-instance connection errors in buffered lxmd logs".into()
        } else {
            format!(
                "{} recent shared-instance connection error(s); last: {}",
                lxmd.recent_logs.rns_shared_instance_errors,
                lxmd.recent_logs
                    .last_rns_shared_instance_error
                    .as_deref()
                    .unwrap_or("unknown")
            )
        },
    ));

    checks.push(DiagnosticCheck::new(
        "lxmf_messagestore_accessible",
        lxmd.storage.messagestore.exists,
        format!(
            "{} files, {} bytes in {}",
            lxmd.storage.messagestore.file_count,
            lxmd.storage.messagestore.total_bytes,
            lxmd.storage.messagestore.path
        ),
    ));

    checks.push(DiagnosticCheck::new(
        "lxmf_peer_store_has_entries",
        lxmd.storage.peers.bytes > 1,
        format!(
            "{} bytes in {}",
            lxmd.storage.peers.bytes, lxmd.storage.peers.path
        ),
    ));

    let healthy = checks.iter().all(|c| c.ok);
    let status = if healthy {
        "healthy"
    } else if lxmd_ready {
        "degraded"
    } else {
        "unhealthy"
    };

    DiagnosticsSnapshot {
        status: status.into(),
        generated_at_ms: now_ms(),
        checks,
        processes,
        lxmd,
    }
}

#[derive(Debug, Serialize)]
struct DiagnosticsSnapshot {
    status: String,
    generated_at_ms: u128,
    checks: Vec<DiagnosticCheck>,
    processes: Vec<ProcessState>,
    lxmd: LxmdDiagnostics,
}

#[derive(Debug, Serialize)]
struct DiagnosticCheck {
    name: String,
    ok: bool,
    detail: String,
}

impl DiagnosticCheck {
    fn new(name: &str, ok: bool, detail: String) -> Self {
        Self {
            name: name.into(),
            ok,
            detail,
        }
    }
}

#[derive(Debug, Serialize)]
struct LxmdDiagnostics {
    config_dir: String,
    rns_config_dir: String,
    ready_file: FileSnapshot,
    config_file: FileSnapshot,
    identity_file: FileSnapshot,
    storage: LxmfStorageDiagnostics,
    recent_logs: LxmdLogSignals,
}

impl LxmdDiagnostics {
    fn from_config(config: &ServerConfig, logs: &[LogLine]) -> Self {
        let config_dir = config.lxmd.config_dir.clone();
        let storage_root = config_dir.join("storage").join("lxmf");
        Self {
            config_dir: display_path(&config_dir),
            rns_config_dir: display_path(&config.lxmd.rns_config_dir),
            ready_file: FileSnapshot::from_path(&config.lxmd.ready_file),
            config_file: FileSnapshot::from_path(&config_dir.join("config")),
            identity_file: FileSnapshot::from_path(&config_dir.join("identity")),
            storage: LxmfStorageDiagnostics {
                base: DirectorySnapshot::from_path(&storage_root),
                messagestore: DirectorySnapshot::from_path(&storage_root.join("messagestore")),
                peers: FileSnapshot::from_path(&storage_root.join("peers")),
                local_deliveries: FileSnapshot::from_path(&storage_root.join("local_deliveries")),
                locally_processed: FileSnapshot::from_path(&storage_root.join("locally_processed")),
                outbound_stamp_costs: FileSnapshot::from_path(
                    &storage_root.join("outbound_stamp_costs"),
                ),
                node_stats: FileSnapshot::from_path(&storage_root.join("node_stats")),
            },
            recent_logs: LxmdLogSignals::from_logs(logs),
        }
    }
}

#[derive(Debug, Serialize)]
struct LxmfStorageDiagnostics {
    base: DirectorySnapshot,
    messagestore: DirectorySnapshot,
    peers: FileSnapshot,
    local_deliveries: FileSnapshot,
    locally_processed: FileSnapshot,
    outbound_stamp_costs: FileSnapshot,
    node_stats: FileSnapshot,
}

#[derive(Debug, Serialize)]
struct DirectorySnapshot {
    path: String,
    exists: bool,
    file_count: u64,
    total_bytes: u64,
    newest_mtime_ms: Option<u128>,
}

impl DirectorySnapshot {
    fn from_path(path: &Path) -> Self {
        let mut snapshot = Self {
            path: display_path(path),
            exists: path.is_dir(),
            file_count: 0,
            total_bytes: 0,
            newest_mtime_ms: None,
        };
        let Ok(entries) = fs::read_dir(path) else {
            return snapshot;
        };
        for entry in entries.flatten() {
            let Ok(metadata) = entry.metadata() else {
                continue;
            };
            if !metadata.is_file() {
                continue;
            }
            snapshot.file_count += 1;
            snapshot.total_bytes = snapshot.total_bytes.saturating_add(metadata.len());
            if let Some(ms) = modified_ms(&metadata) {
                snapshot.newest_mtime_ms = Some(snapshot.newest_mtime_ms.unwrap_or(0).max(ms));
            }
        }
        snapshot
    }
}

#[derive(Debug, Serialize)]
struct FileSnapshot {
    path: String,
    exists: bool,
    bytes: u64,
    modified_ms: Option<u128>,
}

impl FileSnapshot {
    fn from_path(path: &Path) -> Self {
        let metadata = path.metadata().ok();
        Self {
            path: display_path(path),
            exists: metadata.as_ref().map(|m| m.is_file()).unwrap_or(false),
            bytes: metadata.as_ref().map(|m| m.len()).unwrap_or(0),
            modified_ms: metadata.as_ref().and_then(modified_ms),
        }
    }
}

fn modified_ms(metadata: &Metadata) -> Option<u128> {
    metadata
        .modified()
        .ok()?
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|duration| duration.as_millis())
}

#[derive(Debug, Serialize)]
struct LxmdLogSignals {
    buffered_lines: usize,
    rns_shared_instance_connected: bool,
    rns_shared_instance_errors: usize,
    delivery_events: usize,
    inbound_message_events: usize,
    propagation_events: usize,
    peer_events: usize,
    error_events: usize,
    warning_events: usize,
    last_rns_shared_instance_error: Option<String>,
    last_delivery_event: Option<String>,
    last_propagation_event: Option<String>,
    last_error_event: Option<String>,
}

impl LxmdLogSignals {
    fn from_logs(logs: &[LogLine]) -> Self {
        let mut signals = Self {
            buffered_lines: logs.len(),
            rns_shared_instance_connected: false,
            rns_shared_instance_errors: 0,
            delivery_events: 0,
            inbound_message_events: 0,
            propagation_events: 0,
            peer_events: 0,
            error_events: 0,
            warning_events: 0,
            last_rns_shared_instance_error: None,
            last_delivery_event: None,
            last_propagation_event: None,
            last_error_event: None,
        };
        for log in logs {
            let lower = log.line.to_lowercase();
            let formatted = format!("{} {}", log.stream, log.line);
            if lower.contains("shared instance") && lower.contains("connected") {
                signals.rns_shared_instance_connected = true;
            }
            if lower.contains("shared instance")
                && (lower.contains("failed") || lower.contains("refused"))
            {
                signals.rns_shared_instance_errors += 1;
                signals.last_rns_shared_instance_error = Some(formatted.clone());
            }
            if lower.contains("deliver") {
                signals.delivery_events += 1;
                signals.last_delivery_event = Some(formatted.clone());
            }
            if lower.contains("inbound") || lower.contains("received") {
                signals.inbound_message_events += 1;
            }
            if lower.contains("propagation") {
                signals.propagation_events += 1;
                signals.last_propagation_event = Some(formatted.clone());
            }
            if lower.contains("peer") {
                signals.peer_events += 1;
            }
            if lower.contains("error") || lower.contains("failed") {
                signals.error_events += 1;
                signals.last_error_event = Some(formatted.clone());
            }
            if lower.contains("warn") {
                signals.warning_events += 1;
            }
        }
        signals
    }
}

fn authorized(request: &HttpRequest, config: &HttpConfig) -> bool {
    if config.disable_auth {
        return true;
    }
    let Some(token) = config.auth_token.as_ref() else {
        return false;
    };
    request
        .headers
        .get("authorization")
        .map(|value| value == &format!("Bearer {}", token))
        .unwrap_or(false)
}

fn all_processes_ready(state: &SharedState) -> bool {
    let guard = state.read().unwrap();
    !guard.processes.is_empty()
        && guard
            .processes
            .values()
            .all(|p| p.status == "running" && p.ready)
}

fn config_schema() -> serde_json::Value {
    serde_json::json!({
        "type": "object",
        "properties": {
            "lxmd_bin": {"type": "string"},
            "lxmd": {
                "type": "object",
                "properties": {
                    "config_dir": {"type": "string"},
                    "rns_config_dir": {"type": "string"},
                    "propagation_node": {"type": "boolean"},
                    "on_inbound": {"type": "string"}
                }
            },
            "rns": {
                "type": "object",
                "properties": {
                    "shared_instance_port": {"type": "integer", "default": DEFAULT_RNS_SHARED_PORT}
                }
            },
            "http": {
                "type": "object",
                "properties": {
                    "enabled": {"type": "boolean"},
                    "host": {"type": "string"},
                    "port": {"type": "integer"},
                    "auth_token": {"type": "string"},
                    "disable_auth": {"type": "boolean"}
                }
            },
            "sidecars": {
                "type": "array",
                "items": {
                    "type": "object",
                    "required": ["name", "bin"],
                    "properties": {
                        "name": {"type": "string"},
                        "bin": {"type": "string"},
                        "args": {"type": "array", "items": {"type": "string"}},
                        "env": {"type": "object"},
                        "cwd": {"type": "string"},
                        "restart": {"type": "boolean"},
                        "ready_file": {"type": "string"}
                    }
                }
            }
        }
    })
}

#[derive(Debug)]
struct HttpRequest {
    method: String,
    path: String,
    query: String,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

struct HttpResponse {
    status: u16,
    status_text: &'static str,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl HttpResponse {
    fn json(status: u16, status_text: &'static str, body: &serde_json::Value) -> Self {
        let body = serde_json::to_vec(body).unwrap_or_default();
        Self {
            status,
            status_text,
            headers: vec![
                ("Content-Type".into(), "application/json".into()),
                ("Content-Length".into(), body.len().to_string()),
                ("Connection".into(), "close".into()),
            ],
            body,
        }
    }

    fn ok(body: serde_json::Value) -> Self {
        Self::json(200, "OK", &body)
    }

    fn bad_request(msg: &str) -> Self {
        Self::json(400, "Bad Request", &serde_json::json!({"error": msg}))
    }

    fn unauthorized(msg: &str) -> Self {
        Self::json(401, "Unauthorized", &serde_json::json!({"error": msg}))
    }

    fn not_found() -> Self {
        Self::json(404, "Not Found", &serde_json::json!({"error": "not found"}))
    }

    fn internal_error(msg: &str) -> Self {
        Self::json(
            500,
            "Internal Server Error",
            &serde_json::json!({"error": msg}),
        )
    }
}

fn parse_request(stream: &mut dyn Read) -> io::Result<HttpRequest> {
    let mut reader = BufReader::new(stream);
    let mut request_line = String::new();
    reader.read_line(&mut request_line)?;
    let request_line = request_line.trim_end();
    let parts: Vec<&str> = request_line.splitn(3, ' ').collect();
    if parts.len() < 2 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid request line",
        ));
    }

    let (path, query) = if let Some(pos) = parts[1].find('?') {
        (parts[1][..pos].to_string(), parts[1][pos + 1..].to_string())
    } else {
        (parts[1].to_string(), String::new())
    };

    let mut headers = HashMap::new();
    loop {
        let mut line = String::new();
        reader.read_line(&mut line)?;
        let line = line.trim_end();
        if line.is_empty() {
            break;
        }
        if let Some((key, value)) = line.split_once(':') {
            headers.insert(key.trim().to_lowercase(), value.trim().to_string());
        }
    }

    let body = if let Some(len) = headers
        .get("content-length")
        .and_then(|value| value.parse::<usize>().ok())
    {
        let mut body = vec![0; len];
        reader.read_exact(&mut body)?;
        body
    } else {
        Vec::new()
    };

    Ok(HttpRequest {
        method: parts[0].into(),
        path,
        query,
        headers,
        body,
    })
}

fn write_response(stream: &mut dyn Write, response: &HttpResponse) -> io::Result<()> {
    write!(
        stream,
        "HTTP/1.1 {} {}\r\n",
        response.status, response.status_text
    )?;
    for (key, value) in &response.headers {
        write!(stream, "{}: {}\r\n", key, value)?;
    }
    write!(stream, "\r\n")?;
    stream.write_all(&response.body)?;
    stream.flush()
}

fn parse_query(query: &str) -> HashMap<String, String> {
    let mut params = HashMap::new();
    for pair in query.split('&').filter(|p| !p.is_empty()) {
        if let Some((key, value)) = pair.split_once('=') {
            params.insert(key.to_string(), value.to_string());
        } else {
            params.insert(pair.to_string(), String::new());
        }
    }
    params
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(prefix: &str) -> PathBuf {
        env::temp_dir().join(format!(
            "{}-{}",
            prefix,
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    #[test]
    fn config_defaults_build_lxmd_launch_plan() {
        let dir = temp_dir("lxmf-server-config-defaults");
        let args = Args::parse_from(["start", "--config", dir.to_str().unwrap()]);
        let config = ServerConfig::from_args(&args);
        let specs = config.process_specs();

        assert_eq!(specs.len(), 1);
        assert_eq!(specs[0].name, "lxmd");
        assert!(specs[0].args.contains(&"--config".to_string()));
        assert!(specs[0].args.contains(&"--rnsconfig".to_string()));
        assert!(specs[0].args.contains(&"--ready-file".to_string()));
        assert_eq!(config.http.port, DEFAULT_HTTP_PORT);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn rns_client_config_generation_points_to_shared_instance() {
        let dir = temp_dir("lxmf-server-rns-config");
        let args = Args::parse_from(["start", "--config", dir.to_str().unwrap()]);
        let config = ServerConfig::from_args(&args);

        config.ensure_runtime_bootstrap().unwrap();

        let content = fs::read_to_string(config.lxmd.rns_config_dir.join("config")).unwrap();
        assert!(content.contains("LocalClientInterface"));
        assert!(content.contains("port = 37428"));
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn parse_config_rejects_unknown_fields() {
        let err = ServerConfig::parse_config_json(br#"{"unexpected": true}"#).unwrap_err();
        assert!(err.contains("unknown field"));
    }

    #[test]
    fn http_auth_requires_bearer_token() {
        let cfg = HttpConfig {
            enabled: true,
            host: DEFAULT_HTTP_HOST.into(),
            port: DEFAULT_HTTP_PORT,
            auth_token: Some("secret".into()),
            disable_auth: false,
        };
        let mut request = HttpRequest {
            method: "GET".into(),
            path: "/api/info".into(),
            query: String::new(),
            headers: HashMap::new(),
            body: Vec::new(),
        };
        assert!(!authorized(&request, &cfg));
        request
            .headers
            .insert("authorization".into(), "Bearer secret".into());
        assert!(authorized(&request, &cfg));
    }

    #[test]
    fn parse_request_with_query_and_body() {
        let raw = b"POST /api/config/validate?x=1 HTTP/1.1\r\nContent-Length: 2\r\n\r\n{}";
        let req = parse_request(&mut &raw[..]).unwrap();
        assert_eq!(req.method, "POST");
        assert_eq!(req.path, "/api/config/validate");
        assert_eq!(req.query, "x=1");
        assert_eq!(req.body, b"{}");
    }

    #[test]
    fn process_command_for_unknown_process_returns_404_without_queueing() {
        let mut config = ServerConfig::from_args(&Args::parse_from(["start"]));
        config.http.disable_auth = true;
        let state = SharedState::default();
        state
            .write()
            .unwrap()
            .processes
            .insert("lxmd".into(), ProcessState::new("lxmd", true));
        let (tx, rx) = mpsc::channel();
        let ctx = HttpContext {
            config,
            state,
            control_tx: tx,
        };
        let request = HttpRequest {
            method: "POST".into(),
            path: "/api/processes/does-not-exist/restart".into(),
            query: String::new(),
            headers: HashMap::new(),
            body: Vec::new(),
        };

        let response = route_request(request, ctx);

        assert_eq!(response.status, 404);
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn diagnostics_endpoint_reports_lxmd_storage_and_logs() {
        let dir = temp_dir("lxmf-server-diagnostics");
        let args = Args::parse_from(["start", "--config", dir.to_str().unwrap()]);
        let mut config = ServerConfig::from_args(&args);
        config.http.disable_auth = true;
        config.ensure_runtime_bootstrap().unwrap();

        let storage_root = config.lxmd.config_dir.join("storage").join("lxmf");
        fs::create_dir_all(storage_root.join("messagestore")).unwrap();
        fs::write(
            storage_root.join("messagestore").join("message-1"),
            b"hello",
        )
        .unwrap();
        fs::write(storage_root.join("peers"), [0x91, 0x80]).unwrap();
        fs::write(&config.lxmd.ready_file, b"ready").unwrap();

        let state = SharedState::default();
        let mut process = ProcessState::new("lxmd", false);
        process.status = "running".into();
        process.ready = true;
        process.logs.push_back(LogLine {
            ts_ms: 1,
            stream: "stderr".into(),
            line: "[Local shared instance] Connected to shared instance via Unix socket".into(),
        });
        state
            .write()
            .unwrap()
            .processes
            .insert("lxmd".into(), process);
        let (tx, _rx) = mpsc::channel();
        let ctx = HttpContext {
            config,
            state,
            control_tx: tx,
        };
        let request = HttpRequest {
            method: "GET".into(),
            path: "/api/diagnostics".into(),
            query: String::new(),
            headers: HashMap::new(),
            body: Vec::new(),
        };

        let response = route_request(request, ctx);
        let body: serde_json::Value = serde_json::from_slice(&response.body).unwrap();

        assert_eq!(response.status, 200);
        assert_eq!(body["status"], "healthy");
        assert_eq!(body["lxmd"]["storage"]["messagestore"]["file_count"], 1);
        assert_eq!(body["lxmd"]["storage"]["peers"]["bytes"], 2);
        assert_eq!(
            body["lxmd"]["recent_logs"]["rns_shared_instance_connected"],
            true
        );
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn config_apply_queues_live_reload() {
        let dir = temp_dir("lxmf-server-apply");
        let args = Args::parse_from(["start", "--config", dir.to_str().unwrap()]);
        let config = ServerConfig::from_args(&args);
        let (tx, rx) = mpsc::channel();

        let result = config
            .save_json_with_current_context(
                br#"{"lxmd_bin":"/bin/echo","http":{"disable_auth":true}}"#,
                true,
                Some(tx),
            )
            .unwrap();

        assert_eq!(result.action, "apply");
        match rx.try_recv().unwrap() {
            ProcessControlCommand::Reload { specs, config } => {
                assert_eq!(specs[0].command, PathBuf::from("/bin/echo"));
                assert_eq!(config.lxmd_bin, "/bin/echo");
            }
            other => panic!("unexpected command: {:?}", other),
        }
        let _ = fs::remove_dir_all(dir);
    }
}
