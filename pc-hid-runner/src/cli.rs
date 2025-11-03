use std::{
    fs::{self, OpenOptions},
    io,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    process, thread,
    time::{Duration, Instant},
};

use authenticator::ctap::PqcPolicy;
use clap::{Args, Parser, Subcommand, ValueEnum};
use clap_num::maybe_hex;
use daemonize::Daemonize;
use nix::unistd::{self, Gid, Group};
use nix::{
    errno::Errno,
    sys::signal::{self, Signal},
    unistd::Pid,
};
use transport_core::state::default_state_dir;

use crate::{
    gadget::{GadgetConfig, HID_DEVICE_NODE},
    permissions, service, HidDeviceDescriptor, Options,
};

#[derive(Parser, Debug)]
#[clap(
    about = "Feitian ML-DSA authenticator service controller",
    version,
    author
)]
pub struct Cli {
    #[clap(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Start the authenticator service
    Start(StartCommand),
    /// Stop a running authenticator service
    Stop(StateArgs),
    /// Show service status
    Status(StateArgs),
}

#[derive(Args, Debug, Clone)]
pub struct StartCommand {
    #[clap(flatten)]
    device: DeviceArgs,
    #[clap(flatten)]
    state: StateArgs,
    /// Run in the foreground (useful for systemd integration)
    #[clap(long)]
    pub foreground: bool,
}

#[derive(Args, Debug, Clone)]
pub struct StateArgs {
    /// Directory where persistent Trussed state and pid files are stored
    #[clap(long, value_parser, default_value_os_t = default_state_dir())]
    pub state_dir: PathBuf,
}

#[derive(Args, Debug, Clone)]
pub struct DeviceArgs {
    /// HID product name
    #[clap(long, default_value = "Feitian FIDO2 Software Authenticator (ML-DSA)")]
    pub name: String,
    /// USB manufacturer string used by Trussed
    #[clap(long, default_value = "Feitian Technologies Co., Ltd.")]
    pub manufacturer: String,
    /// USB product string used by Trussed
    #[clap(long, default_value = "Feitian FIDO2 Software Authenticator (ML-DSA)")]
    pub product: String,
    /// USB serial number string used by Trussed
    #[clap(long, default_value = "FEITIAN-PQC-001")]
    pub serial: String,
    /// Vendor ID for the virtual HID device
    #[clap(long, value_parser = maybe_hex::<u32>, default_value_t = 0x096e)]
    pub vendor_id: u32,
    /// Product ID for the virtual HID device
    #[clap(long, value_parser = maybe_hex::<u32>, default_value_t = 0x0858)]
    pub product_id: u32,
    /// Version reported by the HID descriptor
    #[clap(long, value_parser = maybe_hex::<u32>, default_value_t = 0x0001)]
    pub version: u32,
    /// USB VID presented by Trussed (for legacy tooling)
    #[clap(short, long, value_parser = maybe_hex::<u16>, default_value_t = 0x1998)]
    pub vid: u16,
    /// USB PID presented by Trussed (for legacy tooling)
    #[clap(short, long, value_parser = maybe_hex::<u16>, default_value_t = 0x0616)]
    pub pid: u16,
    /// Authenticator AAGUID
    #[clap(long, default_value = "4645495449414E980616525A30310000")]
    pub aaguid: String,
    /// Policy controlling whether PQC PIN/UV is preferred, required, or disabled
    #[clap(long, value_enum, default_value_t = PqcPolicyArg::Prefer)]
    pub pqc_policy: PqcPolicyArg,
    /// Backend transport to use
    #[clap(long, value_enum, default_value_t = BackendArg::Gadget)]
    pub backend: BackendArg,
    #[clap(flatten)]
    pub gadget: GadgetArgs,
}

#[derive(Args, Debug, Clone)]
pub struct GadgetArgs {
    /// Path to the configfs USB gadget root
    #[clap(long, default_value = "/sys/kernel/config/usb_gadget")]
    pub gadget_root: PathBuf,
    /// Name for the gadget created under configfs
    #[clap(long, default_value = "feitian-pqc-authenticator")]
    pub gadget_name: String,
    /// USB device controller to bind (defaults to the first available)
    #[clap(long)]
    pub gadget_udc: Option<String>,
    /// Max power in mA advertised by the configuration descriptor
    #[clap(long, default_value_t = 100)]
    pub gadget_max_power_ma: u16,
    /// USB specification version (bcdUSB, hex)
    #[clap(long, value_parser = maybe_hex::<u16>, default_value_t = 0x0200)]
    pub gadget_usb_version: u16,
}

#[derive(Copy, Clone, Debug, ValueEnum, PartialEq, Eq)]
pub enum BackendArg {
    Uhid,
    Gadget,
    #[cfg(feature = "usbip-backend")]
    Usbip,
}

#[derive(Copy, Clone, Debug, ValueEnum, PartialEq, Eq)]
pub enum PqcPolicyArg {
    Prefer,
    ClassicOnly,
    Require,
}

impl From<PqcPolicyArg> for PqcPolicy {
    fn from(value: PqcPolicyArg) -> Self {
        match value {
            PqcPolicyArg::Prefer => PqcPolicy::PreferPqc,
            PqcPolicyArg::ClassicOnly => PqcPolicy::ClassicOnly,
            PqcPolicyArg::Require => PqcPolicy::RequirePqc,
        }
    }
}

impl BackendArg {
    fn into_backend(self) -> service::Backend {
        match self {
            BackendArg::Uhid => service::Backend::Uhid,
            BackendArg::Gadget => service::Backend::Gadget,
            #[cfg(feature = "usbip-backend")]
            BackendArg::Usbip => service::Backend::Usbip,
        }
    }
}

impl StateArgs {
    fn pid_path(&self) -> PathBuf {
        self.state_dir.join("authenticator.pid")
    }
}

impl StartCommand {
    fn to_runner_config(&self) -> Result<service::RunnerConfig, String> {
        let aaguid = service::parse_aaguid(&self.device.aaguid)?;
        let options = Options {
            manufacturer: Some(self.device.manufacturer.clone()),
            product: Some(self.device.product.clone()),
            serial_number: Some(self.device.serial.clone()),
            vid: self.device.vid,
            pid: self.device.pid,
            device_class: None,
        };
        let descriptor = service::descriptor(
            self.device.name.clone(),
            self.device.vendor_id,
            self.device.product_id,
            self.device.version,
        );
        Ok(service::RunnerConfig {
            descriptor,
            options,
            state_dir: self.state.state_dir.clone(),
            aaguid,
            identity: service::IdentityStrings {
                manufacturer: self.device.manufacturer.clone(),
                product: self.device.product.clone(),
                serial: self.device.serial.clone(),
            },
            pqc_policy: self.device.pqc_policy.into(),
            backend: self.device.backend.into_backend(),
            gadget: if self.device.backend == BackendArg::Gadget {
                Some(GadgetConfig {
                    configfs_root: self.device.gadget.gadget_root.clone(),
                    name: self.device.gadget.gadget_name.clone(),
                    udc: self.device.gadget.gadget_udc.clone(),
                    max_power_ma: self.device.gadget.gadget_max_power_ma,
                    usb_version_bcd: self.device.gadget.gadget_usb_version,
                })
            } else {
                None
            },
        })
    }
}

fn read_pid(path: &Path) -> io::Result<Option<Pid>> {
    match fs::read_to_string(path) {
        Ok(contents) => {
            let trimmed = contents.trim();
            if trimmed.is_empty() {
                fs::remove_file(path).ok();
                return Ok(None);
            }
            match trimmed.parse::<i32>() {
                Ok(pid) => Ok(Some(Pid::from_raw(pid))),
                Err(_) => {
                    fs::remove_file(path).ok();
                    Ok(None)
                }
            }
        }
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err),
    }
}

fn process_running(pid: Pid) -> bool {
    match signal::kill(pid, None) {
        Ok(_) => true,
        Err(Errno::ESRCH) => false,
        Err(_) => true,
    }
}

fn run_service(config: service::RunnerConfig) -> io::Result<()> {
    let _ = pretty_env_logger::try_init();
    service::run(config)
}

fn warn_backend_permissions(config: &service::RunnerConfig) {
    match config.backend {
        service::Backend::Uhid => warn_uhid_permissions(&config.descriptor),
        service::Backend::Gadget => warn_gadget_permissions(config),
        #[cfg(feature = "usbip-backend")]
        service::Backend::Usbip => {}
    }
}

fn warn_uhid_permissions(descriptor: &HidDeviceDescriptor) {
    let euid = unistd::geteuid();
    if euid.is_root() {
        return;
    }

    match permissions::check_uhid_access() {
        Ok(_) => {}
        Err(err) if err.kind() == io::ErrorKind::PermissionDenied => {
            warn_group_membership();
        }
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            eprintln!(
                "warning: /dev/uhid is not available. Load the uhid kernel module with 'sudo modprobe uhid'."
            );
        }
        Err(_) => {}
    }

    if let Ok(nodes) = permissions::hidraw_nodes_for_descriptor(descriptor) {
        for node in nodes {
            let mode = node.mode & 0o777;
            if mode & 0o007 != 0 {
                eprintln!(
                    "warning: {} is world-accessible (mode {:o}). Install contrib/udev/70-feitian-authenticator.rules or tighten permissions.",
                    node.path.display(),
                    mode
                );
            }
        }
    }
}

fn warn_gadget_permissions(config: &service::RunnerConfig) {
    if !unistd::geteuid().is_root() {
        eprintln!(
            "warning: configuring the USB gadget backend requires root access to configfs and {}.",
            HID_DEVICE_NODE
        );
    }

    if let Some(gadget) = &config.gadget {
        let gadget_root = gadget.configfs_root.join(&gadget.name);
        if gadget_root.exists() {
            eprintln!(
                "warning: gadget directory {} already exists and will be reused; ensure no other instance is running.",
                gadget_root.display()
            );
        }
    }

    let device_path = Path::new(HID_DEVICE_NODE);
    if device_path.exists() {
        if let Ok(metadata) = device_path.metadata() {
            let mode = metadata.permissions().mode() & 0o777;
            if mode & 0o006 == 0 {
                return;
            }
            eprintln!(
                "warning: {} is currently world- or group-writable (mode {:o}); adjust permissions if this is unintended.",
                device_path.display(),
                mode
            );
        }
    }
}

fn warn_group_membership() {
    const GROUP_NAME: &str = "plugdev";
    let plugdev_gid = group_by_name(GROUP_NAME);
    let groups = unistd::getgroups().unwrap_or_default();
    let egid = unistd::getegid();

    if let Some(gid) = plugdev_gid {
        if !groups.contains(&gid) && egid != gid {
            eprintln!(
                "warning: insufficient permissions to access /dev/uhid. Add your user to the '{}' group or adjust contrib/udev/70-feitian-authenticator.rules.",
                GROUP_NAME
            );
        } else {
            eprintln!(
                "warning: unable to access /dev/uhid even though '{}' group is present. Verify the udev rule contrib/udev/70-feitian-authenticator.rules is installed.",
                GROUP_NAME
            );
        }
    } else {
        eprintln!(
            "warning: insufficient permissions to access /dev/uhid and '{}' group was not found. Install contrib/udev/70-feitian-authenticator.rules and adjust the GROUP value for your system.",
            GROUP_NAME
        );
    }
}

fn group_by_name(name: &str) -> Option<Gid> {
    Group::from_name(name).ok().flatten().map(|g| g.gid)
}

fn start(cmd: StartCommand) -> io::Result<()> {
    let state_dir = cmd.state.state_dir.clone();
    service::ensure_state_dir(&state_dir)?;
    let pid_path = cmd.state.pid_path();
    if let Some(pid) = read_pid(&pid_path)? {
        if process_running(pid) {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!("authenticator already running (pid {})", pid),
            ));
        }
        fs::remove_file(&pid_path).ok();
    }

    let config = cmd
        .to_runner_config()
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?;

    warn_backend_permissions(&config);

    if cmd.foreground {
        fs::write(&pid_path, format!("{}\n", process::id()))?;
        let result = run_service(config);
        fs::remove_file(&pid_path).ok();
        return result;
    }

    let log_path = state_dir.join("authenticator.log");
    let stdout = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(&log_path)?;
    let stderr = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(&log_path)?;

    let daemon = Daemonize::new()
        .pid_file(&pid_path)
        .stdout(stdout)
        .stderr(stderr)
        .exit_action(|| println!("Authenticator daemonizing..."));

    daemon
        .start()
        .map_err(|err| io::Error::new(io::ErrorKind::Other, err))?;

    let result = run_service(config);
    fs::remove_file(&pid_path).ok();
    result
}

fn stop(state: StateArgs) -> io::Result<()> {
    let pid_path = state.pid_path();
    match read_pid(&pid_path)? {
        Some(pid) => {
            if process_running(pid) {
                signal::kill(pid, Signal::SIGTERM)
                    .map_err(|err| io::Error::new(io::ErrorKind::Other, err))?;
                let deadline = Instant::now() + Duration::from_secs(5);
                while process_running(pid) && Instant::now() < deadline {
                    thread::sleep(Duration::from_millis(200));
                }
                if process_running(pid) {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "timed out waiting for authenticator to stop",
                    ));
                }
            }
            fs::remove_file(&pid_path).ok();
            println!("Authenticator stopped");
            Ok(())
        }
        None => {
            println!("Authenticator is not running");
            Ok(())
        }
    }
}

fn status(state: StateArgs) -> io::Result<()> {
    let pid_path = state.pid_path();
    match read_pid(&pid_path)? {
        Some(pid) if process_running(pid) => {
            println!("Authenticator running (pid {})", pid);
        }
        Some(_) => {
            fs::remove_file(&pid_path).ok();
            println!("Authenticator is not running");
        }
        None => println!("Authenticator is not running"),
    }
    Ok(())
}

pub fn run_cli() -> io::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Start(cmd) => start(cmd),
        Command::Stop(state) => stop(state),
        Command::Status(state) => status(state),
    }
}
