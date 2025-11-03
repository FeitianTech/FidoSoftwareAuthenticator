use std::{
    fs::{self, File, OpenOptions},
    io::{self, ErrorKind},
    os::unix::{fs::symlink, fs::OpenOptionsExt, io::AsRawFd},
    path::{Path, PathBuf},
    thread,
    time::Duration,
};

use log::{info, warn};
use nix::{
    errno::Errno,
    fcntl::{fcntl, FcntlArg, OFlag},
    libc,
    poll::{poll, PollFd, PollFlags},
    unistd::{read, write},
};

use crate::uhid::{CtapHidFrame, CTAPHID_FRAME_LEN, CTAPHID_REPORT_DESCRIPTOR};

const CONFIG_NAME: &str = "c.1";
const HID_FUNCTION: &str = "hid.usb0";
const STRINGS_LANG: &str = "0x409";
const DEVICE_APPEARANCE_WAIT_LOOPS: usize = 100;
const DEVICE_APPEARANCE_WAIT_DELAY: Duration = Duration::from_millis(50);

#[derive(Clone, Debug)]
pub struct GadgetConfig {
    pub configfs_root: PathBuf,
    pub name: String,
    pub udc: Option<String>,
    pub max_power_ma: u16,
    pub usb_version_bcd: u16,
}

impl GadgetConfig {
    fn root_path(&self) -> PathBuf {
        self.configfs_root.join(&self.name)
    }
}

pub fn resolve_udc(preferred: Option<&str>) -> io::Result<String> {
    if let Some(name) = preferred {
        return Ok(name.to_string());
    }

    let mut entries = fs::read_dir("/sys/class/udc")?
        .filter_map(|entry| entry.ok())
        .filter(|entry| entry.file_type().map(|ft| ft.is_dir()).unwrap_or(true));

    if let Some(entry) = entries.next() {
        entry
            .file_name()
            .into_string()
            .map_err(|_| io::Error::new(ErrorKind::InvalidData, "UDC name is not valid UTF-8"))
    } else {
        Err(io::Error::new(
            ErrorKind::NotFound,
            "no USB Device Controller (UDC) available under /sys/class/udc",
        ))
    }
}

fn write_str(path: &Path, value: &str) -> io::Result<()> {
    fs::write(path, value)
}

fn write_hex(path: &Path, value: u16) -> io::Result<()> {
    write_str(path, &format!("{:04x}", value))
}

pub struct UsbGadget {
    root: PathBuf,
    udc_path: PathBuf,
    device_path: PathBuf,
    bound: bool,
}

impl UsbGadget {
    pub fn create(
        config: &GadgetConfig,
        manufacturer: &str,
        product: &str,
        serial: &str,
        vid: u16,
        pid: u16,
        device_class: (u8, u8, u8),
        hid_version_bcd: u16,
        udc: &str,
    ) -> io::Result<Self> {
        let root = config.root_path();
        if root.exists() {
            return Err(io::Error::new(
                ErrorKind::AlreadyExists,
                format!(
                    "gadget {} already exists; stop the service before starting a new instance",
                    root.display()
                ),
            ));
        }
        fs::create_dir_all(&root)?;

        write_hex(&root.join("idVendor"), vid)?;
        write_hex(&root.join("idProduct"), pid)?;
        write_hex(&root.join("bcdUSB"), config.usb_version_bcd)?;
        write_hex(&root.join("bcdDevice"), hid_version_bcd)?;
        write_str(
            &root.join("bDeviceClass"),
            &format!("{:02x}", device_class.0),
        )?;
        write_str(
            &root.join("bDeviceSubClass"),
            &format!("{:02x}", device_class.1),
        )?;
        write_str(
            &root.join("bDeviceProtocol"),
            &format!("{:02x}", device_class.2),
        )?;

        let strings = root.join("strings").join(STRINGS_LANG);
        fs::create_dir_all(&strings)?;
        write_str(&strings.join("manufacturer"), manufacturer)?;
        write_str(&strings.join("product"), product)?;
        write_str(&strings.join("serialnumber"), serial)?;

        let configs = root.join("configs").join(CONFIG_NAME);
        fs::create_dir_all(&configs)?;
        write_str(&configs.join("bmAttributes"), "0x80")?;
        write_str(&configs.join("MaxPower"), &config.max_power_ma.to_string())?;

        let config_strings = configs.join("strings").join(STRINGS_LANG);
        fs::create_dir_all(&config_strings)?;
        write_str(&config_strings.join("configuration"), "FIDO2")?;

        let functions = root.join("functions").join(HID_FUNCTION);
        fs::create_dir_all(&functions)?;
        write_str(&functions.join("protocol"), "0")?;
        write_str(&functions.join("subclass"), "0")?;
        write_str(
            &functions.join("report_length"),
            &CTAPHID_FRAME_LEN.to_string(),
        )?;
        fs::write(&functions.join("report_desc"), &CTAPHID_REPORT_DESCRIPTOR)?;

        let link = configs.join(HID_FUNCTION);
        symlink(&functions, &link)?;

        let udc_path = root.join("UDC");
        write_str(&udc_path, &(udc.to_string() + "\n"))?;

        info!(
            "bound USB gadget {} to UDC {} (manufacturer='{}', product='{}')",
            config.name, udc, manufacturer, product
        );

        let device_path = hid_device_node(HID_FUNCTION);
        wait_for_device(&device_path)?;

        Ok(Self {
            root,
            udc_path,
            device_path,
            bound: true,
        })
    }

    pub fn device_path(&self) -> &Path {
        &self.device_path
    }
}

impl Drop for UsbGadget {
    fn drop(&mut self) {
        if self.bound {
            if let Err(err) = write_str(&self.udc_path, "") {
                warn!("failed to unbind gadget: {err}");
            }
            self.bound = false;
        }
        if let Err(err) = fs::remove_dir_all(&self.root) {
            if err.kind() != ErrorKind::NotFound {
                warn!("failed to tear down gadget {}: {err}", self.root.display());
            }
        }
    }
}

fn hid_device_node(function: &str) -> PathBuf {
    let suffix = function.rsplit('.').next().unwrap_or("usb0");
    let idx = suffix.trim_start_matches("usb");
    PathBuf::from(format!("/dev/hidg{}", idx))
}

fn wait_for_device(path: &Path) -> io::Result<()> {
    for _ in 0..DEVICE_APPEARANCE_WAIT_LOOPS {
        if path.exists() {
            return Ok(());
        }
        thread::sleep(DEVICE_APPEARANCE_WAIT_DELAY);
    }
    Err(io::Error::new(
        ErrorKind::TimedOut,
        format!("HID gadget device node {} did not appear", path.display()),
    ))
}

pub struct GadgetDevice {
    file: File,
}

impl GadgetDevice {
    pub fn open(path: &Path) -> io::Result<Self> {
        let mut options = OpenOptions::new();
        options.read(true);
        options.write(true);
        options.custom_flags(libc::O_NONBLOCK);
        let file = options.open(path)?;
        let fd = file.as_raw_fd();
        let flags = fcntl(fd, FcntlArg::F_GETFL).map_err(to_io_error)?;
        let mut oflags = OFlag::from_bits_truncate(flags);
        oflags.insert(OFlag::O_NONBLOCK);
        fcntl(fd, FcntlArg::F_SETFL(oflags)).map_err(to_io_error)?;
        Ok(Self { file })
    }

    pub fn try_read_frame(&mut self) -> io::Result<Option<CtapHidFrame>> {
        let mut buffer = [0u8; CTAPHID_FRAME_LEN + 1];
        let fd = self.file.as_raw_fd();
        match read(fd, &mut buffer) {
            Ok(0) => Ok(None),
            Ok(len) if len == CTAPHID_FRAME_LEN => {
                let mut data = [0u8; CTAPHID_FRAME_LEN];
                data.copy_from_slice(&buffer[..CTAPHID_FRAME_LEN]);
                Ok(Some(CtapHidFrame::new(data)))
            }
            Ok(len) if len == CTAPHID_FRAME_LEN + 1 && buffer[0] == 0 => {
                let mut data = [0u8; CTAPHID_FRAME_LEN];
                data.copy_from_slice(&buffer[1..CTAPHID_FRAME_LEN + 1]);
                Ok(Some(CtapHidFrame::new(data)))
            }
            Ok(len) => Err(io::Error::new(
                ErrorKind::InvalidData,
                format!("unexpected HID frame length {len}"),
            )),
            Err(err) => match err {
                Errno::EAGAIN => Ok(None),
                other => Err(io::Error::from(other)),
            },
        }
    }

    pub fn write_frame(&mut self, frame: &CtapHidFrame) -> io::Result<()> {
        let bytes = frame.as_bytes();
        let fd = self.file.as_raw_fd();
        match write(fd, bytes) {
            Ok(written) if written == CTAPHID_FRAME_LEN => Ok(()),
            Ok(written) => Err(io::Error::new(
                ErrorKind::WriteZero,
                format!(
                    "short write to HID gadget (expected {} bytes, wrote {})",
                    CTAPHID_FRAME_LEN, written
                ),
            )),
            Err(err) => Err(io::Error::from(err)),
        }
    }

    pub fn wait(&self, timeout: Option<Duration>) -> io::Result<bool> {
        let mut fds = [PollFd::new(&self.file, PollFlags::POLLIN)];
        let timeout_ms = timeout
            .map(|d| d.as_millis().min(i32::MAX as u128) as i32)
            .unwrap_or(-1);
        loop {
            match poll(&mut fds, timeout_ms) {
                Ok(ready) => return Ok(ready > 0),
                Err(Errno::EINTR) => continue,
                Err(err) => return Err(to_io_error(err.into())),
            }
        }
    }
}

fn to_io_error(err: nix::Error) -> io::Error {
    io::Error::from(err)
}
