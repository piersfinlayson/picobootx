// Copyright (C) 2026 Piers Finlayson <piers@piers.rocks>
//
// MIT License

//! Drive picobootx with picoboot-rs, over a real USB bus.
//!
//! The bridge in `test/usbip` has already put a picobootx device on this
//! machine's bus by the time this runs, and `test/usbip/picotool.sh` drives that
//! same device with picotool.  This drives it with the other host implementation
//! of PICOBOOT, and the checks deliberately mirror picotool's — the same claims,
//! reached a different way.
//!
//! The difference that makes it worth having is not the language.  picotool goes
//! through libusb, and picoboot-rs goes through nusb, which talks to the kernel
//! itself rather than through a C library.  So this is a second USB stack as well
//! as a second implementation of the protocol, and a claim both of them agree on
//! is a claim about picobootx rather than about either host.
//!
//! Checks run in order against one device and print as they go, the way the C
//! suites and picotool.sh do, rather than as cargo tests — several of them only
//! mean anything in sequence, and there is one device for them to share.
//!
//! # This never touches a board
//!
//! The checks erase flash and blow an OTP row. Behind the bridge those are a few
//! bytes of a model that starts again on the next run. On a real part the flash
//! erase takes out whatever was running and the OTP row is gone for good, since
//! a fuse goes one way only.
//!
//! So this refuses to open anything that is not behind the usbip virtual host
//! controller. The bridge's device is, a board on a real controller cannot be,
//! and a machine that cannot answer the question at all is refused too.

use std::path::Path;
use std::process::ExitCode;

use picoboot::{Access, Connection, Picoboot, PicobootCmd, PicobootCmdId, Target};

/// Where the checks work, and how much they move.  The flash model behind the
/// bridge covers the whole window picobootx admits, so the addresses here are
/// only a place to work rather than a limit.
const FLASH_BASE: u32 = 0x1000_0000;
const SECTOR: u32 = 4096;

/// An OTP row past the ones the part gives meaning to, so what is read back is
/// what was written and not something the model holds for another reason.  The
/// same row picotool.sh uses.
const OTP_ROW: u16 = 0xC0;

/// How many rows an OTP command carries, and how wide a row is when read through
/// the ECC view.  picobootx's `pb_otp_args_t` is row, row_count, ecc.
const OTP_ROWS: u16 = 1;
const OTP_ECC_ROW_BYTES: u32 = 2;

struct Report {
    passed: u32,
    failed: u32,
}

impl Report {
    fn new() -> Self {
        Report {
            passed: 0,
            failed: 0,
        }
    }

    fn check(&mut self, name: &str, outcome: Result<(), String>) {
        match outcome {
            Ok(()) => {
                self.passed += 1;
                println!("  ok    {name}");
            }
            Err(why) => {
                self.failed += 1;
                println!("  FAIL  {name}: {why}");
            }
        }
    }
}

/// Anything that went wrong is a failed check rather than a panic, so one
/// problem does not hide what the rest of the run would have said.
fn why<T, E: std::fmt::Display>(result: Result<T, E>) -> Result<T, String> {
    result.map_err(|e| e.to_string())
}

/// A block of bytes that is unlike any other block this run uses, so a read that
/// came from the wrong place or from a stale erase does not match.
fn pattern(seed: u8, len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed))
        .collect()
}

/// Erase a sector and write a pattern into it, then read it back.
async fn write_and_read(conn: &mut Connection, data: &[u8]) -> Result<Vec<u8>, String> {
    why(conn.flash_erase(FLASH_BASE, SECTOR).await)?;
    why(conn.flash_write(FLASH_BASE, data).await)?;
    why(conn.flash_read(FLASH_BASE, data.len() as u32).await)
}

/// One OTP row, through the ECC view, as sixteen bits.  picoboot-rs has no OTP
/// call of its own, so the command is built here — which also means this reaches
/// picobootx's framing without a helper in between.
fn otp_cmd(id: PicobootCmdId, transfer_len: u32) -> PicobootCmd {
    let mut args = [0u8; 16];
    args[0..2].copy_from_slice(&OTP_ROW.to_le_bytes());
    args[2..4].copy_from_slice(&OTP_ROWS.to_le_bytes());
    args[4] = 1; // the ECC view, which is the low sixteen bits of the row
    PicobootCmd::new(id, 0x05, transfer_len, args)
}

async fn otp_write(conn: &mut Connection, value: u16) -> Result<(), String> {
    let cmd = otp_cmd(PicobootCmdId::OtpWrite, OTP_ECC_ROW_BYTES);
    why(conn.send_cmd(cmd, Some(&value.to_le_bytes())).await)?;
    Ok(())
}

async fn otp_read(conn: &mut Connection) -> Result<u16, String> {
    let cmd = otp_cmd(PicobootCmdId::OtpRead, OTP_ECC_ROW_BYTES);
    let data = why(conn.send_cmd(cmd, None).await)?;
    if data.len() < 2 {
        return Err(format!("OTP read returned {} bytes, wanted 2", data.len()));
    }
    Ok(u16::from_le_bytes([data[0], data[1]]))
}

/// The controller usbip attaches through.  A device behind it was made by the
/// bridge, and real silicon, which sits behind a real host controller, can never
/// be behind it.
const VHCI_DRIVER: &str = "vhci_hcd";

/// Whether this device is the bridge's rather than a board somebody has plugged
/// in.  The checks below erase flash and blow an OTP row, which the model behind
/// the bridge forgets on the next run and a real part keeps for good, so the
/// question is asked of every candidate before one is opened.
///
/// It is asked of the kernel rather than of the descriptors, because the bridge
/// presents the same 2e8a:000f a real part does — that is the point of it — so
/// nothing the device says about itself can separate the two.  The bus a device
/// is on is not the device's to claim.
///
/// Anything other than a clear yes is a no, so a system that cannot answer at
/// all, such as one that is not Linux, refuses rather than proceeds.
fn is_bridge_device(bus: &str) -> bool {
    bus_is_virtual(Path::new("/sys/bus/usb/devices"), bus)
}

/// Whether one bus is the virtual controller's, given where the USB device tree
/// is rooted.  Split from `is_bridge_device` so the discrimination can be tested
/// against a tree that is not the running kernel's — the answer this gives is
/// the only thing standing between these checks and somebody's board, so it is
/// worth testing rather than assuming.
///
/// The bus entry is a symlink into the device tree, and the controller that owns
/// it is a component of what it resolves to.
fn bus_is_virtual(devices_root: &Path, bus: &str) -> bool {
    std::fs::canonicalize(devices_root.join(format!("usb{bus}")))
        .map(|p| {
            p.components()
                .any(|c| c.as_os_str().to_string_lossy().starts_with(VHCI_DRIVER))
        })
        .unwrap_or(false)
}

#[tokio::main]
async fn main() -> ExitCode {
    println!("picobootx against picoboot-rs, through nusb");
    println!();
    println!("picoboot-rs");

    let mut report = Report::new();

    // The device is found rather than chosen: the first PICOBOOT device on the
    // bus is whatever happens to be plugged in, and these checks would take a
    // board apart.
    let candidates = match Picoboot::list_devices(None).await {
        Ok(d) => d,
        Err(e) => {
            println!("  FAIL  picoboot-rs lists the bus: {e}");
            println!();
            println!("1 checks, 1 failed");
            return ExitCode::FAILURE;
        }
    };

    let mut bridged: Vec<_> = candidates
        .into_iter()
        .filter(|info| is_bridge_device(info.bus_id()))
        .collect();

    let device = match bridged.len() {
        1 => bridged.remove(0),
        0 => {
            println!(
                "  FAIL  picoboot-rs finds the bridge's device: none behind {VHCI_DRIVER}, so \
                 there is nothing here this may touch.  Start the bridge with \
                 rust/interop/interop.sh, which is the only supported way to run this."
            );
            println!();
            println!("1 checks, 1 failed");
            return ExitCode::FAILURE;
        }
        n => {
            println!(
                "  FAIL  picoboot-rs finds the bridge's device: {n} are behind {VHCI_DRIVER} and \
                 there is no way to tell which the bridge made"
            );
            println!();
            println!("1 checks, 1 failed");
            return ExitCode::FAILURE;
        }
    };

    let mut picoboot = match Picoboot::new(device).await {
        Ok(p) => p,
        Err(e) => {
            println!("  FAIL  picoboot-rs finds the device: {e}");
            println!();
            println!("1 checks, 1 failed");
            return ExitCode::FAILURE;
        }
    };

    // What the device says it is.  picotool decides this from the bootrom magic
    // in the modelled ROM, and picoboot-rs decides it from the product id, so
    // the two agreeing says the device is consistent about which part it is.
    let target = picoboot.target();
    report.check(
        "picoboot-rs finds the device and takes it for an RP2350",
        if target == &Target::Rp2350 {
            Ok(())
        } else {
            Err(format!("it took it for {target:?}"))
        },
    );

    let conn = match picoboot.connect().await {
        Ok(c) => c,
        Err(e) => {
            report.check("picoboot-rs claims the interface", Err(e.to_string()));
            println!();
            println!(
                "{} checks, {} failed",
                report.passed + report.failed,
                report.failed
            );
            return ExitCode::FAILURE;
        }
    };
    report.check("picoboot-rs claims the interface", Ok(()));

    // The control endpoint, which is the path picobootx does not reach through
    // its transport seam.  A device that answers this has answered a vendor
    // control request on the interface picoboot-rs claimed.
    report.check(
        "the device answers GET_COMMAND_STATUS on the control endpoint",
        why(conn.get_command_status().await).map(|_| ()),
    );

    report.check(
        "the device accepts exclusive access and leaves XIP",
        async {
            why(conn.set_exclusive_access(Access::ExclusiveAndEject).await)?;
            why(conn.exit_xip().await)
        }
        .await,
    );

    // The bootrom magic, read over PICOBOOT rather than inferred.  picotool
    // reads the same six bytes to decide which part it is talking to, so this is
    // the same claim its `info -a` check makes, reached without picotool.
    report.check("a read of low ROM returns the bootrom magic", {
        match why(conn.read(0x10, 4).await) {
            Err(e) => Err(e),
            Ok(rom) if rom.len() == 4 && &rom[0..3] == b"Mu\x02" => Ok(()),
            Ok(rom) => Err(format!("ROM at 0x10 reads {rom:02x?}")),
        }
    });

    let first = pattern(0x11, SECTOR as usize);
    report.check("picoboot-rs writes flash and reads back what it wrote", {
        match write_and_read(conn, &first).await {
            Err(e) => Err(e),
            Ok(back) if back == first => Ok(()),
            Ok(_) => Err("what came back is not what went in".into()),
        }
    });

    // Programming flash can clear a bit and never set one, so a second write
    // that did not erase first would read back as the two ANDed together.  The
    // patterns differ in every byte, so that answer cannot look like this one.
    let second = pattern(0x9E, SECTOR as usize);
    report.check(
        "a second write replaces the first rather than being merged into it",
        match write_and_read(conn, &second).await {
            Err(e) => Err(e),
            Ok(back) if back == second => Ok(()),
            Ok(_) => Err("what came back is not what went in".into()),
        },
    );

    report.check("erased flash reads as ones", {
        let outcome = async {
            why(conn.flash_erase(FLASH_BASE, SECTOR).await)?;
            why(conn.flash_read(FLASH_BASE, SECTOR).await)
        }
        .await;
        match outcome {
            Err(e) => Err(e),
            Ok(back) if back.iter().all(|b| *b == 0xFF) => Ok(()),
            Ok(back) => Err(format!(
                "{} bytes of {} are not 0xFF",
                back.iter().filter(|b| **b != 0xFF).count(),
                back.len()
            )),
        }
    });

    report.check("an OTP row is blown and reads back", {
        let outcome = async {
            otp_write(conn, 0x1234).await?;
            otp_read(conn).await
        }
        .await;
        match outcome {
            Err(e) => Err(e),
            Ok(0x1234) => Ok(()),
            Ok(v) => Err(format!("the row reads 0x{v:04x}")),
        }
    });

    // A fuse goes one way only.  picotool never asks for a write that would
    // clear a bit, because it reads the row first and refuses one itself — so
    // this is the half of the rule its checks cannot reach.  The device is asked
    // for it directly, and what comes back has to be the two values together.
    report.check(
        "a write that would clear an OTP bit sets bits and clears none",
        {
            let outcome = async {
                otp_write(conn, 0x4100).await?;
                otp_read(conn).await
            }
            .await;
            match outcome {
                Err(e) => Err(e),
                Ok(0x5334) => Ok(()),
                Ok(0x4100) => Err("the row was replaced rather than blown further".into()),
                Ok(v) => Err(format!("the row reads 0x{v:04x}")),
            }
        },
    );

    // INTERFACE RESET, the other vendor control request, and the one a host
    // issues when it wants the device back in a known state.  Doing it last
    // leaves nothing after it to be disturbed by it, and the status read
    // afterwards is what says the device is still answering.
    report.check(
        "the device answers INTERFACE RESET and still talks afterwards",
        {
            let outcome = async {
                why(conn.reset_interface().await)?;
                why(conn.get_command_status().await)
            }
            .await;
            outcome.map(|_| ())
        },
    );

    println!();
    println!(
        "{} checks, {} failed",
        report.passed + report.failed,
        report.failed
    );

    if report.failed == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    /// A USB device tree with one bus on the controller named, laid out the way
    /// sysfs lays one out: the bus is a symlink into the device tree, and the
    /// controller is a directory along the way.
    fn tree(name: &str, bus: &str, controller: &str) -> std::path::PathBuf {
        let root = std::env::temp_dir().join(format!("pbx-bus-{name}"));
        let _ = std::fs::remove_dir_all(&root);
        let real = root
            .join("devices/platform")
            .join(controller)
            .join(format!("usb{bus}"));
        std::fs::create_dir_all(&real).unwrap();
        let devices = root.join("bus/usb/devices");
        std::fs::create_dir_all(&devices).unwrap();
        symlink(&real, devices.join(format!("usb{bus}"))).unwrap();
        devices
    }

    #[test]
    fn the_bridges_bus_is_taken_as_virtual() {
        let devices = tree("vhci", "3", "vhci_hcd.0");
        assert!(bus_is_virtual(&devices, "3"));
    }

    #[test]
    fn a_real_controllers_bus_is_not() {
        let devices = tree("xhci", "1", "xhci-hcd.0");
        assert!(!bus_is_virtual(&devices, "1"));
    }

    /// A controller whose name merely contains the driver's is not it.  The
    /// component has to start with the name, or a board on something called
    /// "not-vhci_hcd" would be opened and taken apart.
    #[test]
    fn a_controller_that_only_contains_the_name_is_not_it() {
        let devices = tree("nearly", "2", "not-vhci_hcd.0");
        assert!(!bus_is_virtual(&devices, "2"));
    }

    /// A bus that is not there at all is not the bridge's.  This is what a
    /// machine with no sysfs answers, so the tool refuses there rather than
    /// carrying on.
    #[test]
    fn an_absent_bus_is_not() {
        let devices = tree("absent", "4", "vhci_hcd.0");
        assert!(!bus_is_virtual(&devices, "9"));
    }
}
