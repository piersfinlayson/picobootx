// Copyright (C) 2026 Piers Finlayson <piers@piers.rocks>
//
// MIT License

//! Finding and talking to the hardware test device.
//!
//! Shared by the two binaries, because both have to find the same board and
//! neither may find anything else.

use std::time::Duration;

use nusb::transfer::ControlType::Vendor;
use nusb::transfer::{Buffer, Bulk, ControlIn, ControlOut, In, Out, Recipient};
use nusb::{Device, Endpoint, Interface, MaybeFuture};

use picobootx::wire::{CMD_LEN, MAGIC};

/// What the device declares itself as.  The ids are the ones a real part in
/// BOOTSEL carries, because picoboot hosts look for those, so the product
/// string is the only thing separating this instrument from any other RP2350
/// somebody has in the bootloader.
///
/// Matching on it is what stops this tool touching a board that is not the one
/// under test.  A stock part in BOOTSEL, or a One ROM, does not answer to it.
pub const VID: u16 = 0x2e8a;
pub const PID: u16 = 0x000f;
pub const PRODUCT: &str = "RP2350 picobootx hwtest";

/// The interface picoboot is served on, and the endpoints the device declares.
pub const INTERFACE: u8 = 0;
pub const EP_OUT: u8 = 0x01;
pub const EP_IN: u8 = 0x81;
pub const MAX_PACKET: usize = 64;

/// picoboot's own control requests, from the library under test.
pub use picobootx::{REQUEST_GET_CMD_STATUS, REQUEST_INTERFACE_RESET};

/// The device's way back into BOOTSEL.  Its own vendor request rather than one
/// of picoboot's, and it carries a value as well, so a stray request cannot
/// reboot the board.
pub const REQUEST_BOOTSEL: u8 = 0x45;
pub const REQUEST_BOOTSEL_VALUE: u16 = 0xb007;

/// Read what the protocol and its queues are doing.  Answered on the control
/// endpoint, so it works while the bulk pair is halted or wedged.
pub const REQUEST_DIAG: u8 = 0x46;
pub const DIAG_LEN: u16 = 8;

/// Long enough for a device that is going to answer to have answered.
pub const TIMEOUT: Duration = Duration::from_millis(2000);

/// The device, its interface, and the pair of bulk endpoints.
pub struct Board {
    pub device: Device,
    pub interface: Interface,
}

impl Board {
    /// Open the one hardware test device on the bus.
    ///
    /// Refuses where there is not exactly one, rather than picking. Two boards
    /// answering the same description is a question for whoever plugged them
    /// in, not something to resolve by taking the first.
    pub async fn open() -> Result<Self, String> {
        let mut found: Vec<_> = nusb::list_devices()
            .wait()
            .map_err(|e| format!("cannot list the bus: {e}"))?
            .filter(|d| {
                d.vendor_id() == VID && d.product_id() == PID && d.product_string() == Some(PRODUCT)
            })
            .collect();

        let info = match found.len() {
            1 => found.remove(0),
            0 => {
                return Err(format!(
                    "no device calling itself {PRODUCT:?} ({VID:04x}:{PID:04x}).  Flash \
                     test/hw/device onto the board, or put it back with picobootx-hw-bootsel \
                     if it is already running the test firmware"
                ));
            }
            n => return Err(format!("{n} of them are plugged in, so which is not clear")),
        };

        let mut device = info
            .open()
            .await
            .map_err(|e| format!("cannot open the device: {e}"))?;

        detach_kernel_driver(&mut device);

        let interface = device
            .claim_interface(INTERFACE)
            .await
            .map_err(|e| format!("cannot claim interface {INTERFACE}: {e}"))?;

        Ok(Self { device, interface })
    }

    /// Send one 32 byte command header.
    pub fn send_cmd(&self, cmd_id: u8, transfer_len: u32, args: &[u8]) -> Result<(), String> {
        let mut buf = [0u8; CMD_LEN];
        buf[0..4].copy_from_slice(&MAGIC.to_le_bytes());
        buf[4..8].copy_from_slice(&1u32.to_le_bytes());
        buf[8] = cmd_id;
        buf[9] = args.len() as u8;
        buf[12..16].copy_from_slice(&transfer_len.to_le_bytes());
        buf[16..16 + args.len()].copy_from_slice(args);

        let mut ep: Endpoint<Bulk, Out> = self
            .interface
            .endpoint(EP_OUT)
            .map_err(|e| format!("no bulk OUT endpoint: {e}"))?;

        ep.transfer_blocking(Buffer::from(buf.to_vec()), TIMEOUT)
            .into_result()
            .map(|_| ())
            .map_err(|e| format!("{e}"))
    }

    /// Read one reply.  The length is rounded up to a packet, as nusb requires.
    pub fn read_reply(&self, len: usize) -> Result<Vec<u8>, String> {
        let rounded = len.div_ceil(MAX_PACKET) * MAX_PACKET;

        let mut ep: Endpoint<Bulk, In> = self
            .interface
            .endpoint(EP_IN)
            .map_err(|e| format!("no bulk IN endpoint: {e}"))?;

        let completion = ep.transfer_blocking(Buffer::new(rounded), TIMEOUT);
        let mut data = completion
            .into_result()
            .map(nusb::transfer::Buffer::into_vec)
            .map_err(|e| format!("{e}"))?;
        data.truncate(len);
        Ok(data)
    }

    /// What the device made of the last command.  On the control endpoint, so
    /// it is answerable while the bulk endpoints are halted - which is the
    /// whole reason a refusal can be diagnosed at all.
    pub async fn command_status(&self) -> Result<Vec<u8>, String> {
        self.device
            .control_in(
                ControlIn {
                    control_type: Vendor,
                    recipient: Recipient::Interface,
                    request: REQUEST_GET_CMD_STATUS,
                    value: 0,
                    index: INTERFACE as u16,
                    length: 16,
                },
                TIMEOUT,
            )
            .await
            .map_err(|e| format!("GET_COMMAND_STATUS failed: {e}"))
    }

    /// What the device says its protocol and queues are doing.
    pub async fn diagnostics(&self) -> Result<String, String> {
        let d = self
            .device
            .control_in(
                ControlIn {
                    control_type: Vendor,
                    recipient: Recipient::Interface,
                    request: REQUEST_DIAG,
                    value: 0,
                    index: INTERFACE as u16,
                    length: DIAG_LEN,
                },
                TIMEOUT,
            )
            .await
            .map_err(|e| format!("diagnostics failed: {e}"))?;

        if d.len() < 8 {
            return Err(format!("the device answered {} bytes", d.len()));
        }
        let state = match d[0] {
            0 => "Idle",
            1 => "DataOut",
            2 => "DataIn",
            3 => "CustomIn",
            4 => "AwaitZlp",
            5 => "AwaitAck",
            6 => "Stalled",
            _ => "?",
        };
        Ok(format!(
            "state={state} halted_out={} halted_in={} in_flight={} rx={} tx={}",
            d[1] != 0,
            d[2] != 0,
            d[3] != 0,
            u16::from_le_bytes([d[4], d[5]]),
            u16::from_le_bytes([d[6], d[7]]),
        ))
    }

    /// Clear a halt the device raised, in one direction.
    ///
    /// Both directions have to be cleared after a refusal.  A host library that
    /// clears only the one whose transfer it saw fail leaves the other halted,
    /// and the loss that follows looks exactly like a device fault.
    pub async fn clear_halt(&self, addr: u8) -> Result<(), String> {
        if addr & 0x80 != 0 {
            let mut ep: Endpoint<Bulk, In> = self
                .interface
                .endpoint(addr)
                .map_err(|e| format!("no bulk IN endpoint: {e}"))?;
            ep.clear_halt().await.map_err(|e| format!("{e}"))
        } else {
            let mut ep: Endpoint<Bulk, Out> = self
                .interface
                .endpoint(addr)
                .map_err(|e| format!("no bulk OUT endpoint: {e}"))?;
            ep.clear_halt().await.map_err(|e| format!("{e}"))
        }
    }

    /// The vendor request picoboot hosts send to put the interface back in a
    /// known state after a refusal.
    pub async fn interface_reset(&self) -> Result<(), String> {
        self.control_out(REQUEST_INTERFACE_RESET, 0).await
    }

    /// Ask the device to reboot into BOOTSEL.
    pub async fn bootsel(&self) -> Result<(), String> {
        self.control_out(REQUEST_BOOTSEL, REQUEST_BOOTSEL_VALUE)
            .await
    }

    async fn control_out(&self, request: u8, value: u16) -> Result<(), String> {
        self.device
            .control_out(
                ControlOut {
                    control_type: Vendor,
                    recipient: Recipient::Interface,
                    request,
                    value,
                    index: INTERFACE as u16,
                    data: &[],
                },
                TIMEOUT,
            )
            .await
            .map(|_| ())
            .map_err(|e| format!("control request {request:#04x} failed: {e}"))
    }
}

/// Let go of the interface if something else holds it.
///
/// The kernel does not bind a vendor interface, but a run that died mid
/// transfer can leave one claimed.  Only Linux has the notion, and taking the
/// device by reference on every platform is what keeps the binding above
/// mutable everywhere rather than only where it is used.
fn detach_kernel_driver(device: &mut Device) {
    #[cfg(target_os = "linux")]
    let _ = device.detach_kernel_driver(INTERFACE);
    #[cfg(not(target_os = "linux"))]
    let _ = device;
}
