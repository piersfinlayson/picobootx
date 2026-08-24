// Copyright (C) 2026 Piers Finlayson <piers@piers.rocks>
//
// MIT License

//! Finding and talking to the hardware test device.
//!
//! Shared by the binaries, because they all have to find the same board and
//! none of them may find anything else.
//!
//! # Speaking the protocol, not approximating it
//!
//! PICOBOOT ends every command with an acknowledgement, and which end sends it
//! depends on which way the data went.  A command with no device-to-host phase
//! is acknowledged by the device, on the bulk IN endpoint, and one that carried
//! data to the host is acknowledged by the host, on the bulk OUT endpoint.  A
//! host that leaves either out parks the device part way through a command,
//! where it stays until something puts it back — across the host process
//! exiting, since neither end of a USB bus is reset by a program ending.
//!
//! So [`Board::read_reply`] is followed by [`Board::ack`] and a command with no
//! data phase is followed by [`Board::read_ack`], and [`Board::quiesce`] is what
//! every run starts and ends with.

use std::fmt;
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

/// The standard request that reports an endpoint's halt.
pub const REQUEST_GET_STATUS: u8 = 0x00;

/// Read what the protocol and its queues are doing.  Answered on the control
/// endpoint, so it works while the bulk pair is halted or wedged.
pub const REQUEST_DIAG: u8 = 0x46;
pub const DIAG_LEN: u16 = 8;

/// Long enough for a device that is going to answer to have answered.
pub const TIMEOUT: Duration = Duration::from_millis(2000);

/// How long a drain waits for a packet that may not be there.
///
/// Short, because the ordinary answer is that nothing comes and the wait is
/// paid in full every time a run starts.
const DRAIN_TIMEOUT: Duration = Duration::from_millis(100);

/// How many packets a drain will take before giving up on the endpoint ever
/// going quiet.  A device queues one packet per poll, so a pipe still handing
/// them over after this many is not one waiting to be emptied.
const DRAIN_LIMIT: usize = 8;

/// What the protocol and its queues are doing at one moment, as the device
/// reports it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Diagnostics {
    /// `picobootx::State`, as its discriminant.
    pub state: u8,
    /// Whether the host-to-device endpoint is halted.
    pub halted_out: bool,
    /// Whether the device-to-host endpoint is halted.
    pub halted_in: bool,
    /// Whether a packet is armed on the device-to-host endpoint and not yet
    /// taken by the host.
    pub in_flight: bool,
    /// Bytes queued from the host and not yet taken by the protocol.
    pub rx: u16,
    /// Bytes the protocol has queued for the host and not yet sent.
    pub tx: u16,
}

impl Diagnostics {
    /// The state a device waiting for its next command is in, with both queues
    /// empty, neither endpoint halted and nothing owed to the host.
    ///
    /// This is what a run starts from and what it leaves behind.
    pub fn is_quiet(&self) -> bool {
        self.state == Self::IDLE
            && !self.halted_out
            && !self.halted_in
            && !self.in_flight
            && self.rx == 0
            && self.tx == 0
    }

    /// `picobootx::State::Idle`.  Named here because the discriminant crosses
    /// the wire as a number and nothing else on this side gives it a meaning.
    pub const IDLE: u8 = 0;

    fn state_name(&self) -> &'static str {
        match self.state {
            0 => "Idle",
            1 => "DataOut",
            2 => "DataIn",
            3 => "CustomIn",
            4 => "AwaitZlp",
            5 => "AwaitAck",
            6 => "Stalled",
            _ => "?",
        }
    }
}

impl fmt::Display for Diagnostics {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "state={} halted_out={} halted_in={} in_flight={} rx={} tx={}",
            self.state_name(),
            self.halted_out,
            self.halted_in,
            self.in_flight,
            self.rx,
            self.tx,
        )
    }
}

/// The device, its interface, and the pair of bulk endpoints.
///
/// The endpoints are opened once and kept.  Opening one per transfer works, but
/// it means a halt is cleared on a handle that is then thrown away rather than
/// on the one the next transfer uses.
pub struct Board {
    pub device: Device,
    pub interface: Interface,
    /// What the device enumerated with, which on this part is its chip
    /// identifier.  `None` where it declares no serial number.
    pub serial: Option<String>,
    ep_out: Endpoint<Bulk, Out>,
    ep_in: Endpoint<Bulk, In>,
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

        let serial = info.serial_number().map(str::to_owned);

        let mut device = info
            .open()
            .await
            .map_err(|e| format!("cannot open the device: {e}"))?;

        detach_kernel_driver(&mut device);

        let interface = device
            .claim_interface(INTERFACE)
            .await
            .map_err(|e| format!("cannot claim interface {INTERFACE}: {e}"))?;

        let ep_out = interface
            .endpoint::<Bulk, Out>(EP_OUT)
            .map_err(|e| format!("no bulk OUT endpoint: {e}"))?;
        let ep_in = interface
            .endpoint::<Bulk, In>(EP_IN)
            .map_err(|e| format!("no bulk IN endpoint: {e}"))?;

        Ok(Self {
            device,
            interface,
            serial,
            ep_out,
            ep_in,
        })
    }

    /// Send one 32 byte command header.
    pub fn send_cmd(&mut self, cmd_id: u8, transfer_len: u32, args: &[u8]) -> Result<(), String> {
        let mut buf = [0u8; CMD_LEN];
        buf[0..4].copy_from_slice(&MAGIC.to_le_bytes());
        buf[4..8].copy_from_slice(&1u32.to_le_bytes());
        buf[8] = cmd_id;
        buf[9] = args.len() as u8;
        buf[12..16].copy_from_slice(&transfer_len.to_le_bytes());
        buf[16..16 + args.len()].copy_from_slice(args);

        self.write_out(&buf, TIMEOUT)
    }

    /// Send the host-to-device half of a data phase, a packet at a time.
    pub fn send_data(&mut self, data: &[u8]) -> Result<(), String> {
        for packet in data.chunks(MAX_PACKET) {
            self.write_out(packet, TIMEOUT)?;
        }
        Ok(())
    }

    /// Read one reply.  The length is rounded up to a packet, as nusb requires.
    pub fn read_reply(&mut self, len: usize) -> Result<Vec<u8>, String> {
        let rounded = len.div_ceil(MAX_PACKET) * MAX_PACKET;

        let completion = self.ep_in.transfer_blocking(Buffer::new(rounded), TIMEOUT);
        let mut data = completion
            .into_result()
            .map(nusb::transfer::Buffer::into_vec)
            .map_err(|e| format!("{e}"))?;
        data.truncate(len);
        Ok(data)
    }

    /// Acknowledge a device-to-host phase, which is the host's to send.
    ///
    /// An empty packet, which is what the protocol names.  The device takes a
    /// single byte as well, for a host that cannot send an empty one.
    pub fn ack(&mut self) -> Result<(), String> {
        self.write_out(&[], TIMEOUT)
    }

    /// Collect the device's acknowledgement of a command that carried no data
    /// to the host.
    ///
    /// The device sends one byte rather than an empty packet, so what comes
    /// back is at most that, and its content means nothing.
    pub fn read_ack(&mut self) -> Result<(), String> {
        self.read_reply(1).map(|_| ())
    }

    /// Whether the device reports this endpoint as halted.
    ///
    /// The standard `GET_STATUS`, which is how a host that did not itself
    /// cause the halt finds out about one.  Bit 0 of the two bytes is the halt.
    pub async fn endpoint_halted(&self, addr: u8) -> Result<bool, String> {
        let s = self
            .device
            .control_in(
                ControlIn {
                    control_type: nusb::transfer::ControlType::Standard,
                    recipient: Recipient::Endpoint,
                    request: REQUEST_GET_STATUS,
                    value: 0,
                    index: u16::from(addr),
                    length: 2,
                },
                TIMEOUT,
            )
            .await
            .map_err(|e| format!("GET_STATUS on {addr:#04x} failed: {e}"))?;

        match s.first() {
            Some(b) => Ok(b & 1 != 0),
            None => Err(format!("GET_STATUS on {addr:#04x} answered nothing")),
        }
    }

    /// Put the device back to waiting for a command, and say so if it would
    /// not go.
    ///
    /// Three things in order, because each undoes something the one after it
    /// cannot.
    ///
    /// **Only a halt the device reports is cleared.**  Clearing one that was
    /// never set is not a harmless extra: `CLEAR_FEATURE(ENDPOINT_HALT)` resets
    /// the host's data toggle for that endpoint, and a device whose driver does
    /// not reset its own then answers the next packet with the wrong number and
    /// the transfer is dropped.  Both real PICOBOOT hosts ask first — picotool
    /// with this same `GET_STATUS`, picoboot-rs from its own record of what it
    /// saw halt — so a test that cleared unconditionally would be measuring a
    /// host nobody has.
    ///
    /// Draining the IN endpoint collects a reply the device armed for a host
    /// that went away, and the reset then puts the protocol back to Idle.
    pub async fn quiesce(&mut self) -> Result<(), String> {
        for addr in [EP_IN, EP_OUT] {
            if self.endpoint_halted(addr).await? {
                self.clear_halt(addr).await?;
            }
        }
        self.drain();
        self.interface_reset().await?;

        let d = self.diagnostics().await?;
        if d.is_quiet() {
            Ok(())
        } else {
            Err(format!("it settled at {d}"))
        }
    }

    /// Take whatever the device-to-host endpoint is still holding.
    ///
    /// Returns how many packets it took.  Ending on a transfer that timed out
    /// is the ordinary outcome and is not reported as a fault — the point is
    /// that nothing is left, not that something was there.
    pub fn drain(&mut self) -> usize {
        let mut taken = 0;
        while taken < DRAIN_LIMIT {
            let completion = self
                .ep_in
                .transfer_blocking(Buffer::new(MAX_PACKET), DRAIN_TIMEOUT);
            if completion.into_result().is_err() {
                break;
            }
            taken += 1;
        }
        taken
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
    pub async fn diagnostics(&self) -> Result<Diagnostics, String> {
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

        if d.len() < DIAG_LEN as usize {
            return Err(format!("the device answered {} bytes", d.len()));
        }
        Ok(Diagnostics {
            state: d[0],
            halted_out: d[1] != 0,
            halted_in: d[2] != 0,
            in_flight: d[3] != 0,
            rx: u16::from_le_bytes([d[4], d[5]]),
            tx: u16::from_le_bytes([d[6], d[7]]),
        })
    }

    /// Clear a halt the device raised, in one direction.
    ///
    /// Both directions have to be cleared after a refusal.  A host library that
    /// clears only the one whose transfer it saw fail leaves the other halted,
    /// and the loss that follows looks exactly like a device fault.
    pub async fn clear_halt(&mut self, addr: u8) -> Result<(), String> {
        let r = if addr & 0x80 != 0 {
            self.ep_in.clear_halt().await
        } else {
            self.ep_out.clear_halt().await
        };
        r.map_err(|e| format!("clearing the halt on {addr:#04x} failed: {e}"))
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

    fn write_out(&mut self, data: &[u8], timeout: Duration) -> Result<(), String> {
        self.ep_out
            .transfer_blocking(Buffer::from(data.to_vec()), timeout)
            .into_result()
            .map(|_| ())
            .map_err(|e| format!("{e}"))
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
