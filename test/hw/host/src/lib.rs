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
/// string is the only thing separating these instruments from any other RP2350
/// somebody has in the bootloader, and from each other.
///
/// Matching on one is what stops this tool touching a board that is not the one
/// under test.  A stock part in BOOTSEL, or a One ROM, answers to neither.
pub const VID: u16 = 0x2e8a;
pub const PID: u16 = 0x000f;

/// Which of the two test firmwares is on the board.
///
/// The same checks are asked of both, and one board carries them one at a time.
/// The product string is how a run says which it is talking to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Firmware {
    /// [test/hw/device-embassy](../../device-embassy), the Rust picobootx on
    /// embassy-usb.
    Embassy,
    /// [test/hw/device-tinyusb](../../device-tinyusb), the C picobootx on
    /// tinyusb.
    Tinyusb,
}

impl Firmware {
    /// Both, in the order a listing names them.
    pub const ALL: [Firmware; 2] = [Firmware::Embassy, Firmware::Tinyusb];

    /// The product string the firmware enumerates with.
    pub const fn product(self) -> &'static str {
        match self {
            Firmware::Embassy => "RP2350 picobootx hwtest embassy",
            Firmware::Tinyusb => "RP2350 picobootx hwtest tinyusb",
        }
    }

    /// What it is called on the command line and in a report.
    pub const fn name(self) -> &'static str {
        match self {
            Firmware::Embassy => "embassy",
            Firmware::Tinyusb => "tinyusb",
        }
    }

    /// The firmware that name belongs to.
    pub fn from_name(name: &str) -> Option<Self> {
        Firmware::ALL.into_iter().find(|f| f.name() == name)
    }

    /// Whether it answers [`REQUEST_DIAG`].
    ///
    /// Both do.  A wire says what a device did and this says why.
    pub const fn serves_diagnostics(self) -> bool {
        matches!(self, Firmware::Embassy | Firmware::Tinyusb)
    }
}

impl fmt::Display for Firmware {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// Reset the port the board is on, and say what re-enumerating showed.
///
/// A board that has stopped answering keeps the descriptors the host already
/// read, so it goes on presenting whatever it was running.  Resetting the port
/// makes it say what it is now, which is how a board sitting in BOOTSEL after a
/// hand jumper stops looking like a wedged firmware.
pub async fn port_reset() -> Result<Option<String>, String> {
    let info = nusb::list_devices()
        .wait()
        .map_err(|e| format!("cannot list the bus: {e}"))?
        .find(|d| d.vendor_id() == VID && d.product_id() == PID)
        .ok_or_else(|| format!("nothing answering {VID:04x}:{PID:04x} to reset"))?;

    info.open()
        .await
        .map_err(|e| format!("cannot open the device: {e}"))?
        .reset()
        .await
        .map_err(|e| format!("the port reset failed: {e}"))?;

    Ok(nusb::list_devices()
        .wait()
        .map_err(|e| format!("cannot list the bus: {e}"))?
        .find(|d| d.vendor_id() == VID && d.product_id() == PID)
        .and_then(|d| d.product_string().map(str::to_owned)))
}

/// Take `--device <name>` off a command line, and hand back the rest.
///
/// All three binaries accept it and nothing else varies between the firmwares,
/// so the parsing is here rather than three times.  `--device=name` too, since
/// that is how the flag gets typed half the time.
pub fn take_device_arg(
    args: impl IntoIterator<Item = String>,
) -> Result<(Option<Firmware>, Vec<String>), String> {
    let names = || Firmware::ALL.map(Firmware::name).join(" or ");

    let mut want = None;
    let mut rest = Vec::new();
    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        let name = if arg == "--device" {
            Some(
                args.next()
                    .ok_or_else(|| format!("--device wants a name after it: {}", names()))?,
            )
        } else {
            arg.strip_prefix("--device=").map(str::to_owned)
        };

        match name {
            Some(name) => {
                want =
                    Some(Firmware::from_name(&name).ok_or_else(|| {
                        format!("there is no {name:?} firmware, only {}", names())
                    })?);
            }
            None => rest.push(arg),
        }
    }
    Ok((want, rest))
}

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

/// Ask where the device will let a host write.
///
/// Every address the RP2350 defaults accept for a write is either the test
/// firmware's own memory or the flash it runs from, so the window is the
/// device's to nominate and this is how it says which one.
pub const REQUEST_SCRATCH: u8 = 0x47;
pub const SCRATCH_REPLY_LEN: u16 = 16;

/// Where the device will let a host work, in memory and in flash.
#[derive(Clone, Copy, Debug)]
pub struct Scratch {
    pub ram: u32,
    pub ram_len: u32,
    pub flash: u32,
    pub flash_len: u32,
}

/// PICOBOOT's read, write and get-info, as the identifier goes on the wire.
pub const CMD_READ: u8 = 0x04 | picobootx::wire::DIR_IN;
pub const CMD_WRITE: u8 = 0x05;
pub const CMD_GET_INFO: u8 = 0x0b | picobootx::wire::DIR_IN;
pub const CMD_REBOOT2: u8 = 0x0a;
pub const CMD_FLASH_ERASE: u8 = 0x03;
pub const CMD_EXCLUSIVE_ACCESS: u8 = 0x01;
pub const CMD_EXIT_XIP: u8 = 0x06;
pub const CMD_ENTER_XIP: u8 = 0x07;

/// Two more the protocol names and this device does not serve.
pub const CMD_EXEC: u8 = 0x08;
pub const CMD_VECTORIZE_FLASH: u8 = 0x09;

/// What `EXCLUSIVE_ACCESS` asks for, in its one argument byte.
pub const ACCESS_NOT_EXCLUSIVE: u8 = 0;
pub const ACCESS_EXCLUSIVE: u8 = 1;
pub const ACCESS_EXCLUSIVE_AND_EJECT: u8 = 2;

/// The units flash works in: a page is what a program writes, a sector what an
/// erase clears, and a block what a bulk erase clears at once.
pub const FLASH_PAGE: u32 = 256;
pub const FLASH_SECTOR: u32 = 4096;
pub const FLASH_BLOCK: u32 = 65536;

/// The reboot the protocol replaced, which a device is expected not to serve.
pub const CMD_REBOOT_OLD: u8 = 0x02;

/// `REBOOT2`'s argument block: flags, a delay, and two parameters.
pub const REBOOT_ARGS_LEN: usize = 16;

/// Reboot the way the part boots normally, which brings this firmware back.
pub const REBOOT_NORMAL: u32 = 0x0;

/// `GET_INFO`'s argument block is sixteen bytes whatever it asks for.
pub const INFO_ARGS_LEN: usize = 16;

/// Which kind of information is being asked for, in the first argument byte.
pub const INFO_SYS: u8 = 0x01;
pub const INFO_PARTITION: u8 = 0x02;
pub const INFO_UF2_TARGET: u8 = 0x03;
pub const INFO_UF2_STATUS: u8 = 0x04;

/// The first byte value past the last type the protocol names, which is the one
/// a device whose test of the type is off by one serves.
pub const INFO_UNNAMED: u8 = 0x05;

/// The reply opens with a word saying how many words follow, then the flags
/// word those words belong to.  The flags word is counted by the first, so a
/// reply carrying no data at all is still these two words.
pub const INFO_HEADER_LEN: usize = 8;

/// The two UF2 types answer with their words alone (RP2350 datasheet 5.6.4.11),
/// so there is no flags word in front of them and the reply opens with the
/// count word by itself.
pub const INFO_COUNT_LEN: usize = 4;

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

    /// `picobootx::State::Idle`, as the byte the device reports.
    pub const IDLE: u8 = picobootx::State::Idle as u8;

    /// The state the byte names, or `None` for one no state has.
    ///
    /// The discriminant crosses the wire as a number, and `picobootx` is what
    /// gives it a meaning - naming the seven again here would be a second copy
    /// to keep in step.
    pub fn state(&self) -> Option<picobootx::State> {
        picobootx::State::try_from(self.state).ok()
    }
}

impl fmt::Display for Diagnostics {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "state={} halted_out={} halted_in={} in_flight={} rx={} tx={}",
            self.state()
                .map_or_else(|| String::from("?"), |s| format!("{s:?}")),
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
    /// Which of the two test firmwares answered, which is what decides
    /// anything the host has to do differently.
    pub firmware: Firmware,
    /// What the device enumerated with, which on this part is its chip
    /// identifier.  `None` where it declares no serial number.
    pub serial: Option<String>,
    ep_out: Endpoint<Bulk, Out>,
    ep_in: Endpoint<Bulk, In>,
}

impl Board {
    /// Open the one hardware test device on the bus.
    ///
    /// `want` names a firmware, and `None` takes whichever is there.  Refuses
    /// where there is not exactly one, rather than picking: two boards
    /// answering the description is a question for whoever plugged them in,
    /// not something to resolve by taking the first.
    pub async fn open(want: Option<Firmware>) -> Result<Self, String> {
        let mut found: Vec<_> = nusb::list_devices()
            .wait()
            .map_err(|e| format!("cannot list the bus: {e}"))?
            .filter_map(|d| identify(&d, want).map(|f| (d, f)))
            .collect();

        let (info, firmware) = match found.len() {
            1 => found.remove(0),
            0 => return Err(missing(want)),
            n if found.iter().any(|(_, f)| *f != found[0].1) => {
                return Err(format!(
                    "{n} boards are plugged in and not all the same firmware, so say \
                     --device embassy or --device tinyusb"
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
            firmware,
            serial,
            ep_out,
            ep_in,
        })
    }

    /// Give up the interface and the endpoints, keeping the device.
    ///
    /// A port reset is refused while an interface is claimed, so anything that
    /// resets the bus has to let go of everything below the device first.
    pub fn into_device(self) -> Device {
        let Self {
            device,
            interface,
            ep_out,
            ep_in,
            ..
        } = self;
        drop(ep_out);
        drop(ep_in);
        drop(interface);
        device
    }

    /// Send one 32 byte command header.
    pub fn send_cmd(&mut self, cmd_id: u8, transfer_len: u32, args: &[u8]) -> Result<(), String> {
        self.send_cmd_sized(cmd_id, args.len() as u8, transfer_len, args)
    }

    /// Send one command header, stating an argument size of its own.
    ///
    /// The size a command declares and the arguments it carries are separate
    /// fields on the wire, and a device has to judge the first.  Everything
    /// except a test of that judgement wants [`Board::send_cmd`], where the two
    /// agree by construction.
    pub fn send_cmd_sized(
        &mut self,
        cmd_id: u8,
        cmd_size: u8,
        transfer_len: u32,
        args: &[u8],
    ) -> Result<(), String> {
        self.send_cmd_magic(MAGIC, cmd_id, cmd_size, transfer_len, args)
    }

    /// Send one command header carrying a magic of its own.
    ///
    /// The magic is what says a command is the protocol's rather than an
    /// integrator's, so a device has to judge it.  Everything else wants
    /// [`Board::send_cmd`], where it is the protocol's by construction.
    pub fn send_cmd_magic(
        &mut self,
        magic: u32,
        cmd_id: u8,
        cmd_size: u8,
        transfer_len: u32,
        args: &[u8],
    ) -> Result<(), String> {
        let mut buf = [0u8; CMD_LEN];
        buf[0..4].copy_from_slice(&magic.to_le_bytes());
        buf[4..8].copy_from_slice(&1u32.to_le_bytes());
        buf[8] = cmd_id;
        buf[9] = cmd_size;
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

    /// Read a reply and keep every byte of it, however many there are.
    ///
    /// [`Board::read_reply`] cuts what came back down to the length asked for,
    /// which is right for reading an answer and no use for judging one: a
    /// device sending more than the transfer length allows has the excess
    /// trimmed away before anything can look at it.  This keeps the lot.
    ///
    /// `room` is how much space to offer, and it has to be more than the
    /// answer is allowed to be, since a transfer ends when the buffer fills as
    /// well as on a short packet.  A whole spare packet is what leaves an
    /// overrun somewhere to land.
    pub fn read_raw(&mut self, room: usize) -> Result<Vec<u8>, String> {
        let rounded = room.div_ceil(MAX_PACKET) * MAX_PACKET;

        self.ep_in
            .transfer_blocking(Buffer::new(rounded), TIMEOUT)
            .into_result()
            .map(nusb::transfer::Buffer::into_vec)
            .map_err(|e| format!("{e}"))
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

        // The tinyusb device reports nothing, so a run against it has the
        // clearing and the reset and not the confirmation that they worked.
        if !self.firmware.serves_diagnostics() {
            return Ok(());
        }

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
    ///
    /// Only the embassy firmware has anything to say - see
    /// [`Firmware::serves_diagnostics`].
    pub async fn diagnostics(&self) -> Result<Diagnostics, String> {
        if !self.firmware.serves_diagnostics() {
            return Err(format!(
                "the {} firmware serves no diagnostics, since the C picobootx \
                 publishes no state to report",
                self.firmware
            ));
        }

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

    /// Where the device will let a host work.
    pub async fn scratch(&self) -> Result<Scratch, String> {
        let s = self
            .device
            .control_in(
                ControlIn {
                    control_type: Vendor,
                    recipient: Recipient::Interface,
                    request: REQUEST_SCRATCH,
                    value: 0,
                    index: INTERFACE as u16,
                    length: SCRATCH_REPLY_LEN,
                },
                TIMEOUT,
            )
            .await
            .map_err(|e| format!("asking where to write failed: {e}"))?;

        if s.len() < SCRATCH_REPLY_LEN as usize {
            return Err(format!("the device answered {} bytes", s.len()));
        }
        let word = |at: usize| u32::from_le_bytes([s[at], s[at + 1], s[at + 2], s[at + 3]]);
        Ok(Scratch {
            ram: word(0),
            ram_len: word(4),
            flash: word(8),
            flash_len: word(12),
        })
    }

    /// Ask for partition information, and return the count word, the flags word
    /// and the data after them.
    ///
    /// The part answers this one, so it comes back in the shape the system kind
    /// does: 5.4.8.16 and 5.4.8.17 both put the subset of the flags that were
    /// answered in the first word of their own buffer.  What a flag is worth in
    /// words is a different question in each — a partition flag naming
    /// something the part does not have is answered with no words at all, so
    /// what follows the flags word here cannot be worked out from it.
    pub fn get_info_partition(
        &mut self,
        flags_and_partition: u32,
        words: u32,
    ) -> Result<(u32, u32, Vec<u8>), String> {
        self.get_info_flagged(INFO_PARTITION, flags_and_partition, words)
    }

    /// Ask for information of a type that answers with its words alone, and
    /// return the count word and the words after it.
    ///
    /// The two UF2 types are the ones shaped this way: what they answer is the
    /// answer itself, with nothing in front of it saying what was asked.
    /// `words` is how many of them the answer is expected to carry, which is
    /// what the transfer length is built from.
    pub fn get_info_words(
        &mut self,
        info_type: u8,
        param0: u32,
        words: u32,
    ) -> Result<(u32, Vec<u8>), String> {
        let len = INFO_COUNT_LEN as u32 + words * 4;
        let reply = self.get_info_reply(info_type, param0, len)?;

        if reply.len() < INFO_COUNT_LEN {
            return Err(format!("the reply was {} bytes", reply.len()));
        }
        let count = u32::from_le_bytes([reply[0], reply[1], reply[2], reply[3]]);
        Ok((count, reply[INFO_COUNT_LEN..].to_vec()))
    }

    /// Ask for information of a type whose answer opens with a flags word, and
    /// return the count word, that flags word and the data after them.
    fn get_info_flagged(
        &mut self,
        info_type: u8,
        param0: u32,
        words: u32,
    ) -> Result<(u32, u32, Vec<u8>), String> {
        let len = INFO_HEADER_LEN as u32 + words * 4;
        let reply = self.get_info_reply(info_type, param0, len)?;

        if reply.len() < INFO_HEADER_LEN {
            return Err(format!("the reply was {} bytes", reply.len()));
        }
        let count = u32::from_le_bytes([reply[0], reply[1], reply[2], reply[3]]);
        let answered = u32::from_le_bytes([reply[4], reply[5], reply[6], reply[7]]);
        Ok((count, answered, reply[INFO_HEADER_LEN..].to_vec()))
    }

    /// Send one `GET_INFO` at a stated transfer length and take the reply,
    /// acknowledging it the way the protocol says.
    fn get_info_reply(&mut self, info_type: u8, param0: u32, len: u32) -> Result<Vec<u8>, String> {
        let mut args = [0u8; INFO_ARGS_LEN];
        args[0] = info_type;
        args[4..8].copy_from_slice(&param0.to_le_bytes());

        self.send_cmd(CMD_GET_INFO, len, &args)?;
        let reply = self.read_reply(len as usize)?;
        self.ack()?;
        Ok(reply)
    }

    /// Send a command that carries no data either way, and collect the
    /// device's acknowledgement.
    pub fn sync_cmd(&mut self, cmd_id: u8, args: &[u8]) -> Result<(), String> {
        self.send_cmd(cmd_id, 0, args)?;
        self.read_ack()
    }

    /// Erase a range of flash, and collect the device's acknowledgement.
    ///
    /// The device is away from the bus for the whole erase — it runs with
    /// interrupts off and flash answering commands rather than reads — so the
    /// acknowledgement arriving at all is part of what this asks.
    pub fn flash_erase(&mut self, addr: u32, size: u32) -> Result<(), String> {
        let mut args = [0u8; 8];
        args[0..4].copy_from_slice(&addr.to_le_bytes());
        args[4..8].copy_from_slice(&size.to_le_bytes());

        self.send_cmd(CMD_FLASH_ERASE, 0, &args)?;
        self.read_ack()
    }

    /// Read `len` bytes from `addr`, acknowledging the transfer.
    ///
    /// One bulk transfer however long it is, which is what a host does — the
    /// stack issues as many IN tokens as the length needs, and a transfer
    /// shorter than a whole packet ends on the short packet.
    pub fn read_mem(&mut self, addr: u32, len: u32) -> Result<Vec<u8>, String> {
        let mut args = [0u8; 8];
        args[0..4].copy_from_slice(&addr.to_le_bytes());
        args[4..8].copy_from_slice(&len.to_le_bytes());

        self.send_cmd(CMD_READ, len, &args)?;
        let data = self.read_reply(len as usize)?;
        self.ack()?;
        Ok(data)
    }

    /// Write `data` at `addr`, and collect the device's acknowledgement.
    pub fn write_mem(&mut self, addr: u32, data: &[u8]) -> Result<(), String> {
        let mut args = [0u8; 8];
        args[0..4].copy_from_slice(&addr.to_le_bytes());
        args[4..8].copy_from_slice(&(data.len() as u32).to_le_bytes());

        self.send_cmd(CMD_WRITE, data.len() as u32, &args)?;
        self.send_data(data)?;
        self.read_ack()
    }

    /// Ask for system information, and return the count word, the flags word
    /// and the data after them.
    ///
    /// `words` is how many words of data the answer is expected to carry, which
    /// is what the transfer length is built from — the protocol leaves that
    /// length to the host, so getting it wrong is one of the things worth asking
    /// a device about.  A device that cannot fit its answer in the length given
    /// refuses the command rather than sending part of it.  What the answer
    /// carries is not what was asked for: a flag the part cannot answer is
    /// dropped and is worth no words, so a length sized to the request would be
    /// longer than the reply.
    pub fn get_info_sys(&mut self, flags: u32, words: u32) -> Result<(u32, u32, Vec<u8>), String> {
        self.get_info_flagged(INFO_SYS, flags, words)
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

/// Which test firmware this device is, where it is one and one the caller
/// asked for.
fn identify(d: &nusb::DeviceInfo, want: Option<Firmware>) -> Option<Firmware> {
    if d.vendor_id() != VID || d.product_id() != PID {
        return None;
    }
    let product = d.product_string()?;
    Firmware::ALL
        .into_iter()
        .find(|f| f.product() == product)
        .filter(|f| want.is_none_or(|w| w == *f))
}

/// What to say when nothing answered.
fn missing(want: Option<Firmware>) -> String {
    let (which, flash) = match want {
        Some(f) => (format!("the {f} firmware"), format!("test/hw/device-{f}")),
        None => (
            String::from("either test firmware"),
            String::from("one of test/hw/device-embassy and test/hw/device-tinyusb"),
        ),
    };
    format!(
        "no device running {which} ({VID:04x}:{PID:04x}).  Flash {flash} onto the board, or \
         put it back with picobootx-hw-bootsel if it is already running a test firmware"
    )
}

/// Whether that firmware is on the bus at all.
pub fn present(want: Firmware) -> bool {
    nusb::list_devices()
        .wait()
        .map(|mut d| d.any(|d| identify(&d, Some(want)).is_some()))
        .unwrap_or(false)
}

/// Wait for the board to leave the bus, which is how a reboot is seen from
/// here.  Returns how long it took to see it go.
///
/// How long a device is away is a property of how fast its firmware gets back
/// on the bus, not of the reboot: measured on one board, the embassy firmware
/// is absent for a fifth of a second and the tinyusb one for seven
/// milliseconds.  So this polls every millisecond rather than on the fifty the
/// other waits settle for, which would see the first and miss the second and
/// call a device that rebooted correctly a device that never rebooted.
pub async fn wait_gone(want: Firmware, within: Duration) -> Result<Duration, String> {
    let start = std::time::Instant::now();
    if wait_every(POLL, within, || !present(want)).await {
        Ok(start.elapsed())
    } else {
        Err(format!("it was still on the bus after {within:?}"))
    }
}

/// Wait for the board to come back, and open it.
///
/// Enumerating and being ready to answer are not the same moment, so the open
/// is retried rather than made once the moment it appears.  It has to come
/// back as what it was: a reboot that brought up the other firmware would be a
/// different board answering the rest of the run.
pub async fn wait_back(want: Firmware, within: Duration) -> Result<Board, String> {
    if !wait_until(within, || present(want)).await {
        return Err(format!("it did not come back within {within:?}"));
    }
    let mut last = String::new();
    for _ in 0..40 {
        match Board::open(Some(want)).await {
            Ok(b) => return Ok(b),
            Err(e) => last = e,
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    Err(format!("it came back but would not open: {last}"))
}

/// How often a wait that is only watching for the board to come back looks.
const SETTLE: Duration = Duration::from_millis(50);

/// How often a wait that has to catch a short outage looks.
const POLL: Duration = Duration::from_millis(1);

async fn wait_until(within: Duration, done: impl FnMut() -> bool) -> bool {
    wait_every(SETTLE, within, done).await
}

async fn wait_every(interval: Duration, within: Duration, mut done: impl FnMut() -> bool) -> bool {
    let deadline = std::time::Instant::now() + within;
    loop {
        if done() {
            return true;
        }
        if std::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(interval).await;
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
