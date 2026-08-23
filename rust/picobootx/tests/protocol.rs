// Copyright (C) 2026 Piers Finlayson <piers@piers.rocks>
//
// MIT License

//! The protocol driven as a Rust integrator drives it.
//!
//! The conformance suite reaches the same state machine through the C ABI, and
//! everything here is something that ABI cannot express: an `Ops` that leaves a
//! method to its default, the accessors that hand the operations back, and a
//! `Custom::fill` that reports more bytes than it was given room for.

use picobootx::wire::{CMD_LEN, DIR_IN, MAGIC, STATUS_LEN};
use picobootx::{
    Command, Control, Custom, Direction, Endpoints, Filled, NoCustom, Ops, Picoboot, Reboot,
    Recipient, Request, RequestType, Stage, State, Status, Transport,
};

const EP_OUT: u8 = 0x03;
const EP_IN: u8 = 0x84;

const CMD_FLASH_ERASE: u8 = 0x03;
const CMD_EXIT_XIP: u8 = 0x06;
const CMD_REBOOT2: u8 = 0x0a;
const CMD_READ: u8 = 0x84;

/// The magic a device of our own would carry.  Not `MAGIC`.
const OURS: u32 = 0x5ac3_e17b;

/// The buffer the library fills a device-to-host packet from, which is the
/// most it ever offers a fill on one call.  Named here because a transmit FIFO
/// larger than this is what makes the buffer, rather than the FIFO, the limit
/// the fill is held to.
const PUMP_BUF: usize = 64;

// ---------------------------------------------------------------------------
// The wire
// ---------------------------------------------------------------------------

/// The two bulk endpoints as a pair of queues.
///
/// `tx_capacity` is the transmit FIFO an integrator sizes, and it is what
/// decides how much room a fill is offered on one call.
struct Wire {
    rx: Vec<u8>,
    fifo: Vec<u8>,
    sent: Vec<u8>,
    tx_capacity: usize,
    acks: usize,
    stalled_out: bool,
    stalled_in: bool,
}

impl Wire {
    fn new(tx_capacity: usize) -> Self {
        Self {
            rx: Vec::new(),
            fifo: Vec::new(),
            sent: Vec::new(),
            tx_capacity,
            acks: 0,
            stalled_out: false,
            stalled_in: false,
        }
    }

    fn host_send(&mut self, bytes: &[u8]) {
        self.rx.extend_from_slice(bytes);
    }
}

impl Transport for Wire {
    fn rx_available(&self) -> u32 {
        self.rx.len() as u32
    }

    fn rx_read(&mut self, buf: &mut [u8]) -> u32 {
        let n = buf.len().min(self.rx.len());
        buf[..n].copy_from_slice(&self.rx[..n]);
        self.rx.drain(..n);
        n as u32
    }

    fn rx_clear(&mut self) {
        self.rx.clear();
    }

    fn tx_available(&self) -> u32 {
        (self.tx_capacity - self.fifo.len()) as u32
    }

    fn tx_write(&mut self, buf: &[u8]) -> u32 {
        let n = buf.len().min(self.tx_capacity - self.fifo.len());
        self.fifo.extend_from_slice(&buf[..n]);
        n as u32
    }

    fn tx_flush(&mut self) -> u32 {
        let n = self.fifo.len();
        self.sent.append(&mut self.fifo);
        n as u32
    }

    fn tx_clear(&mut self) {
        self.fifo.clear();
    }

    fn send_ack(&mut self) -> bool {
        self.acks += 1;
        true
    }

    fn is_stalled(&self, dir: Direction) -> bool {
        match dir {
            Direction::Out => self.stalled_out,
            Direction::In => self.stalled_in,
        }
    }

    fn set_stalled(&mut self, dir: Direction, stalled: bool) {
        match dir {
            Direction::Out => self.stalled_out = stalled,
            Direction::In => self.stalled_in = stalled,
        }
    }
}

// ---------------------------------------------------------------------------
// Command packets
// ---------------------------------------------------------------------------

fn packet(magic: u32, cmd_id: u8, cmd_size: u8, transfer_len: u32) -> [u8; CMD_LEN] {
    let mut buf = [0u8; CMD_LEN];
    buf[0..4].copy_from_slice(&magic.to_le_bytes());
    buf[4..8].copy_from_slice(&0x0000_00a5u32.to_le_bytes());
    buf[8] = cmd_id;
    buf[9] = cmd_size;
    buf[12..16].copy_from_slice(&transfer_len.to_le_bytes());
    buf
}

fn read_packet(addr: u32, size: u32) -> [u8; CMD_LEN] {
    let mut buf = packet(MAGIC, CMD_READ, 0x08, size);
    buf[16..20].copy_from_slice(&addr.to_le_bytes());
    buf[20..24].copy_from_slice(&size.to_le_bytes());
    buf
}

fn status_request() -> Request {
    Request {
        request_type: RequestType::Vendor,
        recipient: Recipient::Interface,
        dir_in: true,
        request: 0x42, // GET_COMMAND_STATUS
        value: 0,
        index: 0,
        length: STATUS_LEN as u16,
    }
}

/// The status code the device would answer `GET_COMMAND_STATUS` with.
fn status_code<O: Ops, C: Custom>(pb: &mut Picoboot<'_, O, C>, wire: &mut Wire) -> u32 {
    let Control::Reply(block) = pb.on_control(wire, &status_request(), Stage::Setup) else {
        panic!("GET_COMMAND_STATUS was not answered with a status block");
    };
    u32::from_le_bytes([block[4], block[5], block[6], block[7]])
}

// ---------------------------------------------------------------------------
// The devices
// ---------------------------------------------------------------------------

/// A device that writes no operation at all.
struct Bare;

impl Ops for Bare {}

/// A device that serves READ, and nothing else.
struct Reader;

impl Ops for Reader {
    fn read_prepare(&mut self, addr: u32, size: u32) -> picobootx::Result {
        let _ = (addr, size);
        Ok(())
    }

    fn read(&mut self, addr: u32, buf: &mut [u8]) -> picobootx::Result {
        for (i, b) in buf.iter_mut().enumerate() {
            *b = (addr as u8).wrapping_add(i as u8);
        }
        Ok(())
    }
}

/// A device that changes its mind about EXIT_XIP when told to.
struct Switch {
    refuse: Option<Status>,
}

impl Ops for Switch {
    fn exit_xip(&mut self) -> picobootx::Result {
        match self.refuse {
            None => Ok(()),
            Some(status) => Err(status),
        }
    }
}

/// A device that agrees to reboot and leaves `reboot_execute` to its default.
struct RebootsQuietly;

impl Ops for RebootsQuietly {
    fn reboot_prepare(&mut self, args: &Reboot) -> picobootx::Result {
        let _ = args;
        Ok(())
    }
}

/// The same, with the reboot itself written.
struct RebootsLoudly {
    went: Option<Reboot>,
}

impl Ops for RebootsLoudly {
    fn reboot_prepare(&mut self, args: &Reboot) -> picobootx::Result {
        let _ = args;
        Ok(())
    }

    fn reboot_execute(&mut self, args: &Reboot) {
        self.went = Some(*args);
    }
}

/// Commands of our own, whose magic can be taken away and given back.
struct Ours {
    magic: Option<u32>,
    dispatched: usize,
}

impl Custom for Ours {
    fn magic(&self) -> Option<u32> {
        self.magic
    }

    fn dispatch(&mut self, cmd: &Command) -> picobootx::Result {
        let _ = cmd;
        self.dispatched += 1;
        Ok(())
    }
}

/// A fill that reports `over` bytes more than the room it was handed.
struct Overreporting {
    over: usize,
}

impl Custom for Overreporting {
    fn magic(&self) -> Option<u32> {
        Some(OURS)
    }

    fn dispatch(&mut self, cmd: &Command) -> picobootx::Result {
        let _ = cmd;
        Ok(())
    }

    fn fill(&mut self, cmd: &Command, buf: &mut [u8]) -> core::result::Result<Filled, Status> {
        let _ = cmd;
        buf.fill(0x5a);
        Ok(Filled::Done(buf.len() + self.over))
    }
}

fn endpoints() -> Endpoints {
    Endpoints {
        out: EP_OUT,
        r#in: EP_IN,
    }
}

// ---------------------------------------------------------------------------
// Scenarios
// ---------------------------------------------------------------------------

#[test]
fn a_command_no_operation_was_written_for_is_refused_on_the_wire() {
    // The device that has not written READ halts and says why.
    let mut wire = Wire::new(64);
    let mut pb = Picoboot::new(Bare, NoCustom, None, endpoints());

    wire.host_send(&read_packet(0x2000_0000, 8));
    pb.poll(&mut wire);

    assert_eq!(pb.state(), State::Stalled);
    assert!(wire.is_stalled(Direction::In));
    assert_eq!(status_code(&mut pb, &mut wire), Status::UnknownCmd as u32);
    assert!(wire.sent.is_empty());

    // The one thing changed: a device that writes the pair serves the same
    // command and the bytes arrive.
    let mut wire = Wire::new(64);
    let mut pb = Picoboot::new(Reader, NoCustom, None, endpoints());

    wire.host_send(&read_packet(0x2000_0000, 8));
    pb.poll(&mut wire);
    pb.poll(&mut wire);

    assert_eq!(pb.state(), State::AwaitAck);
    assert_eq!(wire.sent, vec![0, 1, 2, 3, 4, 5, 6, 7]);
    assert_eq!(status_code(&mut pb, &mut wire), Status::Ok as u32);
}

#[test]
fn a_command_the_device_serves_and_the_protocol_does_not_is_refused() {
    // FLASH_ERASE reaches flash_erase_prepare, which Bare leaves defaulted.
    // The refusal is the operation's, not the command table's, which is what
    // separates this from an identifier the protocol has never heard of.
    let mut wire = Wire::new(64);
    let mut pb = Picoboot::new(Bare, NoCustom, None, endpoints());

    let mut cmd = packet(MAGIC, CMD_FLASH_ERASE, 0x08, 0);
    cmd[16..20].copy_from_slice(&0x1000_0000u32.to_le_bytes());
    cmd[20..24].copy_from_slice(&4096u32.to_le_bytes());
    wire.host_send(&cmd);
    pb.poll(&mut wire);

    assert_eq!(pb.state(), State::Stalled);
    assert_eq!(status_code(&mut pb, &mut wire), Status::UnknownCmd as u32);
}

#[test]
fn the_operations_stay_reachable_once_the_protocol_holds_them() {
    let mut wire = Wire::new(64);
    let mut pb = Picoboot::new(Switch { refuse: None }, NoCustom, None, endpoints());

    wire.host_send(&packet(MAGIC, CMD_EXIT_XIP, 0x00, 0));
    pb.poll(&mut wire);
    assert_eq!(pb.state(), State::AwaitZlp);
    assert_eq!(wire.acks, 1);
    pb.on_tx(0);
    assert_eq!(pb.state(), State::Idle);

    // Reach past the protocol and change the device's mind.  The accessor has
    // to hand back the operations the state machine is using, not a copy of
    // what they were.
    pb.ops().refuse = Some(Status::InvalidState);

    wire.host_send(&packet(MAGIC, CMD_EXIT_XIP, 0x00, 0));
    pb.poll(&mut wire);
    assert_eq!(pb.state(), State::Stalled);
    assert_eq!(wire.acks, 1);
    assert_eq!(status_code(&mut pb, &mut wire), Status::InvalidState as u32);
}

#[test]
fn the_custom_commands_stay_reachable_once_the_protocol_holds_them() {
    let mut wire = Wire::new(64);
    let custom = Ours {
        magic: None,
        dispatched: 0,
    };
    let mut pb = Picoboot::new(Bare, custom, None, endpoints());

    // No magic named, so a command carrying ours is not ours.
    wire.host_send(&packet(OURS, 0x01, 0x00, 0));
    pb.poll(&mut wire);
    assert_eq!(pb.state(), State::Stalled);
    assert_eq!(status_code(&mut pb, &mut wire), Status::UnknownCmd as u32);
    assert_eq!(pb.custom().dispatched, 0);

    // Name it through the accessor, and the same packet is dispatched.
    pb.custom().magic = Some(OURS);
    pb.on_control(&mut wire, &interface_reset(), Stage::Setup);

    wire.host_send(&packet(OURS, 0x01, 0x00, 0));
    pb.poll(&mut wire);
    assert_eq!(pb.state(), State::AwaitZlp);
    assert_eq!(pb.custom().dispatched, 1);
}

fn interface_reset() -> Request {
    Request {
        request_type: RequestType::Vendor,
        recipient: Recipient::Interface,
        dir_in: false,
        request: 0x41,
        value: 0,
        index: 0,
        length: 0,
    }
}

#[test]
fn a_fill_that_reports_more_than_the_room_it_was_given_is_refused() {
    // The room offered is the smaller of the transmit FIFO's and the library's
    // own buffer, so the FIFO is sized here to be the larger of the two.  What
    // the fill is then handed is the whole of that buffer, and one byte more
    // than that is a byte past the end of it — which is the read this refusal
    // exists to prevent, and is not something the transport could catch on the
    // library's behalf afterwards.
    let mut wire = Wire::new(PUMP_BUF);
    let mut pb = Picoboot::new(Bare, Overreporting { over: 1 }, None, endpoints());

    wire.host_send(&packet(OURS, 0x01 | DIR_IN, 0x00, PUMP_BUF as u32));
    pb.poll(&mut wire);
    assert_eq!(pb.state(), State::CustomIn);

    pb.poll(&mut wire);
    assert_eq!(pb.state(), State::Stalled);
    assert_eq!(status_code(&mut pb, &mut wire), Status::UnknownError as u32);
    assert!(wire.sent.is_empty());

    // The one thing changed: the same fill, reporting what it was actually
    // handed, completes the transfer.
    let mut wire = Wire::new(PUMP_BUF);
    let mut pb = Picoboot::new(Bare, Overreporting { over: 0 }, None, endpoints());

    wire.host_send(&packet(OURS, 0x01 | DIR_IN, 0x00, PUMP_BUF as u32));
    pb.poll(&mut wire);
    pb.poll(&mut wire);

    assert_eq!(pb.state(), State::AwaitAck);
    assert_eq!(wire.sent, vec![0x5a; PUMP_BUF]);
}

#[test]
fn a_device_that_writes_no_reboot_answers_and_stays_where_it_is() {
    let mut wire = Wire::new(64);
    let mut pb = Picoboot::new(RebootsQuietly, NoCustom, None, endpoints());

    wire.host_send(&packet(MAGIC, CMD_REBOOT2, 0x10, 0));
    pb.poll(&mut wire);
    assert_eq!(pb.state(), State::AwaitZlp);
    assert_eq!(wire.acks, 1);

    // The acknowledgement has gone, which is when the reboot would happen.
    pb.on_tx(0);
    assert_eq!(pb.state(), State::Idle);

    // Still serving, because nothing rebooted.
    wire.host_send(&packet(MAGIC, CMD_EXIT_XIP, 0x00, 0));
    pb.poll(&mut wire);
    assert_eq!(pb.state(), State::AwaitZlp);
    assert_eq!(wire.acks, 2);

    // The one thing changed: a device that writes reboot_execute is called,
    // with the arguments the command carried, at that same point.
    let mut wire = Wire::new(64);
    let mut pb = Picoboot::new(RebootsLoudly { went: None }, NoCustom, None, endpoints());

    let mut cmd = packet(MAGIC, CMD_REBOOT2, 0x10, 0);
    cmd[16..20].copy_from_slice(&2u32.to_le_bytes());
    cmd[20..24].copy_from_slice(&50u32.to_le_bytes());
    wire.host_send(&cmd);
    pb.poll(&mut wire);
    assert!(pb.ops().went.is_none());

    pb.on_tx(0);
    let went = pb.ops().went.expect("the reboot was not run");
    assert_eq!(went.flags, 2);
    assert_eq!(went.delay_ms, 50);
}
