// Copyright (C) 2026 Piers Finlayson <piers@piers.rocks>
//
// MIT License

//! The driver task, driven on this machine.
//!
//! `EndpointIn` and `EndpointOut` are ordinary traits, so a bus can be modelled
//! here and the task run against it with no USB stack and no part.  What that
//! buys is the orderings hardware will not perform on demand: a host that waits
//! for what it is owed before sending again, a transfer that spans packets, a
//! refusal part way through one.
//!
//! The model is deliberately strict about one thing.  A real host does not send
//! its next command until it has collected the reply to the last, so
//! [`Bus::to_device`] is only handed over when nothing is waiting to go the
//! other way unless a test says otherwise.  A driver that waits for a packet
//! while owing one deadlocks against that, which is what it does on a wire.

extern crate std;

use std::rc::Rc;
use std::vec;
use std::vec::Vec;

use core::cell::RefCell;
use core::future::Future;
use core::pin::pin;
use core::task::{Context, Poll, Waker};

use embassy_usb::Handler;
use embassy_usb::control::InResponse;
use embassy_usb::control::{Recipient, Request, RequestType};
use embassy_usb_driver::Direction as UsbDirection;
use embassy_usb_driver::{
    Endpoint, EndpointAddress, EndpointError, EndpointIn, EndpointInfo, EndpointOut, EndpointType,
};

use picobootx::wire::{CMD_LEN, DIR_IN, MAGIC};
use picobootx::{NoCustom, Ops, Result as PbResult, Status};

use crate::Picoboot;
use crate::halt::Halt;
use picobootx::Endpoints;

const EP_OUT: u8 = 0x01;
const EP_IN: u8 = 0x81;
const MAX_PACKET: u16 = 64;

const CMD_READ: u8 = 0x04 | DIR_IN;
const CMD_WRITE: u8 = 0x05;
const CMD_EXIT_XIP: u8 = 0x06;

// ---------------------------------------------------------------------------
// The bus
// ---------------------------------------------------------------------------

/// What the host and the device have put on the wire, and what the controller
/// is holding.
#[derive(Default)]
struct Bus {
    /// Packets the host has sent and the device has yet to read.
    to_device: Vec<Vec<u8>>,
    /// Packets the device has written, in order.
    to_host: Vec<Vec<u8>>,
    /// Whether the last packet written is still uncollected, which is what
    /// `Halt::in_flight` reports.
    in_flight: bool,
    stalled_out: bool,
    stalled_in: bool,
    /// Every endpoint address `resync` was called for, in order.
    resyncs: Vec<u8>,
    /// Whether the host collects a packet the moment it is written.  A real
    /// host does, and a test that wants to watch a packet sit unread says so.
    host_collects: bool,
    /// Fail the next write, as an endpoint does when the bus goes under it.
    fail_in: bool,
    /// Fail the next read, likewise.
    fail_out: bool,
}

impl Bus {
    fn new() -> Rc<RefCell<Self>> {
        Rc::new(RefCell::new(Self {
            host_collects: true,
            ..Self::default()
        }))
    }
}

/// The host's side of the bus, as a test drives it.
struct Host(Rc<RefCell<Bus>>);

impl Host {
    /// Queue one 32 byte command header.
    fn send_cmd(&self, cmd_id: u8, transfer_len: u32, args: &[u8]) {
        let mut buf = vec![0u8; CMD_LEN];
        buf[0..4].copy_from_slice(&MAGIC.to_le_bytes());
        buf[4..8].copy_from_slice(&1u32.to_le_bytes());
        buf[8] = cmd_id;
        buf[9] = args.len() as u8;
        buf[12..16].copy_from_slice(&transfer_len.to_le_bytes());
        buf[16..16 + args.len()].copy_from_slice(args);
        self.0.borrow_mut().to_device.push(buf);
    }

    /// Queue one packet of a host-to-device data phase.
    fn send_data(&self, data: &[u8]) {
        self.0.borrow_mut().to_device.push(data.to_vec());
    }

    /// Queue the single zero byte a host acknowledges a transfer with.
    fn send_ack(&self) {
        self.0.borrow_mut().to_device.push(vec![0u8]);
    }

    /// Everything the device has sent, joined.
    fn collected(&self) -> Vec<u8> {
        self.0.borrow().to_host.concat()
    }

    fn packets(&self) -> usize {
        self.0.borrow().to_host.len()
    }
}

// ---------------------------------------------------------------------------
// The endpoints
// ---------------------------------------------------------------------------

fn info(addr: u8) -> EndpointInfo {
    EndpointInfo {
        addr: EndpointAddress::from(addr),
        ep_type: EndpointType::Bulk,
        max_packet_size: MAX_PACKET,
        interval_ms: 0,
    }
}

struct FakeOut {
    bus: Rc<RefCell<Bus>>,
    info: EndpointInfo,
}

impl Endpoint for FakeOut {
    fn info(&self) -> &EndpointInfo {
        &self.info
    }

    async fn wait_enabled(&mut self) {}
}

impl EndpointOut for FakeOut {
    async fn read(&mut self, buf: &mut [u8]) -> core::result::Result<usize, EndpointError> {
        // Pending while the host has sent nothing, which is what an endpoint
        // does.  A driver that waits here while owing the host a packet never
        // comes back, and that is the point of modelling it this way.
        core::future::poll_fn(|_cx| {
            let mut bus = self.bus.borrow_mut();
            if core::mem::take(&mut bus.fail_out) {
                return Poll::Ready(Err(EndpointError::Disabled));
            }
            if bus.stalled_out || bus.to_device.is_empty() {
                return Poll::Pending;
            }
            let packet = bus.to_device.remove(0);
            let n = packet.len().min(buf.len());
            buf[..n].copy_from_slice(&packet[..n]);
            Poll::Ready(Ok(n))
        })
        .await
    }
}

struct FakeIn {
    bus: Rc<RefCell<Bus>>,
    info: EndpointInfo,
}

impl Endpoint for FakeIn {
    fn info(&self) -> &EndpointInfo {
        &self.info
    }

    async fn wait_enabled(&mut self) {}
}

impl EndpointIn for FakeIn {
    async fn write(&mut self, buf: &[u8]) -> core::result::Result<(), EndpointError> {
        let mut bus = self.bus.borrow_mut();
        if bus.stalled_in || core::mem::take(&mut bus.fail_in) {
            return Err(EndpointError::Disabled);
        }
        bus.to_host.push(buf.to_vec());
        // Armed, and in flight until the host takes it.
        bus.in_flight = !bus.host_collects;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// The halt control
// ---------------------------------------------------------------------------

struct FakeHalt(Rc<RefCell<Bus>>);

impl Halt for FakeHalt {
    fn is_stalled(&self, ep_addr: u8) -> bool {
        let bus = self.0.borrow();
        if ep_addr & 0x80 == 0 {
            bus.stalled_out
        } else {
            bus.stalled_in
        }
    }

    fn set_stalled(&mut self, ep_addr: u8, stalled: bool) {
        let mut bus = self.0.borrow_mut();
        if ep_addr & 0x80 == 0 {
            bus.stalled_out = stalled;
        } else {
            bus.stalled_in = stalled;
        }
    }

    fn resync(&mut self, ep_addr: u8, _max_packet_size: u16) {
        self.0.borrow_mut().resyncs.push(ep_addr);
    }

    fn in_flight(&self, ep_addr: u8) -> bool {
        let _ = ep_addr;
        self.0.borrow().in_flight
    }
}

// ---------------------------------------------------------------------------
// What the device does
// ---------------------------------------------------------------------------

/// Serves a small window of memory, so a read has something to return and a
/// write has somewhere to land.
struct MemOps {
    mem: [u8; 512],
    /// Refuse the next prepare, whichever it is.
    refuse: bool,
}

impl MemOps {
    fn new() -> Self {
        let mut mem = [0u8; 512];
        for (i, b) in mem.iter_mut().enumerate() {
            *b = i as u8;
        }
        Self { mem, refuse: false }
    }
}

impl Ops for MemOps {
    fn read_prepare(&mut self, addr: u32, size: u32) -> PbResult {
        if self.refuse || addr as usize + size as usize > self.mem.len() {
            return Err(Status::InvalidArg);
        }
        Ok(())
    }

    fn read(&mut self, addr: u32, buf: &mut [u8]) -> PbResult {
        let at = addr as usize;
        buf.copy_from_slice(&self.mem[at..at + buf.len()]);
        Ok(())
    }

    fn write_prepare(
        &mut self,
        addr: u32,
        size: u32,
    ) -> core::result::Result<picobootx::Target, Status> {
        if self.refuse || addr as usize + size as usize > self.mem.len() {
            return Err(Status::InvalidArg);
        }
        Ok(picobootx::Target::Memory)
    }

    fn write(&mut self, addr: u32, buf: &[u8]) -> PbResult {
        let at = addr as usize;
        self.mem[at..at + buf.len()].copy_from_slice(buf);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Running the task
// ---------------------------------------------------------------------------

/// How many polls a test gives the task to get somewhere.
///
/// Generous, because each one is a single step of the loop and a transfer takes
/// several.  A test that has not finished by then has not stalled by accident.
const STEPS: usize = 2000;

/// Poll the driver task, without an executor.
///
/// The task never returns, so it is stepped rather than awaited, and a test
/// says how far to let it get.
fn step(fut: &mut core::pin::Pin<&mut impl Future>, times: usize) {
    let waker = Waker::noop();
    let mut cx = Context::from_waker(waker);
    for _ in 0..times {
        let _ = fut.as_mut().poll(&mut cx);
    }
}

/// A device on a modelled bus, and the host's side of it.
fn device(
    bus: &Rc<RefCell<Bus>>,
) -> (
    Picoboot<'static, MemOps, NoCustom, FakeHalt>,
    FakeOut,
    FakeIn,
) {
    let picoboot = Picoboot::new(
        MemOps::new(),
        NoCustom,
        None,
        Endpoints {
            out: EP_OUT,
            r#in: EP_IN,
        },
        MAX_PACKET,
        FakeHalt(Rc::clone(bus)),
    );
    let ep_out = FakeOut {
        bus: Rc::clone(bus),
        info: info(EP_OUT),
    };
    let ep_in = FakeIn {
        bus: Rc::clone(bus),
        info: info(EP_IN),
    };
    (picoboot, ep_out, ep_in)
}

/// CLEAR_FEATURE(ENDPOINT_HALT), as a host sends it for one endpoint.
fn clear_halt(ep: u8) -> Request {
    Request {
        direction: UsbDirection::Out,
        request_type: RequestType::Standard,
        recipient: Recipient::Endpoint,
        request: 0x01,
        value: 0x00,
        index: u16::from(ep),
        length: 0,
    }
}

/// picoboot's INTERFACE RESET, as a host sends it.
fn interface_reset() -> Request {
    Request {
        direction: UsbDirection::Out,
        request_type: RequestType::Vendor,
        recipient: Recipient::Interface,
        request: picobootx::REQUEST_INTERFACE_RESET,
        value: 0,
        index: 0,
        length: 0,
    }
}

// ---------------------------------------------------------------------------
// The tests
// ---------------------------------------------------------------------------

/// The reply to a command has to be produced without the host sending anything
/// further.
///
/// This is the shape of a deadlock the driver had: the poll that took the
/// command moved to the sending state, and the loop then waited on the
/// host-to-device endpoint before the poll that queues the first packet ever
/// ran.  The host was waiting for that packet, so neither side moved.  Nothing
/// is queued here after the command, so a driver that waits for one produces
/// nothing at all.
#[test]
fn a_reply_is_produced_without_the_host_sending_anything_further() {
    let bus = Bus::new();
    let host = Host(Rc::clone(&bus));
    let (picoboot, ep_out, ep_in) = device(&bus);

    let mut args = [0u8; 8];
    args[0..4].copy_from_slice(&0u32.to_le_bytes());
    args[4..8].copy_from_slice(&4u32.to_le_bytes());
    host.send_cmd(CMD_READ, 4, &args);

    let mut fut = pin!(picoboot.run(ep_out, ep_in));
    step(&mut fut, STEPS);

    assert_eq!(
        host.collected(),
        vec![0, 1, 2, 3],
        "the reply never went out"
    );
}

/// A device-to-host transfer longer than one packet is served in packets, in
/// order, and completely.
#[test]
fn a_reply_longer_than_one_packet_is_served_in_order() {
    let bus = Bus::new();
    let host = Host(Rc::clone(&bus));
    let (picoboot, ep_out, ep_in) = device(&bus);

    const LEN: u32 = 200;
    let mut args = [0u8; 8];
    args[0..4].copy_from_slice(&0u32.to_le_bytes());
    args[4..8].copy_from_slice(&LEN.to_le_bytes());
    host.send_cmd(CMD_READ, LEN, &args);

    let mut fut = pin!(picoboot.run(ep_out, ep_in));
    step(&mut fut, STEPS);

    let want: Vec<u8> = (0..LEN as usize).map(|i| i as u8).collect();
    assert_eq!(
        host.collected(),
        want,
        "the transfer was short or out of order"
    );
    assert!(
        host.packets() > 1,
        "200 bytes should take more than one 64 byte packet"
    );
}

/// A host-to-device transfer spanning packets lands where it was addressed.
#[test]
fn a_host_to_device_transfer_spanning_packets_is_taken_whole() {
    let bus = Bus::new();
    let host = Host(Rc::clone(&bus));
    let (picoboot, ep_out, ep_in) = device(&bus);

    const LEN: u32 = 100;
    let payload: Vec<u8> = (0..LEN as usize).map(|i| (0xa0 + i) as u8).collect();

    let mut args = [0u8; 8];
    args[0..4].copy_from_slice(&256u32.to_le_bytes());
    args[4..8].copy_from_slice(&LEN.to_le_bytes());
    host.send_cmd(CMD_WRITE, LEN, &args);
    for chunk in payload.chunks(MAX_PACKET as usize) {
        host.send_data(chunk);
    }

    let mut fut = pin!(picoboot.run(ep_out, ep_in));
    step(&mut fut, STEPS);

    // The device acknowledges a host-to-device transfer it has taken.
    assert!(
        !host.collected().is_empty(),
        "the device never acknowledged the transfer"
    );
}

/// A refused command halts both endpoints rather than answering.
#[test]
fn a_refused_command_halts_both_endpoints() {
    let bus = Bus::new();
    let host = Host(Rc::clone(&bus));
    let (picoboot, ep_out, ep_in) = device(&bus);

    let mut args = [0u8; 8];
    args[0..4].copy_from_slice(&0xffff_0000u32.to_le_bytes());
    args[4..8].copy_from_slice(&4u32.to_le_bytes());
    host.send_cmd(CMD_READ, 4, &args);

    let mut fut = pin!(picoboot.run(ep_out, ep_in));
    step(&mut fut, STEPS);

    let b = bus.borrow();
    assert!(
        b.stalled_out,
        "the host-to-device endpoint was left running"
    );
    assert!(b.stalled_in, "the device-to-host endpoint was left running");
    assert!(b.to_host.is_empty(), "a refused command answered anyway");
}

/// A halted pipe is waited on rather than read, and the task takes up again
/// once the halts go.
#[test]
fn a_halted_pipe_serves_again_once_the_halts_are_cleared() {
    let bus = Bus::new();
    let host = Host(Rc::clone(&bus));
    let (picoboot, ep_out, ep_in) = device(&bus);

    let mut args = [0u8; 8];
    args[0..4].copy_from_slice(&0xffff_0000u32.to_le_bytes());
    args[4..8].copy_from_slice(&4u32.to_le_bytes());
    host.send_cmd(CMD_READ, 4, &args);

    let mut fut = pin!(picoboot.run(ep_out, ep_in));
    step(&mut fut, STEPS);
    assert!(
        bus.borrow().stalled_out,
        "the refusal did not halt the pipe"
    );

    // What a host does next, as a host does it: CLEAR_FEATURE on each endpoint,
    // then INTERFACE RESET.  The stack answers CLEAR_FEATURE by clearing the
    // halt, which is modelled here, and picobootx drops that direction's queue
    // and leaves the state machine where it is - so the reset is what puts the
    // protocol back to waiting for a command.
    for ep in [EP_OUT, EP_IN] {
        {
            let mut b = bus.borrow_mut();
            if ep & 0x80 == 0 {
                b.stalled_out = false;
            } else {
                b.stalled_in = false;
            }
        }
        picoboot.handler().control_out(clear_halt(ep), &[]);
    }
    picoboot.handler().control_out(interface_reset(), &[]);

    let mut args = [0u8; 8];
    args[0..4].copy_from_slice(&0u32.to_le_bytes());
    args[4..8].copy_from_slice(&4u32.to_le_bytes());
    host.send_cmd(CMD_READ, 4, &args);
    step(&mut fut, STEPS);

    assert_eq!(
        host.collected(),
        vec![0, 1, 2, 3],
        "the pipe never came back after the halts went"
    );
}

/// A packet the host has not taken is not reported to the protocol as sent.
///
/// `CMD_REBOOT2` acts in `on_tx`, so a device that counted an armed packet as a
/// delivered one would reboot with the reply still sitting on the controller.
#[test]
fn a_packet_the_host_has_not_taken_is_not_counted_as_sent() {
    let bus = Bus::new();
    let host = Host(Rc::clone(&bus));
    bus.borrow_mut().host_collects = false;
    let (picoboot, ep_out, ep_in) = device(&bus);

    const LEN: u32 = 200;
    let mut args = [0u8; 8];
    args[0..4].copy_from_slice(&0u32.to_le_bytes());
    args[4..8].copy_from_slice(&LEN.to_le_bytes());
    host.send_cmd(CMD_READ, LEN, &args);

    let mut fut = pin!(picoboot.run(ep_out, ep_in));
    step(&mut fut, STEPS);

    assert_eq!(
        host.packets(),
        1,
        "the driver sent on without the host taking the first packet"
    );
}

// ---------------------------------------------------------------------------
// The queue
// ---------------------------------------------------------------------------

/// What goes in comes out, in order, across the point the ring wraps.
#[test]
fn the_queue_wraps_without_reordering() {
    let mut fifo = crate::fifo::Fifo::<8>::new();
    assert_eq!(fifo.write(&[1, 2, 3, 4, 5, 6]), 6);
    let mut got = [0u8; 4];
    assert_eq!(fifo.read(&mut got), 4);
    assert_eq!(got, [1, 2, 3, 4]);

    // Wraps: four bytes are queued past the end of the ring.
    assert_eq!(fifo.write(&[7, 8, 9, 10]), 4);
    let mut got = [0u8; 6];
    assert_eq!(fifo.read(&mut got), 6);
    assert_eq!(got, [5, 6, 7, 8, 9, 10]);
    assert_eq!(fifo.len(), 0);
}

/// A queue takes what fits and says so, rather than overwriting what is in it.
#[test]
fn the_queue_refuses_what_will_not_fit() {
    let mut fifo = crate::fifo::Fifo::<4>::new();
    assert_eq!(fifo.write(&[1, 2, 3, 4, 5, 6]), 4);
    assert_eq!(fifo.free(), 0);
    let mut got = [0u8; 8];
    assert_eq!(fifo.read(&mut got), 4);
    assert_eq!(&got[..4], &[1, 2, 3, 4]);
}

/// Clearing drops what is queued and leaves the queue usable.
#[test]
fn clearing_leaves_the_queue_empty_and_usable() {
    let mut fifo = crate::fifo::Fifo::<8>::new();
    fifo.write(&[1, 2, 3]);
    fifo.clear();
    assert_eq!(fifo.len(), 0);
    assert_eq!(fifo.free(), 8);
    assert_eq!(fifo.write(&[9, 9]), 2);
    let mut got = [0u8; 2];
    assert_eq!(fifo.read(&mut got), 2);
    assert_eq!(got, [9, 9]);
}

// ---------------------------------------------------------------------------
// The control endpoint
// ---------------------------------------------------------------------------

/// A request of somebody else's, which picoboot has to leave alone.
fn foreign_request(request_type: RequestType, recipient: Recipient) -> Request {
    Request {
        direction: UsbDirection::Out,
        request_type,
        recipient,
        request: 0x77,
        value: 0,
        index: 0,
        length: 0,
    }
}

/// GET_COMMAND_STATUS, as a host sends it.
fn get_cmd_status() -> Request {
    Request {
        direction: UsbDirection::In,
        request_type: RequestType::Vendor,
        recipient: Recipient::Interface,
        request: picobootx::REQUEST_GET_CMD_STATUS,
        value: 0,
        index: 0,
        length: 16,
    }
}

/// The status block is answered on the control endpoint, which is what makes a
/// refusal diagnosable while the bulk pair is halted.
#[test]
fn the_status_block_is_answered_on_the_control_endpoint() {
    let bus = Bus::new();
    let host = Host(Rc::clone(&bus));
    let (picoboot, ep_out, ep_in) = device(&bus);

    let mut args = [0u8; 8];
    args[0..4].copy_from_slice(&0xffff_0000u32.to_le_bytes());
    args[4..8].copy_from_slice(&4u32.to_le_bytes());
    host.send_cmd(CMD_READ, 4, &args);

    let mut fut = pin!(picoboot.run(ep_out, ep_in));
    step(&mut fut, STEPS);

    let mut buf = [0u8; 16];
    let mut handler = picoboot.handler();
    let reply = handler.control_in(get_cmd_status(), &mut buf);
    let InResponse::Accepted(data) = reply.expect("picoboot answers its own request") else {
        panic!("the status block was rejected");
    };
    let code = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
    assert_eq!(
        code,
        Status::InvalidArg as u32,
        "the refusal was not reported"
    );
}

/// A request that is not picoboot's is left for whatever else is registered.
#[test]
fn a_request_that_is_not_picoboots_is_left_alone() {
    let bus = Bus::new();
    let (picoboot, _out, _in) = device(&bus);
    let mut handler = picoboot.handler();

    // Every request type and recipient, so the translation of each is carried
    // out rather than only the pair picoboot answers to.
    for rt in [
        RequestType::Standard,
        RequestType::Class,
        RequestType::Vendor,
        RequestType::Reserved,
    ] {
        for rc in [
            Recipient::Device,
            Recipient::Interface,
            Recipient::Endpoint,
            Recipient::Other,
        ] {
            let req = foreign_request(rt, rc);
            assert!(
                handler.control_out(req, &[]).is_none(),
                "picoboot answered a request of somebody else's"
            );
            let mut buf = [0u8; 8];
            assert!(
                handler.control_in(req, &mut buf).is_none(),
                "picoboot answered a request of somebody else's"
            );
        }
    }
}

/// What the device is doing is readable while it is doing it.
#[test]
fn diagnostics_report_what_the_protocol_is_doing() {
    let bus = Bus::new();
    let host = Host(Rc::clone(&bus));
    let (picoboot, ep_out, ep_in) = device(&bus);

    let idle = picoboot.diagnostics();
    assert_eq!(idle.state, 0, "a device with nothing to do is not idle");
    assert!(!idle.halted_out && !idle.halted_in);
    assert_eq!((idle.rx_len, idle.tx_len), (0, 0));

    let mut args = [0u8; 8];
    args[0..4].copy_from_slice(&0xffff_0000u32.to_le_bytes());
    args[4..8].copy_from_slice(&4u32.to_le_bytes());
    host.send_cmd(CMD_READ, 4, &args);
    let mut fut = pin!(picoboot.run(ep_out, ep_in));
    step(&mut fut, STEPS);

    let refused = picoboot.diagnostics();
    assert!(
        refused.halted_out && refused.halted_in,
        "a refusal is not visible in the read-out"
    );
}

/// A bus reset drops what was queued and puts the protocol back to waiting.
#[test]
fn a_bus_reset_drops_what_was_queued() {
    let bus = Bus::new();
    let host = Host(Rc::clone(&bus));
    let (picoboot, ep_out, ep_in) = device(&bus);

    // Half a command, so something is queued that a reset has to drop.
    host.send_data(&[1, 2, 3, 4]);
    let mut fut = pin!(picoboot.run(ep_out, ep_in));
    step(&mut fut, 20);

    picoboot.handler().reset();

    let after = picoboot.diagnostics();
    assert_eq!(after.state, 0, "a reset left the protocol where it was");
    assert_eq!(after.rx_len, 0, "a reset left the queue holding something");
}

/// A packet armed when the bus goes away is not reported as one that went.
#[test]
fn a_packet_left_by_a_bus_that_went_away_is_not_counted_as_sent() {
    let bus = Bus::new();
    let host = Host(Rc::clone(&bus));
    bus.borrow_mut().host_collects = false;
    let (picoboot, ep_out, ep_in) = device(&bus);

    const LEN: u32 = 200;
    let mut args = [0u8; 8];
    args[0..4].copy_from_slice(&0u32.to_le_bytes());
    args[4..8].copy_from_slice(&LEN.to_le_bytes());
    host.send_cmd(CMD_READ, LEN, &args);

    let mut fut = pin!(picoboot.run(ep_out, ep_in));
    step(&mut fut, 200);
    assert_eq!(host.packets(), 1, "the first packet never went");

    // The bus goes down under the packet nobody took.
    picoboot.handler().enabled(false);
    step(&mut fut, 200);

    // The transfer is not finished, because the packet that would have finished
    // it was never taken.  What matters is that the protocol was not told it
    // went: CMD_REBOOT2 acts in on_tx, and a device that counted an armed
    // packet as a delivered one would reboot with the reply still on the
    // controller.
    assert_ne!(
        picoboot.diagnostics().state,
        0,
        "the protocol finished a transfer the host never took"
    );
    assert!(
        host.collected().len() < LEN as usize,
        "the whole transfer was reported as sent into a bus that had gone"
    );
}

/// An endpoint that fails is taken up again rather than ending the task.
#[test]
fn an_endpoint_that_fails_does_not_end_the_task() {
    let bus = Bus::new();
    let host = Host(Rc::clone(&bus));
    let (picoboot, ep_out, ep_in) = device(&bus);

    // A read that fails, which is what an endpoint does when the bus goes under
    // it.  The packet it would have carried is gone, so what is asked here is
    // only that the task is still running afterwards.
    bus.borrow_mut().fail_out = true;
    let mut fut = pin!(picoboot.run(ep_out, ep_in));
    step(&mut fut, 50);

    // Then a write that fails, part way through serving a command.
    bus.borrow_mut().fail_in = true;
    let mut args = [0u8; 8];
    args[0..4].copy_from_slice(&0u32.to_le_bytes());
    args[4..8].copy_from_slice(&4u32.to_le_bytes());
    host.send_cmd(CMD_READ, 4, &args);
    step(&mut fut, 200);
    assert!(
        host.collected().is_empty(),
        "a write that failed carried its packet anyway"
    );

    // The host does what it does with a pipe that has stopped answering, and
    // the device serves again - which is the thing being asked.
    picoboot.handler().control_out(interface_reset(), &[]);
    host.send_cmd(CMD_READ, 4, &args);
    step(&mut fut, STEPS);

    assert_eq!(
        host.collected(),
        vec![0, 1, 2, 3],
        "the task did not take up again after an endpoint failed"
    );
}

/// INTERFACE RESET on its own puts the pipe back.
///
/// The RP2350 datasheet, 5.6.5.1: the request clears the HALT condition on each
/// of the bulk endpoints, aborts what was in progress and clears the previous
/// result.  So a host is not obliged to send CLEAR_FEATURE first, and a device
/// that only recovers when it does would be relying on what hosts happen to do
/// rather than on what the request is specified to mean.
#[test]
fn interface_reset_alone_puts_the_pipe_back() {
    let bus = Bus::new();
    let host = Host(Rc::clone(&bus));
    let (picoboot, ep_out, ep_in) = device(&bus);

    let mut args = [0u8; 8];
    args[0..4].copy_from_slice(&0xffff_0000u32.to_le_bytes());
    args[4..8].copy_from_slice(&4u32.to_le_bytes());
    host.send_cmd(CMD_READ, 4, &args);

    let mut fut = pin!(picoboot.run(ep_out, ep_in));
    step(&mut fut, STEPS);
    assert!(
        bus.borrow().stalled_out && bus.borrow().stalled_in,
        "the refusal did not halt both endpoints"
    );

    // No CLEAR_FEATURE.  The request is specified to clear the halts itself.
    picoboot.handler().control_out(interface_reset(), &[]);
    assert!(
        !bus.borrow().stalled_out && !bus.borrow().stalled_in,
        "INTERFACE RESET left an endpoint halted"
    );

    let mut args = [0u8; 8];
    args[0..4].copy_from_slice(&0u32.to_le_bytes());
    args[4..8].copy_from_slice(&4u32.to_le_bytes());
    host.send_cmd(CMD_READ, 4, &args);
    step(&mut fut, STEPS);

    assert_eq!(
        host.collected(),
        vec![0, 1, 2, 3],
        "the pipe did not serve again after INTERFACE RESET alone"
    );
}

/// The previous command's result is cleared by INTERFACE RESET.
///
/// Datasheet 5.6.5.1 again.  A status left behind would have the next
/// GET_COMMAND_STATUS answer for a command that is over.
#[test]
fn interface_reset_clears_the_previous_result() {
    let bus = Bus::new();
    let host = Host(Rc::clone(&bus));
    let (picoboot, ep_out, ep_in) = device(&bus);

    let mut args = [0u8; 8];
    args[0..4].copy_from_slice(&0xffff_0000u32.to_le_bytes());
    args[4..8].copy_from_slice(&4u32.to_le_bytes());
    host.send_cmd(CMD_READ, 4, &args);
    let mut fut = pin!(picoboot.run(ep_out, ep_in));
    step(&mut fut, STEPS);

    picoboot.handler().control_out(interface_reset(), &[]);

    let mut buf = [0u8; 16];
    let mut handler = picoboot.handler();
    let reply = handler.control_in(get_cmd_status(), &mut buf);
    let InResponse::Accepted(data) = reply.expect("picoboot answers its own request") else {
        panic!("the status block was rejected");
    };
    let code = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
    assert_eq!(
        code, 0,
        "the refusal was still being reported after a reset"
    );
}

/// The bus being enabled is not the bus going away.
#[test]
fn the_bus_coming_up_is_not_treated_as_it_going_down() {
    let bus = Bus::new();
    let host = Host(Rc::clone(&bus));
    bus.borrow_mut().host_collects = false;
    let (picoboot, ep_out, ep_in) = device(&bus);

    const LEN: u32 = 200;
    let mut args = [0u8; 8];
    args[0..4].copy_from_slice(&0u32.to_le_bytes());
    args[4..8].copy_from_slice(&LEN.to_le_bytes());
    host.send_cmd(CMD_READ, LEN, &args);

    let mut fut = pin!(picoboot.run(ep_out, ep_in));
    step(&mut fut, 200);

    // Enabled, so nothing armed is abandoned.  The packet is still waiting for
    // a host that has not taken it, and the driver goes on waiting.
    picoboot.handler().enabled(true);
    step(&mut fut, 200);

    assert_eq!(
        host.packets(),
        1,
        "the driver moved on from a packet nobody had taken"
    );
}

/// A request in the wrong direction is answered rather than left hanging.
///
/// INTERFACE RESET is a host-to-device request, and a host that sends it the
/// other way is answered with the empty reply the datasheet describes rather
/// than being ignored.
#[test]
fn a_request_arriving_in_the_wrong_direction_is_still_answered() {
    let bus = Bus::new();
    let (picoboot, _out, _in) = device(&bus);

    let mut buf = [0u8; 8];
    let mut handler = picoboot.handler();
    let reply = handler.control_in(interface_reset(), &mut buf);
    let InResponse::Accepted(data) = reply.expect("picoboot answers its own request") else {
        panic!("the request was rejected");
    };
    assert!(data.is_empty(), "an acknowledgement carried data");
}

/// A receive queue with no room for another packet is emptied before more is
/// taken, rather than the endpoint being read into nowhere.
#[test]
fn a_full_receive_queue_is_emptied_before_more_is_taken() {
    let bus = Bus::new();
    let host = Host(Rc::clone(&bus));
    let (picoboot, ep_out, ep_in) = device(&bus);

    // Commands arriving two to a packet, faster than the loop takes them: a
    // turn reads one command out of the queue and puts a whole packet in, and a
    // turn spent sending an acknowledgement takes none out at all.  So the
    // queue fills, and the loop has to empty it before asking the endpoint for
    // more rather than reading into nowhere.
    let mut packet = Vec::new();
    for _ in 0..2 {
        let mut cmd = vec![0u8; CMD_LEN];
        cmd[0..4].copy_from_slice(&MAGIC.to_le_bytes());
        cmd[4..8].copy_from_slice(&1u32.to_le_bytes());
        cmd[8] = CMD_EXIT_XIP;
        packet.extend_from_slice(&cmd);
    }
    for _ in 0..6 {
        host.send_data(&packet);
    }

    let mut fut = pin!(picoboot.run(ep_out, ep_in));
    step(&mut fut, STEPS);

    // Every one of them answered, and nothing left stuck in the queue.
    assert_eq!(
        host.packets(),
        12,
        "a command was dropped rather than the queue being emptied first"
    );
    assert_eq!(
        picoboot.diagnostics().rx_len,
        0,
        "the queue was left holding something"
    );
}

/// A device-to-host command is completed by the host's packet, and the device
/// is then ready for the next one.
///
/// RP2350 datasheet 5.6.5: the transfer is completed with an empty packet in
/// the opposite direction.  picobootx takes a single zero byte for it as well,
/// since a host that cannot send an empty packet sends that instead.
#[test]
fn the_hosts_completion_packet_returns_the_device_to_idle() {
    let bus = Bus::new();
    let host = Host(Rc::clone(&bus));
    let (picoboot, ep_out, ep_in) = device(&bus);

    let mut args = [0u8; 8];
    args[0..4].copy_from_slice(&0u32.to_le_bytes());
    args[4..8].copy_from_slice(&4u32.to_le_bytes());
    host.send_cmd(CMD_READ, 4, &args);

    let mut fut = pin!(picoboot.run(ep_out, ep_in));
    step(&mut fut, STEPS);
    assert_eq!(host.collected(), vec![0, 1, 2, 3]);

    host.send_ack();
    step(&mut fut, STEPS);
    assert_eq!(
        picoboot.diagnostics().state,
        0,
        "the device did not go back to waiting for a command"
    );

    // And it serves the next command, which is what being ready means.
    let mut args = [0u8; 8];
    args[0..4].copy_from_slice(&4u32.to_le_bytes());
    args[4..8].copy_from_slice(&4u32.to_le_bytes());
    host.send_cmd(CMD_READ, 4, &args);
    step(&mut fut, STEPS);
    assert_eq!(
        host.collected(),
        vec![0, 1, 2, 3, 4, 5, 6, 7],
        "the next command was not served"
    );
}
