// Copyright (C) 2026 Piers Finlayson <piers@piers.rocks>
//
// MIT License

//! picobootx as an embassy-usb device: one task, and one control handler.

use core::cell::RefCell;
use core::future::poll_fn;
use core::task::{Poll, Waker};

use embassy_usb::Handler;
use embassy_usb::control::{InResponse, OutResponse, Request as UsbRequest};
use embassy_usb::control::{Recipient as UsbRecipient, RequestType as UsbRequestType};
use embassy_usb_driver::{Direction as UsbDirection, EndpointIn, EndpointOut};

use picobootx::wire::FLASH_PAGE_SIZE;
use picobootx::{Control, Custom, Endpoints, Ops, REQUEST_INTERFACE_RESET};
use picobootx::{Recipient, Request, RequestType, Stage};

use crate::halt::Halt;
use crate::transport::Xport;

/// picobootx, and everything it needs to be driven from two embassy tasks.
///
/// The control endpoint and the bulk endpoints are answered from different
/// places under embassy-usb.  `embassy_usb::UsbDevice::run` owns the control
/// endpoint and calls a [`Handler`] for a request it does not answer itself,
/// and the bulk endpoints are whatever task holds them.  Both need the
/// protocol and both need the queues, so this owns the pair and lends them to
/// each in turn.
///
/// [`handler`](Self::handler) is the control side and [`run`](Self::run) the
/// bulk side, and a device serving picoboot runs both.
pub struct Picoboot<'a, O: Ops, C: Custom, H: Halt> {
    inner: RefCell<Inner<'a, O, C, H>>,
}

struct Inner<'a, O: Ops, C: Custom, H: Halt> {
    core: picobootx::Picoboot<'a, O, C>,
    xport: Xport<H>,
    // Registered by run while both endpoints are halted, and woken when the
    // host puts them back.  Nothing else moves the protocol along in that
    // state, so without it the task would sleep through the recovery.
    waker: Option<Waker>,
    // Bumped whenever the bus goes away under a packet that was armed.  A
    // packet waiting to be taken is waiting on the host, and this is the only
    // report that the host has stopped answering.
    epoch: u32,
}

/// The largest packet a bulk endpoint on a full-speed device carries, and so
/// the largest `max_packet_size` either endpoint may be allocated with.
pub const PACKET_LEN: usize = 64;

/// What the protocol and its queues are doing at one moment.
///
/// For a device that wants to report its own state - over a control request,
/// a log, or a light.  Nothing here changes what the protocol does.
#[derive(Clone, Copy, Debug, Default)]
pub struct Diagnostics {
    /// `picobootx::State`, as its discriminant.
    pub state: u8,
    /// Bytes queued from the host and not yet taken by the protocol.
    pub rx_len: u16,
    /// Bytes the protocol has queued for the host and not yet sent.
    pub tx_len: u16,
    /// Whether the host-to-device endpoint is halted.
    pub halted_out: bool,
    /// Whether the device-to-host endpoint is halted.
    pub halted_in: bool,
    /// Whether a packet is armed on the device-to-host endpoint and not yet
    /// taken by the host.
    pub in_flight: bool,
}

// Whether the protocol is waiting on the host rather than owing it something.
//
// Only then is there a packet to wait for.  In the states left out the device
// is the one with something to send, and polling is what produces it.
fn waits_on_host(state: picobootx::State) -> bool {
    use picobootx::State::{AwaitAck, DataOut, Idle};
    matches!(state, Idle | DataOut | AwaitAck)
}

// What one turn of the driver task's loop found to do.  Read under the borrow
// and acted on after it, since every one of them awaits.
enum Action {
    Halted,
    Send(usize),
    Receive,
    Again,
}

impl<'a, O: Ops, C: Custom, H: Halt> Picoboot<'a, O, C, H> {
    /// Start, with what this device does and where its bulk endpoints are.
    ///
    /// `ops` and `custom` are the protocol's, and mean what
    /// `picobootx::Picoboot::new` says they mean — `flash_page` included.
    ///
    /// `endpoints` are the two bulk addresses as the descriptor gives them,
    /// `max_packet_size` is what both were allocated with — at most
    /// [`PACKET_LEN`], which is all a full-speed bulk endpoint may carry — and
    /// `halt` is how this device halts one of them.  A smaller endpoint is
    /// served in packets of its own size rather than being handed one it would
    /// refuse.
    pub fn new(
        ops: O,
        custom: C,
        flash_page: Option<&'a mut [u8; FLASH_PAGE_SIZE]>,
        endpoints: Endpoints,
        max_packet_size: u16,
        halt: H,
    ) -> Self {
        let (out, r#in) = (endpoints.out, endpoints.r#in);
        Self {
            inner: RefCell::new(Inner {
                core: picobootx::Picoboot::new(ops, custom, flash_page, endpoints),
                xport: Xport::new(halt, out, r#in, max_packet_size),
                waker: None,
                epoch: 0,
            }),
        }
    }

    /// The control endpoint's side, to be given to `embassy_usb::Builder`.
    ///
    /// picoboot's `INTERFACE RESET` and `GET_COMMAND_STATUS` arrive here, and
    /// a request that is neither is left for whoever else wants it.
    pub fn handler(&self) -> ControlHandler<'_, 'a, O, C, H> {
        ControlHandler { dev: self }
    }

    /// The bulk endpoints' side.  Run this alongside `UsbDevice::run`.
    ///
    /// Never returns.  A halted pipe waits for the host to put it back rather
    /// than reading an endpoint that is not answering, and everything else is
    /// one packet in or one packet out.
    pub async fn run<EO, EI>(&self, mut ep_out: EO, mut ep_in: EI) -> !
    where
        EO: EndpointOut,
        EI: EndpointIn,
    {
        let mut packet = [0u8; PACKET_LEN];
        loop {
            let action = self.lock(|i| {
                i.core.poll(&mut i.xport);
                if i.xport.halted() {
                    return Action::Halted;
                }
                let n = i.xport.take_tx(&mut packet);
                if n > 0 {
                    return Action::Send(n);
                }
                // Reading the host-to-device endpoint waits for a packet, so
                // it may only be done when the host is the one owing something.
                // Where the device owes the data - a device-to-host phase, or
                // the acknowledgement of one - poll is what produces it, and
                // one poll produces one step: the poll that took the command
                // moved to the sending state, and the poll after it is what
                // queues the first packet.  Waiting on the endpoint in between
                // parks the task against a host that is itself waiting for that
                // packet, and neither side moves until the host gives up.
                if !waits_on_host(i.core.state()) {
                    return Action::Again;
                }
                // Only ever ask the endpoint for a packet there is somewhere
                // to put.  The poll above takes a command, a packet's worth of
                // a host-to-device phase, or a partial command it drops, so a
                // queue too full to take another packet is one the next turn
                // of this loop empties further.
                if i.xport.rx.free() >= i.xport.max_packet_size() {
                    Action::Receive
                } else {
                    // Unreachable: a poll runs before every decision, and one
                    // that takes a command leaves the device either owing the
                    // host a packet or no longer reading.  So the queue is
                    // never filled twice without being drained between.
                    // LCOV_UNREACHABLE_START
                    Action::Again
                    // LCOV_UNREACHABLE_STOP
                }
            });

            // Every read and every write waits for its endpoint first.  A
            // driver is free to answer either straight away on an endpoint the
            // host has not configured, and answering a read that way returns a
            // length from before the endpoint was enabled — so a device that
            // reached for the endpoint regardless would spin from reset until
            // enumeration and again after every bus reset.  Waiting costs one
            // poll on an endpoint that is already enabled.
            //
            // Every arm awaits, the ones with nothing to wait on included.  A
            // turn that gets back here without ever having returned Pending
            // starves whatever this loop is joined with — the USB device's own
            // task among it — and the device goes dark rather than busy.
            match action {
                Action::Halted => self.unhalted().await,
                Action::Send(n) => {
                    ep_in.wait_enabled().await;
                    match ep_in.write(&packet[..n]).await {
                        // write returns once the packet is armed, and the
                        // protocol acts on a transmission the host has taken —
                        // CMD_REBOOT2 reboots in on_tx.  So the delivery is
                        // waited for, and a packet the bus never carried is not
                        // reported as one that went.
                        Ok(()) => {
                            if self.delivered().await {
                                self.lock(|i| i.core.on_tx(n as u32));
                            }
                        }
                        Err(_) => yield_now().await,
                    }
                }
                Action::Receive => {
                    ep_out.wait_enabled().await;
                    match ep_out.read(&mut packet).await {
                        Ok(n) => self.lock(|i| {
                            i.xport.rx.write(&packet[..n]);
                            let available = i.xport.rx.len() as u32;
                            i.core.on_rx(&mut i.xport, available);
                        }),
                        Err(_) => yield_now().await,
                    }
                }
                Action::Again => yield_now().await,
            }
        }
    }

    /// What the protocol and its queues are doing, for a device that wants to
    /// report it.
    ///
    /// Every field is read under the same borrow, so the picture is of one
    /// moment rather than assembled from several.
    pub fn diagnostics(&self) -> Diagnostics {
        self.lock(|i| {
            let (rx_len, tx_len) = i.xport.queued();
            Diagnostics {
                state: i.core.state() as u8,
                rx_len: rx_len as u16,
                tx_len: tx_len as u16,
                halted_out: i.xport.halted_dir(picobootx::Direction::Out),
                halted_in: i.xport.halted_dir(picobootx::Direction::In),
                in_flight: i.xport.in_flight(),
            }
        })
    }

    fn lock<R>(&self, f: impl FnOnce(&mut Inner<'a, O, C, H>) -> R) -> R {
        f(&mut self.inner.borrow_mut())
    }

    async fn unhalted(&self) {
        poll_fn(|cx| {
            self.lock(|i| {
                if i.xport.halted() {
                    i.waker = Some(cx.waker().clone());
                    Poll::Pending
                } else {
                    Poll::Ready(())
                }
            })
        })
        .await;
    }

    // Wait for the host to take the packet that was just armed, and say
    // whether it took it.  False means the bus went away underneath it.
    //
    // Nothing wakes on a packet being taken — the driver keeps that waker to
    // itself — so this hands the executor a turn between looks.  It runs once
    // per packet sent, and the wait is however long the host takes to issue
    // its IN token.
    async fn delivered(&self) -> bool {
        let epoch = self.lock(|i| i.epoch);
        loop {
            let (in_flight, gone) = self.lock(|i| (i.xport.in_flight(), i.epoch != epoch));
            if !in_flight {
                return true;
            }
            if gone {
                return false;
            }
            yield_now().await;
        }
    }
}

/// The control endpoint's half of a [`Picoboot`].
///
/// Hand it to `embassy_usb::Builder::handler`.  It holds no state of its own —
/// everything it touches belongs to the `Picoboot` it came from.
pub struct ControlHandler<'p, 'a, O: Ops, C: Custom, H: Halt> {
    dev: &'p Picoboot<'a, O, C, H>,
}

impl<O: Ops, C: Custom, H: Halt> Handler for ControlHandler<'_, '_, O, C, H> {
    fn control_out(&mut self, req: UsbRequest, data: &[u8]) -> Option<OutResponse> {
        let _ = data;
        let req = translate(req);
        self.dev.lock(|i| {
            let handled = !matches!(
                i.core.on_control(&mut i.xport, &req, Stage::Setup),
                Control::NotHandled
            );
            if !handled {
                return None;
            }

            // INTERFACE RESET is where the endpoints are put back, and this is
            // the only place a device serving picoboot under embassy-usb hears
            // that a halt has been cleared.  embassy-usb answers
            // CLEAR_FEATURE(ENDPOINT_HALT) itself and tells no handler about
            // it, so the resync a cleared halt calls for goes here, where the
            // request that always follows it arrives.  A host also sends
            // INTERFACE RESET to begin a session, with nothing halted, which is
            // why resync puts back only what picoboot halted.
            if is_interface_reset(&req) {
                i.xport.resync();
                // A packet armed for a host that stopped collecting it is
                // delivered to whoever reads next, one command behind, and a
                // reset is a host asking not to be in that position.  The
                // queues are emptied by the unhalt above, which reaches only
                // what the protocol holds - this is the one the controller
                // holds.  The epoch goes with it, since the task waiting for
                // that packet must hear that it will not be taken rather than
                // read it going away as the host having taken it.
                i.xport.retract_in();
                i.epoch = i.epoch.wrapping_add(1);
                wake(&mut i.waker);
            }
            Some(OutResponse::Accepted)
        })
    }

    fn control_in<'r>(&'r mut self, req: UsbRequest, buf: &'r mut [u8]) -> Option<InResponse<'r>> {
        let req = translate(req);
        // The reply borrows the protocol's own storage, which is lent out only
        // for as long as this call holds it, so it is copied into the buffer
        // embassy-usb offers rather than handed back by reference.
        let len = self.dev.lock(
            |i| match i.core.on_control(&mut i.xport, &req, Stage::Setup) {
                Control::NotHandled => None,
                Control::Ack => Some(0),
                Control::Reply(reply) => {
                    let n = reply.len().min(buf.len());
                    buf[..n].copy_from_slice(&reply[..n]);
                    Some(n)
                }
            },
        )?;
        Some(InResponse::Accepted(&buf[..len]))
    }

    // A bus reset re-enumerates the device, so whatever command was in flight
    // is not one any host is waiting for.  The queues are dropped and the
    // protocol is put back to waiting for a command, which is what INTERFACE
    // RESET means and is how it is asked for.  The endpoints are not resynced
    // here: the stack enables them again when the host configures the device,
    // and enabling is what leaves them ready.
    fn reset(&mut self) {
        self.dev.lock(|i| {
            i.xport.clear();
            i.core
                .on_control(&mut i.xport, &INTERFACE_RESET, Stage::Setup);
            i.epoch = i.epoch.wrapping_add(1);
            wake(&mut i.waker);
        });
    }

    // Power off the bus, which is the other way a packet already armed stops
    // being one any host will take.  The protocol is left where it was: the
    // reset that follows the bus coming back is what puts it to Idle.
    fn enabled(&mut self, enabled: bool) {
        if !enabled {
            self.dev.lock(|i| i.epoch = i.epoch.wrapping_add(1));
        }
    }
}

// Hand the executor a turn.  Woken before it returns Pending, so the task is
// polled again after everything else that is ready rather than after nothing.
async fn yield_now() {
    let mut yielded = false;
    poll_fn(|cx| {
        if yielded {
            return Poll::Ready(());
        }
        yielded = true;
        cx.waker().wake_by_ref();
        Poll::Pending
    })
    .await;
}

fn wake(waker: &mut Option<Waker>) {
    if let Some(waker) = waker.take() {
        waker.wake();
    }
}

// picoboot's INTERFACE RESET, as the host sends it.
const INTERFACE_RESET: Request = Request {
    request_type: RequestType::Vendor,
    recipient: Recipient::Interface,
    dir_in: false,
    request: REQUEST_INTERFACE_RESET,
    value: 0,
    index: 0,
    length: 0,
};

fn is_interface_reset(req: &Request) -> bool {
    req.request == REQUEST_INTERFACE_RESET
        && req.recipient == Recipient::Interface
        && matches!(req.request_type, RequestType::Vendor | RequestType::Class)
}

// embassy-usb's request, in the terms picobootx states its own in.
//
// Only the setup stage exists here.  embassy-usb calls a handler once per
// request with the data stage already moved, and answers the status stage
// itself, so neither of the other two stages picobootx knows about is
// something this crate is in a position to report.
fn translate(req: UsbRequest) -> Request {
    Request {
        request_type: match req.request_type {
            UsbRequestType::Standard => RequestType::Standard,
            UsbRequestType::Class => RequestType::Class,
            UsbRequestType::Vendor => RequestType::Vendor,
            UsbRequestType::Reserved => RequestType::Other(UsbRequestType::Reserved as u8),
        },
        recipient: match req.recipient {
            UsbRecipient::Device => Recipient::Device,
            UsbRecipient::Interface => Recipient::Interface,
            UsbRecipient::Endpoint => Recipient::Endpoint,
            UsbRecipient::Other | UsbRecipient::Reserved => Recipient::Other,
        },
        dir_in: req.direction == UsbDirection::In,
        request: req.request,
        value: req.value,
        index: req.index,
        length: req.length,
    }
}
