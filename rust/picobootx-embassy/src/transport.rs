// Copyright (C) 2026 Piers Finlayson <piers@piers.rocks>
//
// MIT License

//! `picobootx::Transport` over two byte queues and the consumer's halt
//! control.
//!
//! Every method of the trait is synchronous, and every endpoint operation
//! embassy-usb offers is asynchronous, so nothing here touches an endpoint.
//! The driver task moves packets between the queues and the endpoints, and
//! this is the view the protocol takes of the same queues.

use picobootx::{Direction, Transport};

use crate::fifo::Fifo;
use crate::halt::Halt;

/// How many bytes the receive queue holds.
///
/// Two packets, so there is always room to take one more from the endpoint
/// while the protocol has yet to look at what arrived before it.
const RX_LEN: usize = 128;

/// How many the transmit queue holds.
///
/// One packet, which is what the C library gives it.  The protocol fills the
/// queue and flushes, and a flush is one packet, so the size is what decides
/// where a device-to-host transfer is split.
const TX_LEN: usize = 64;

pub(crate) struct Xport<H: Halt> {
    pub(crate) rx: Fifo<RX_LEN>,
    tx: Fifo<TX_LEN>,
    halt: H,
    ep_out: u8,
    ep_in: u8,
    max_packet_size: u16,
    // Which endpoint picoboot halted and has yet to put back.  The stall bit
    // is not this: embassy-usb answers CLEAR_FEATURE(ENDPOINT_HALT) itself and
    // reports it to no handler, so by the INTERFACE RESET that follows there is
    // nothing left in the hardware to read.  A bus reset drops both, since the
    // stack arms the endpoints itself when the host configures the device.
    owed_out: bool,
    owed_in: bool,
}

impl<H: Halt> Xport<H> {
    pub(crate) const fn new(halt: H, ep_out: u8, ep_in: u8, max_packet_size: u16) -> Self {
        Self {
            rx: Fifo::new(),
            tx: Fifo::new(),
            halt,
            ep_out,
            ep_in,
            max_packet_size,
            owed_out: false,
            owed_in: false,
        }
    }

    fn addr(&self, dir: Direction) -> u8 {
        match dir {
            Direction::Out => self.ep_out,
            Direction::In => self.ep_in,
        }
    }

    /// The largest packet either endpoint carries.
    pub(crate) fn max_packet_size(&self) -> usize {
        usize::from(self.max_packet_size)
    }

    /// What the two queues are holding, for a diagnostic read-out.
    pub(crate) fn queued(&self) -> (usize, usize) {
        (self.rx.len(), self.tx.len())
    }

    /// Whether one named endpoint is halted, rather than either of them.
    pub(crate) fn halted_dir(&self, dir: Direction) -> bool {
        self.halt.is_stalled(self.addr(dir))
    }

    /// Whether either endpoint is halted, which is when nothing moves.
    pub(crate) fn halted(&self) -> bool {
        self.halt.is_stalled(self.ep_out) || self.halt.is_stalled(self.ep_in)
    }

    /// Whether a packet armed on the device-to-host endpoint has yet to be
    /// taken by the host.
    pub(crate) fn in_flight(&self) -> bool {
        self.halt.in_flight(self.ep_in)
    }

    /// Take one packet of what the protocol has queued for the host.
    ///
    /// At most `max_packet_size`, since that is all an endpoint carries in one
    /// packet and a longer write is refused rather than split by the driver.  A
    /// short packet ends the host's read, which is what a transfer that has run
    /// out is meant to do.
    pub(crate) fn take_tx(&mut self, buf: &mut [u8]) -> usize {
        let n = buf.len().min(self.max_packet_size());
        self.tx.read(&mut buf[..n])
    }

    /// Put back the endpoints picoboot halted, and only those.
    ///
    /// Resyncing writes the whole buffer control word, so an endpoint that was
    /// not halted would have whatever it was carrying taken back off the
    /// controller.
    pub(crate) fn resync(&mut self) {
        let mps = self.max_packet_size;
        if core::mem::take(&mut self.owed_out) {
            self.halt.resync(self.ep_out, mps);
        }
        if core::mem::take(&mut self.owed_in) {
            self.halt.resync(self.ep_in, mps);
        }
    }

    /// Drop whatever both queues are holding, and whatever either endpoint is
    /// owed.
    pub(crate) fn clear(&mut self) {
        self.rx.clear();
        self.tx.clear();
        self.owed_out = false;
        self.owed_in = false;
    }
}

impl<H: Halt> Transport for Xport<H> {
    fn rx_available(&self) -> u32 {
        self.rx.len() as u32
    }

    fn rx_read(&mut self, buf: &mut [u8]) -> u32 {
        self.rx.read(buf) as u32
    }

    fn rx_clear(&mut self) {
        self.rx.clear();
    }

    fn tx_available(&self) -> u32 {
        self.tx.free() as u32
    }

    fn tx_write(&mut self, buf: &[u8]) -> u32 {
        self.tx.write(buf) as u32
    }

    // Sending is the driver task's, and it takes whatever the queue holds as
    // soon as it next runs, which is after the call that queued it returns.
    // So there is nothing for a flush to start, and what it reports is what is
    // waiting to go.
    fn tx_flush(&mut self) -> u32 {
        self.tx.len() as u32
    }

    fn tx_clear(&mut self) {
        self.tx.clear();
    }

    fn send_ack(&mut self) -> bool {
        self.tx.write(&[0]) == 1
    }

    fn is_stalled(&self, dir: Direction) -> bool {
        self.halt.is_stalled(self.addr(dir))
    }

    // Unhalting drops what the endpoint's queue is holding as well, so a
    // command refused part way through leaves nothing behind for the next one
    // to be read out of.  Halting leaves both queues alone, since the reason
    // for the refusal is answered over the control endpoint and the queues are
    // not read again until the host puts the pipe back.
    fn set_stalled(&mut self, dir: Direction, stalled: bool) {
        self.halt.set_stalled(self.addr(dir), stalled);
        if stalled {
            // Halting is what leaves an endpoint owing a resync.  Clearing the
            // halt does not settle it — the toggle and the receive buffer are
            // still where the halt left them — so the record survives until
            // resync puts the endpoint back.
            match dir {
                Direction::Out => self.owed_out = true,
                Direction::In => self.owed_in = true,
            }
        } else {
            match dir {
                Direction::Out => self.rx.clear(),
                Direction::In => self.tx.clear(),
            }
        }
    }
}
