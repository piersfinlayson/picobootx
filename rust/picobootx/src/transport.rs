// Copyright (C) 2026 Piers Finlayson <piers@piers.rocks>
//
// MIT License

//! How the protocol reaches the wire.

/// Which of the two bulk endpoints.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Direction {
    /// Host to device.
    Out,
    /// Device to host.
    In,
}

/// The two bulk endpoints, and the halt state of each.
///
/// A FIFO in each direction rather than one packet at a time, because that is
/// what the protocol needs: a command arrives whole or not at all, a data phase
/// is written until the endpoint has no more room, and an acknowledgement has
/// to be queued behind whatever is already there.
pub trait Transport {
    /// How many bytes the receive FIFO is holding.
    fn rx_available(&self) -> u32;

    /// Take up to `buf.len()` bytes out of the receive FIFO, and say how many.
    fn rx_read(&mut self, buf: &mut [u8]) -> u32;

    /// Drop whatever the receive FIFO is holding and be ready for more.
    fn rx_clear(&mut self);

    /// How much room the transmit FIFO has.
    fn tx_available(&self) -> u32;

    /// Put bytes in the transmit FIFO, and say how many were taken.
    fn tx_write(&mut self, buf: &[u8]) -> u32;

    /// Send what the transmit FIFO is holding.
    fn tx_flush(&mut self);

    /// Drop whatever the transmit FIFO is holding.
    fn tx_clear(&mut self);

    /// Acknowledge a command with the short packet the protocol calls a
    /// zero-length packet.  False if it could not be queued.
    ///
    /// A packet of one zero byte does this job as well as a packet of no bytes,
    /// and some endpoint streams cannot produce the latter — a host's read ends
    /// on any packet shorter than the endpoint's, and one byte is shorter.
    fn send_ack(&mut self) -> bool;

    /// Whether this endpoint is halted.
    fn is_stalled(&self, dir: Direction) -> bool;

    /// Halt or unhalt this endpoint.
    fn set_stalled(&mut self, dir: Direction, stalled: bool);
}
