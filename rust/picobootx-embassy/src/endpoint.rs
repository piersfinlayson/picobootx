// Copyright (C) 2026 Piers Finlayson <piers@piers.rocks>
//
// MIT License

//! The bulk endpoint controls embassy-usb does not hand out.

/// The controls picoboot's two bulk endpoints need and embassy-usb keeps.
///
/// picoboot reports a refusal by halting both of them and answering
/// `GET_COMMAND_STATUS` with the reason, and the host puts the pipe back with
/// `CLEAR_FEATURE(ENDPOINT_HALT)` followed by the vendor `INTERFACE RESET`.
/// So a device serving picoboot has to be able to halt an endpoint, ask
/// whether one is halted, and make one ready to carry data again.  It also has
/// to be able to tell an armed packet from a delivered one, which no endpoint
/// trait reports either.
///
/// embassy-usb keeps the halt control on `embassy_usb_driver::Bus`, which
/// `UsbDevice` owns and does not lend out, and
/// `embassy_usb_driver::Endpoint` offers only `info` and `wait_enabled`.  So
/// the implementation comes from below the driver, from whoever knows which
/// part is under it.  On an RP2350 that is `Rp2350EndpointControl`, behind
/// this crate's `rp2350` feature, and on another part it is the device's to
/// write.
pub trait EndpointControl {
    /// Whether the endpoint at this address is halted.
    fn is_stalled(&self, ep_addr: u8) -> bool;

    /// Halt or unhalt the endpoint at this address.
    fn set_stalled(&mut self, ep_addr: u8, stalled: bool);

    /// Make the endpoint at this address ready to carry data again.
    ///
    /// Called for both endpoints when the host sends `INTERFACE RESET`, which
    /// is what a host sends after clearing a halt.
    ///
    /// Two things have to be true afterwards, and a driver that leaves either
    /// undone loses the first transfer of every recovery.  The data toggle has
    /// to be back where a host that has just cleared the halt expects it, which
    /// USB 2.0 section 9.4.5 says is DATA0 in each direction.  And the
    /// host-to-device endpoint has to hold a buffer of `max_packet_size` that
    /// the controller may fill, since a halted endpoint holds none.
    fn resync(&mut self, ep_addr: u8, max_packet_size: u16);

    /// Take back a packet armed on the endpoint at this address, so the host
    /// does not receive it.
    ///
    /// Called for the device-to-host endpoint when the host sends `INTERFACE
    /// RESET`, which is a host asking for a clean start.  A packet armed for a
    /// host that stopped collecting is delivered to whoever reads next, one
    /// command behind, and that is what this prevents.
    ///
    /// What this undoes is the arming, which moved the data toggle as well as
    /// offering the buffer.  The host never saw the packet and is still waiting
    /// for its number, so the toggle goes back to what it was rather than
    /// forward to the next one or back to DATA0 — the latter is what a cleared
    /// halt calls for, and is [`EndpointControl::resync`]'s job.
    ///
    /// Doing nothing is the right answer where no packet is armed.
    fn retract(&mut self, ep_addr: u8);

    /// Whether the controller still holds the packet buffer of the endpoint at
    /// this address.
    ///
    /// Asked of the device-to-host endpoint, where it means a packet has been
    /// armed and the host has yet to take it.  `EndpointIn::write` returns once
    /// the packet is armed, and picoboot acts on a transmission the host has
    /// taken — `CMD_REBOOT2` reboots on it — so the wait between the two comes
    /// from here.
    fn in_flight(&self, ep_addr: u8) -> bool;
}

/// The RP2350's [`EndpointControl`], behind the `rp2350` feature.
///
/// Every embassy device on an RP2350 answers these the same way, by
/// reaching the USB controller's own endpoint buffer control words, so this is
/// that answer rather than each device restating it.  It forwards to
/// `picobootx_rp2350::usb`, and a device that wants the calls a piece at a time
/// can reach that module itself.
///
/// Compiled only for a build for the part.  The registers it reaches exist
/// nowhere else, so a host build with the feature on leaves the type absent
/// rather than half-working.
#[cfg(all(feature = "rp2350", target_os = "none"))]
#[derive(Clone, Copy, Debug, Default)]
pub struct Rp2350EndpointControl;

#[cfg(all(feature = "rp2350", target_os = "none"))]
impl EndpointControl for Rp2350EndpointControl {
    fn is_stalled(&self, ep_addr: u8) -> bool {
        picobootx_rp2350::usb::is_stalled(ep_addr)
    }

    fn set_stalled(&mut self, ep_addr: u8, stalled: bool) {
        picobootx_rp2350::usb::set_stalled(ep_addr, stalled);
    }

    fn resync(&mut self, ep_addr: u8, max_packet_size: u16) {
        picobootx_rp2350::usb::resync(ep_addr, max_packet_size);
    }

    fn retract(&mut self, ep_addr: u8) {
        picobootx_rp2350::usb::retract(ep_addr);
    }

    fn in_flight(&self, ep_addr: u8) -> bool {
        picobootx_rp2350::usb::in_flight(ep_addr)
    }
}
