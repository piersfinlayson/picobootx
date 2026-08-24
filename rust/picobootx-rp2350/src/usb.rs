// Copyright (C) 2026 Piers Finlayson <piers@piers.rocks>
//
// MIT License

//! The endpoint buffer controls, for a USB stack that does not expose them.
//!
//! picoboot halts both of its bulk endpoints to report a refusal, and puts
//! them back when the host sends INTERFACE RESET.  A stack whose halt control
//! is owned by the task running the device leaves the code serving the
//! protocol with no way to reach it, and every stack decides for itself what
//! an unhalt leaves behind.  These reach the part's own registers, so the
//! protocol can be served whatever the stack above offers.
//!
//! What they touch is the buffer control word of one endpoint, in the USB
//! controller's dual-port RAM.  Nothing here allocates an endpoint, enables
//! one, or moves data — the stack still owns all of that.
//!
//! Compiled only for a build for the part, since there is no register map
//! under anything else.

/// Where the USB controller's dual-port RAM answers from.
const USB_DPRAM: usize = 0x5010_0000;

/// The device-to-host buffer control words start here, one per endpoint.
const EP_IN_BUFFER_CONTROL: usize = USB_DPRAM + 0x80;

/// The host-to-device ones sit four bytes above each of those.
const EP_OUT_BUFFER_CONTROL: usize = EP_IN_BUFFER_CONTROL + 4;

/// One endpoint's pair of words is this far from the next.
const EP_BUFFER_CONTROL_STRIDE: usize = 8;

/// The part carries this many endpoints in each direction.
const EP_COUNT: usize = 16;

/// How long buffer 0 is, in bytes.
const LENGTH_0: u32 = 0x03ff;

/// Buffer 0 is the controller's to use.
const AVAILABLE_0: u32 = 1 << 10;

/// Reply to this endpoint with a halt.
const STALL: u32 = 1 << 11;

/// The data PID of buffer 0.
const PID_0: u32 = 1 << 13;

/// The buffer control word of the endpoint at this address.
///
/// The address is the one the descriptor gives, so bit 7 chooses the
/// direction and the low four bits the endpoint.
fn buffer_control(ep_addr: u8) -> *mut u32 {
    let n = usize::from(ep_addr) & (EP_COUNT - 1);
    let base = if ep_addr & 0x80 == 0 {
        EP_OUT_BUFFER_CONTROL
    } else {
        EP_IN_BUFFER_CONTROL
    };
    (base + n * EP_BUFFER_CONTROL_STRIDE) as *mut u32
}

/// Wait for the controller to see one write before making the next.
///
/// The controller is clocked at 48MHz and the core is not, so a buffer handed
/// over in the same write that set it up can be taken before the rest of the
/// word has landed.  The part's documentation asks for a gap of a few of the
/// controller's cycles, and this is that gap.
fn settle() {
    for _ in 0..12 {
        // SAFETY: an instruction that does nothing, touches no memory and
        // leaves the flags alone, which is what the options say.
        unsafe { core::arch::asm!("nop", options(nomem, nostack, preserves_flags)) };
    }
}

/// Whether the endpoint at this address is halted.
#[must_use]
pub fn is_stalled(ep_addr: u8) -> bool {
    // SAFETY: the address is one of the controller's own buffer control words,
    // and the index is masked to the endpoints the part carries.  Volatile
    // because the controller writes this word as well.
    let ctrl = unsafe { buffer_control(ep_addr).read_volatile() };
    ctrl & STALL != 0
}

/// Whether the controller still holds the endpoint's buffer.
///
/// A device-to-host buffer is the controller's from the moment it is armed
/// until the host has taken it, so this is how a caller tells a packet that
/// was delivered from one that was merely queued.
#[must_use]
pub fn in_flight(ep_addr: u8) -> bool {
    // SAFETY: as is_stalled.
    let ctrl = unsafe { buffer_control(ep_addr).read_volatile() };
    ctrl & AVAILABLE_0 != 0
}

/// Halt or unhalt the endpoint at this address.
///
/// Unhalting clears the halt and nothing else.  What the endpoint holds
/// afterwards is whatever the halt left there, which is what [`resync`] is
/// for.
pub fn set_stalled(ep_addr: u8, stalled: bool) {
    let ctrl = buffer_control(ep_addr);
    // SAFETY: as is_stalled, and the write puts back every bit it read.
    unsafe {
        let mut value = ctrl.read_volatile();
        if stalled {
            value |= STALL;
        } else {
            value &= !STALL;
        }
        ctrl.write_volatile(value);
    }
}

/// Take back a packet armed on this endpoint that the host has not taken.
///
/// This undoes the arming, which is two bits and not one.  The buffer stops
/// being offered, and the recorded PID goes back to the one before it — arming
/// a packet advances that PID, and the next packet written advances it again
/// from wherever it stands.  A host that never saw the retracted packet is
/// still waiting for its number, so leaving the advance in place would send
/// the one after it and the host would drop it.
///
/// The toggle is put back, not reset.  DATA0 is what a cleared halt calls for
/// and is [`resync`]'s job, and a host that has cleared no halt has moved
/// nothing for a reset to match.
///
/// Does nothing where no packet is armed, since there is then no arming to
/// undo and moving the PID would desynchronise a healthy endpoint.
pub fn retract(ep_addr: u8) {
    let ctrl = buffer_control(ep_addr);
    // SAFETY: as is_stalled, and the write puts back every bit it read but the
    // two the arming set.
    unsafe {
        let value = ctrl.read_volatile();
        if value & AVAILABLE_0 == 0 {
            return;
        }
        ctrl.write_volatile((value & !AVAILABLE_0) ^ PID_0);
    }
}

/// Put the endpoint back to what enabling it leaves behind.
///
/// A host that clears a halt has reset its own data toggle for that endpoint
/// to DATA0, so the device has to do the same or every packet after it is
/// answered with the wrong PID and dropped.  A host-to-device endpoint also
/// has to be handed back to the controller with a buffer to fill, since a
/// halted one has none.
///
/// The two directions take different values.  Host to device is set to expect
/// DATA0 and given a buffer of `max_packet_size`.  Device to host records the
/// PID of the packet last sent, and the controller flips it before sending the
/// next, so DATA0 next means DATA1 here.
pub fn resync(ep_addr: u8, max_packet_size: u16) {
    let ctrl = buffer_control(ep_addr);

    if ep_addr & 0x80 == 0 {
        let value = u32::from(max_packet_size) & LENGTH_0;
        // SAFETY: as is_stalled.  The buffer is offered in a second write, so
        // the controller cannot take it before its length has landed.
        unsafe { ctrl.write_volatile(value) };
        settle();
        // SAFETY: as above.
        unsafe { ctrl.write_volatile(value | AVAILABLE_0) };
    } else {
        // SAFETY: as is_stalled.
        unsafe { ctrl.write_volatile(PID_0) };
    }
}
