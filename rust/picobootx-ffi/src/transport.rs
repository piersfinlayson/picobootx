// Copyright (C) 2026 Piers Finlayson <piers@piers.rocks>
//
// MIT License

//! `Transport` over the `picoboot_vendor_*` API.
//!
//! Stateless: the C side owns the FIFOs and the endpoints, so this carries only
//! the two addresses, which is what its stall calls take.

use core::ffi::c_void;

use picobootx::{Direction, Transport};

use crate::cabi::{
    picoboot_vendor_available, picoboot_vendor_is_endpoint_stalled, picoboot_vendor_read,
    picoboot_vendor_read_clear, picoboot_vendor_send_zlp, picoboot_vendor_stall_endpoint,
    picoboot_vendor_unstall_endpoint, picoboot_vendor_write, picoboot_vendor_write_available,
    picoboot_vendor_write_clear, picoboot_vendor_write_flush,
};

pub struct VendorTransport {
    ep_out: u8,
    ep_in: u8,
}

impl VendorTransport {
    pub fn new(ep_out: u8, ep_in: u8) -> Self {
        Self { ep_out, ep_in }
    }

    fn addr(&self, dir: Direction) -> u8 {
        match dir {
            Direction::Out => self.ep_out,
            Direction::In => self.ep_in,
        }
    }
}

impl Transport for VendorTransport {
    fn rx_available(&self) -> u32 {
        unsafe { picoboot_vendor_available() }
    }

    fn rx_read(&mut self, buf: &mut [u8]) -> u32 {
        unsafe { picoboot_vendor_read(buf.as_mut_ptr().cast::<c_void>(), buf.len() as u32) }
    }

    fn rx_clear(&mut self) {
        unsafe { picoboot_vendor_read_clear() };
    }

    fn tx_available(&self) -> u32 {
        unsafe { picoboot_vendor_write_available() }
    }

    fn tx_write(&mut self, buf: &[u8]) -> u32 {
        unsafe { picoboot_vendor_write(buf.as_ptr().cast::<c_void>(), buf.len() as u32) }
    }

    fn tx_flush(&mut self) -> u32 {
        unsafe { picoboot_vendor_write_flush() }
    }

    fn tx_clear(&mut self) {
        unsafe { picoboot_vendor_write_clear() };
    }

    fn send_ack(&mut self) -> bool {
        unsafe { picoboot_vendor_send_zlp() }
    }

    fn is_stalled(&self, dir: Direction) -> bool {
        unsafe { picoboot_vendor_is_endpoint_stalled(self.addr(dir)) }
    }

    fn set_stalled(&mut self, dir: Direction, stalled: bool) {
        let ep = self.addr(dir);
        if stalled {
            unsafe { picoboot_vendor_stall_endpoint(ep) };
        } else {
            unsafe { picoboot_vendor_unstall_endpoint(ep) };
        }
    }
}
