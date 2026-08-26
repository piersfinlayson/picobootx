// Copyright (C) 2026 Piers Finlayson <piers@piers.rocks>
//
// MIT License

#![no_std]
#![doc = include_str!("../README.md")]

mod device;
mod endpoint;
mod fifo;
mod transport;

#[cfg(test)]
mod tests;

pub use device::{ControlHandler, Diagnostics, PACKET_LEN, PicobootClass};
pub use endpoint::EndpointControl;

#[cfg(all(feature = "rp2350", target_os = "none"))]
pub use endpoint::Rp2350EndpointControl;
