// Copyright (C) 2026 Piers Finlayson <piers@piers.rocks>
//
// MIT License

#![no_std]
#![doc = include_str!("../README.md")]

mod device;
mod fifo;
mod halt;
mod transport;

pub use device::{ControlHandler, PACKET_LEN, Picoboot};
pub use halt::Halt;

#[cfg(all(feature = "rp2350", target_os = "none"))]
pub use halt::Rp2350Halt;
