// Copyright (C) 2026 Piers Finlayson <piers@piers.rocks>
//
// MIT License

//! The control endpoint, in terms of no particular USB stack.

/// What kind of request the host made.
///
/// `Other` carries the value the specification reserves, because a host can
/// send it and answering it as though it were a vendor request would be wrong.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RequestType {
    /// Defined by the USB specification.
    Standard,
    /// Defined by a device class.
    Class,
    /// Defined by the vendor.
    Vendor,
    /// Reserved by the specification.
    Other(u8),
}

/// What the host addressed the request to.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Recipient {
    /// The device.
    Device,
    /// An interface.
    Interface,
    /// An endpoint.
    Endpoint,
    /// Something else.
    Other,
}

/// Where a control transfer has got to.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Stage {
    /// The eight-byte request has arrived and nothing has been answered yet.
    Setup,
    /// The data stage.
    Data,
    /// The status stage.
    Ack,
}

/// A control request, in the terms every USB stack agrees on.
#[derive(Clone, Copy, Debug)]
pub struct Request {
    /// Standard, class or vendor.
    pub request_type: RequestType,
    /// Device, interface, endpoint or other.
    pub recipient: Recipient,
    /// True when the host is reading.
    pub dir_in: bool,
    /// `bRequest`.
    pub request: u8,
    /// `wValue`.
    pub value: u16,
    /// `wIndex`.
    pub index: u16,
    /// `wLength`.
    pub length: u16,
}

/// What the library did with a control request.
#[derive(Clone, Copy, Debug)]
pub enum Control<'a> {
    /// Not picoboot's request.  Whoever else wants it may have it.
    NotHandled,
    /// Handled, with no data.  Answer the status stage.
    Ack,
    /// Handled, with this data, which stays valid until the next call.
    Reply(&'a [u8]),
}

/// `bRequest` for INTERFACE RESET.
pub const REQUEST_INTERFACE_RESET: u8 = 0x41;

/// `bRequest` for GET COMMAND STATUS.
pub const REQUEST_GET_CMD_STATUS: u8 = 0x42;
