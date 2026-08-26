// Copyright (C) 2026 Piers Finlayson <piers@piers.rocks>
//
// MIT License

/// Why a command was refused, as the host reads it back with
/// `GET_COMMAND_STATUS`.
///
/// One byte on the wire.  The values are the protocol's and cannot be changed.
#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum Status {
    /// The command succeeded.
    Ok = 0,
    /// The command identifier is not one this device serves.
    UnknownCmd = 1,
    /// `bCmdSize` is not what this command carries.
    InvalidCmdLength = 2,
    /// `dTransferLength` does not agree with the command's arguments.
    InvalidTransferLen = 3,
    /// The address is outside anything this device will name.
    InvalidAddress = 4,
    /// The address or size is not on the boundary this command needs.
    BadAlignment = 5,
    /// Another write is already in progress.
    InterleavedWrite = 6,
    /// The device is rebooting and will not start anything else.
    Rebooting = 7,
    /// Something failed that has no more specific status.
    UnknownError = 8,
    /// The device is not in a state where this command means anything.
    InvalidState = 9,
    /// The device serves this command but will not do it here.
    NotPermitted = 10,
    /// An argument is out of range or not a value this command accepts.
    InvalidArg = 11,
    /// The buffer offered is smaller than the answer.
    BufferTooSmall = 12,
    /// A precondition the command relies on does not hold.
    PreconditionNotMet = 13,
    /// The data was modified and no longer matches what was expected.
    ModifiedData = 14,
    /// The data is not well formed.
    InvalidData = 15,
    /// What the command names does not exist.
    NotFound = 16,
    /// The modification asked for is not one that can be made.
    UnsupportedMod = 17,
}

impl core::fmt::Display for Status {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let s = match self {
            Self::Ok => "ok",
            Self::UnknownCmd => "unknown command",
            Self::InvalidCmdLength => "invalid command length",
            Self::InvalidTransferLen => "invalid transfer length",
            Self::InvalidAddress => "invalid address",
            Self::BadAlignment => "bad alignment",
            Self::InterleavedWrite => "interleaved write",
            Self::Rebooting => "rebooting",
            Self::UnknownError => "unknown error",
            Self::InvalidState => "invalid state",
            Self::NotPermitted => "not permitted",
            Self::InvalidArg => "invalid argument",
            Self::BufferTooSmall => "buffer too small",
            Self::PreconditionNotMet => "precondition not met",
            Self::ModifiedData => "modified data",
            Self::InvalidData => "invalid data",
            Self::NotFound => "not found",
            Self::UnsupportedMod => "unsupported modification",
        };
        f.write_str(s)
    }
}

impl core::error::Error for Status {}

/// What a callback returns: what the call produced, or the status the command
/// is refused with.
///
/// Most of them produce nothing, so `Result` on its own means `Result<()>`.
pub type Result<T = ()> = core::result::Result<T, Status>;
