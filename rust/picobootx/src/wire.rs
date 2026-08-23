// Copyright (C) 2026 Piers Finlayson <piers@piers.rocks>
//
// MIT License

//! The bytes the protocol puts on the wire.

/// The magic every standard PICOBOOT command carries.
pub const MAGIC: u32 = 0x431f_d10b;

/// A command packet is this many bytes, always.
pub const CMD_LEN: usize = 32;

/// The status packet `GET_COMMAND_STATUS` answers with is this many bytes.
pub const STATUS_LEN: usize = 16;

/// Set in `cmd_id` when the host is reading rather than writing.
pub const DIR_IN: u8 = 0x80;

/// One flash sector, the unit an erase works in.
pub const FLASH_SECTOR_SIZE: u32 = 4096;

/// One flash page, the unit a program works in.
pub const FLASH_PAGE_SIZE: usize = 256;

/// One flash block, the unit a bulk erase works in.
pub const FLASH_BLOCK_SIZE: u32 = 65536;

/// Which system information flags exist, and how many words each carries.
///
/// The protocol names the flags and the device answers whichever of them it was
/// asked for, one after another, so the word counts are what a host reads the
/// answer apart by.
pub(crate) const INFO_FLAGS: [(u32, u32); 6] = [
    (0x0001, 3), // chip info
    (0x0002, 1), // critical
    (0x0004, 1), // cpu info
    (0x0008, 1), // flash device info
    (0x0010, 4), // boot random
    (0x0040, 4), // boot info
];

/// The most words any one system information flag carries.
///
/// This is what a buffer serving one flag has to be able to hold, and it is
/// taken from the table above rather than written out beside it, so a flag with
/// a longer answer widens the buffers that carry it instead of being quietly
/// refused by them.
pub const INFO_MAX_WORDS: usize = info_max_words();

const fn info_max_words() -> usize {
    let mut max = 0;
    let mut i = 0;
    while i < INFO_FLAGS.len() {
        if INFO_FLAGS[i].1 as usize > max {
            max = INFO_FLAGS[i].1 as usize;
        }
        i += 1;
    }
    max
}

/// The 32 bytes a host sends to start a command.
#[repr(C, packed)]
#[derive(Clone, Copy, Debug)]
pub struct Command {
    /// `MAGIC`, or the integrator's own for a custom command.
    pub magic: u32,
    /// The host's identifier for this command, echoed back in the status.
    pub token: u32,
    /// Which command.  Bit 7 set means the host is reading.
    pub cmd_id: u8,
    /// How many of the argument bytes this command uses.
    pub cmd_size: u8,
    /// Not used.
    pub reserved: u16,
    /// How many bytes the data phase carries.
    pub transfer_len: u32,
    /// The command's arguments, laid out per command.
    pub args: [u8; 16],
}

impl Command {
    /// True when the host is reading, from bit 7 of the identifier.
    #[must_use]
    pub const fn is_in(&self) -> bool {
        self.cmd_id & DIR_IN != 0
    }

    /// The first four argument bytes as a word.
    pub(crate) fn arg_u32(&self, at: usize) -> u32 {
        let mut b = [0u8; 4];
        b.copy_from_slice(&self.args[at..at + 4]);
        u32::from_le_bytes(b)
    }

    pub(crate) fn arg_u16(&self, at: usize) -> u16 {
        u16::from_le_bytes([self.args[at], self.args[at + 1]])
    }

    /// Read a command out of the bytes a transport handed over.
    ///
    /// Returns `None` for anything that is not `CMD_LEN` long.
    #[must_use]
    pub fn from_bytes(buf: &[u8]) -> Option<Self> {
        if buf.len() != CMD_LEN {
            return None;
        }
        let w = |at: usize| {
            let mut b = [0u8; 4];
            b.copy_from_slice(&buf[at..at + 4]);
            u32::from_le_bytes(b)
        };
        let mut args = [0u8; 16];
        args.copy_from_slice(&buf[16..32]);
        Some(Self {
            magic: w(0),
            token: w(4),
            cmd_id: buf[8],
            cmd_size: buf[9],
            reserved: u16::from_le_bytes([buf[10], buf[11]]),
            transfer_len: w(12),
            args,
        })
    }
}

/// The status block, as it sits in the state and goes on the wire.
///
/// Kept as bytes because a control transfer may be answered by handing the
/// caller a pointer that outlives the call, so it has to be storage the state
/// owns rather than a value built for the occasion.
#[derive(Clone, Copy, Debug)]
pub(crate) struct StatusBlock(pub(crate) [u8; STATUS_LEN]);

impl StatusBlock {
    pub(crate) const fn new() -> Self {
        Self([0; STATUS_LEN])
    }

    pub(crate) fn set(&mut self, token: u32, code: super::Status, cmd_id: u8, in_progress: bool) {
        self.0 = [0; STATUS_LEN];
        self.0[0..4].copy_from_slice(&token.to_le_bytes());
        self.0[4..8].copy_from_slice(&(code as u32).to_le_bytes());
        self.0[8] = cmd_id;
        self.0[9] = u8::from(in_progress);
    }

    pub(crate) fn set_in_progress(&mut self, in_progress: bool) {
        self.0[9] = u8::from(in_progress);
    }

    pub(crate) fn code(&self) -> u32 {
        u32::from_le_bytes([self.0[4], self.0[5], self.0[6], self.0[7]])
    }
}

// INFO_FLAGS and the function that reads it are both private, so this is here
// rather than in tests/.  Everything else about the wire is public and is
// tested from there.
#[cfg(test)]
mod tests {
    use super::{INFO_FLAGS, INFO_MAX_WORDS, info_max_words};

    #[test]
    fn the_widest_flag_in_the_table_is_what_sizes_a_buffer() {
        let widest = INFO_FLAGS
            .iter()
            .map(|(_, words)| *words as usize)
            .max()
            .expect("the table names at least one flag");
        assert_eq!(info_max_words(), widest);
        assert_eq!(INFO_MAX_WORDS, widest);
    }
}
