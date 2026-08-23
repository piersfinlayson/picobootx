// Copyright (C) 2026 Piers Finlayson <piers@piers.rocks>
//
// MIT License

//! What a device gets for free, and what it has to write.
//!
//! The conformance suite drives this library through the C ABI in
//! `picobootx-ffi`, which hands it a table of C function pointers.  A table is
//! either populated or null, so the suite never meets an `Ops` that left a
//! method to its default — and the defaults are the whole basis of the trait's
//! contract: `impl Ops for MyDevice {}` is a device that agrees to the three
//! advisory commands and refuses everything else.  This is where that is held.

use picobootx::wire::{CMD_LEN, DIR_IN, FLASH_PAGE_SIZE, MAGIC};
use picobootx::{Command, Custom, Ecc, Exclusive, NoCustom, Ops, Reboot, Status};

/// A device that writes no operation at all.
struct Bare;

impl Ops for Bare {}

/// A device with commands of its own, which writes the one method the trait
/// does not default.
struct Bespoke;

impl Custom for Bespoke {
    fn dispatch(&mut self, cmd: &Command) -> picobootx::Result {
        let _ = cmd;
        Ok(())
    }
}

fn reboot_args() -> Reboot {
    Reboot {
        flags: 2,
        delay_ms: 10,
        p0: 0,
        p1: 0,
    }
}

/// A command packet's 32 bytes, with the standard magic.
fn command_bytes(cmd_id: u8, transfer_len: u32) -> [u8; CMD_LEN] {
    let mut buf = [0u8; CMD_LEN];
    buf[0..4].copy_from_slice(&MAGIC.to_le_bytes());
    buf[4..8].copy_from_slice(&0x1234_5678u32.to_le_bytes());
    buf[8] = cmd_id;
    buf[9] = 8;
    buf[12..16].copy_from_slice(&transfer_len.to_le_bytes());
    buf
}

fn command(cmd_id: u8, transfer_len: u32) -> Command {
    Command::from_bytes(&command_bytes(cmd_id, transfer_len)).expect("32 bytes is a command")
}

#[test]
fn the_three_advisory_commands_are_agreed_to() {
    let mut d = Bare;

    assert_eq!(d.exclusive_access(Exclusive::NotExclusive), Ok(()));
    assert_eq!(d.exclusive_access(Exclusive::Exclusive), Ok(()));
    assert_eq!(d.exclusive_access(Exclusive::ExclusiveAndEject), Ok(()));

    // Including a value the protocol does not define.  A device that has not
    // written the method has taken no view on what exclusivity means to it, so
    // it has nothing to refuse this with either.
    assert_eq!(d.exclusive_access(Exclusive::Other(9)), Ok(()));

    assert_eq!(d.exit_xip(), Ok(()));
    assert_eq!(d.enter_xip(), Ok(()));
}

#[test]
fn every_command_that_moves_data_is_refused_as_one_this_device_does_not_serve() {
    let mut d = Bare;
    let mut out = [0u8; 4];
    let data = [0u8; 4];

    assert_eq!(d.read_prepare(0x2000_0000, 4), Err(Status::UnknownCmd));
    assert_eq!(d.read(0x2000_0000, &mut out), Err(Status::UnknownCmd));

    assert_eq!(d.write_prepare(0x2000_0000, 4), Err(Status::UnknownCmd));
    assert_eq!(d.write(0x2000_0000, &data), Err(Status::UnknownCmd));

    assert_eq!(
        d.flash_erase_prepare(0x1000_0000, 4096),
        Err(Status::UnknownCmd)
    );
    assert_eq!(d.flash_erase(0x1000_0000, 4096), Err(Status::UnknownCmd));

    assert_eq!(d.otp_read_prepare(0, 1, Ecc::Raw), Err(Status::UnknownCmd));
    assert_eq!(d.otp_read(0, Ecc::Raw, &mut out), Err(Status::UnknownCmd));
    assert_eq!(d.otp_write_prepare(0, 1, Ecc::Raw), Err(Status::UnknownCmd));
    assert_eq!(d.otp_write(0, Ecc::Raw, &data), Err(Status::UnknownCmd));

    assert_eq!(d.get_info_sys_prepare(0x0001), Err(Status::UnknownCmd));
    assert_eq!(d.get_info_sys(0x0001, &mut out), Err(Status::UnknownCmd));

    assert_eq!(d.reboot_prepare(&reboot_args()), Err(Status::UnknownCmd));
}

#[test]
fn a_flash_page_is_refused_as_one_this_device_will_not_write() {
    let mut d = Bare;

    // Not UnknownCmd, which is what the rest of them say.  write_prepare is
    // what decides whether WRITE is served at all, so a device that reported
    // flash from there and has no flash_page_write has said it serves the
    // command and will not write to that address.
    assert_eq!(
        d.flash_page_write(0x1000_0000, &[0xa5; FLASH_PAGE_SIZE]),
        Err(Status::NotPermitted)
    );
}

#[test]
fn a_table_of_custom_commands_that_names_no_magic_answers_for_none() {
    assert_eq!(Bespoke.magic(), None);
    assert_eq!(NoCustom.magic(), None);
}

#[test]
fn a_custom_command_carrying_data_needs_a_fill_written_for_it() {
    let cmd = command(0x01 | DIR_IN, 16);
    let mut buf = [0u8; 16];

    // dispatch is written, so the command itself is accepted.
    assert_eq!(Bespoke.dispatch(&cmd), Ok(()));

    // The payload is not, because nothing was written to produce it.
    assert_eq!(Bespoke.fill(&cmd, &mut buf), Err(Status::UnknownCmd));
}

#[test]
fn a_device_with_no_commands_of_its_own_refuses_every_one() {
    let cmd = command(0x01, 0);
    let mut none = NoCustom;

    assert_eq!(none.dispatch(&cmd), Err(Status::UnknownCmd));
}

#[test]
fn a_command_is_read_out_of_exactly_thirty_two_bytes() {
    let bytes = command_bytes(0x84, 0x100);

    let cmd = Command::from_bytes(&bytes).expect("32 bytes is a command");
    let (magic, token, cmd_id, cmd_size, transfer_len) = (
        cmd.magic,
        cmd.token,
        cmd.cmd_id,
        cmd.cmd_size,
        cmd.transfer_len,
    );
    assert_eq!(magic, MAGIC);
    assert_eq!(token, 0x1234_5678);
    assert_eq!(cmd_id, 0x84);
    assert_eq!(cmd_size, 8);
    assert_eq!(transfer_len, 0x100);
    assert!(cmd.is_in());

    // Bit 7 of the identifier is the direction, and nothing else in the packet
    // says which way the data goes.
    assert!(!command(0x05, 0x100).is_in());

    // One byte either side of a command is not one.  A transport that handed
    // over a partial packet, or two run together, must not be read as though
    // the first 32 bytes of it were a command.
    assert!(Command::from_bytes(&bytes[..CMD_LEN - 1]).is_none());
    let mut longer = [0u8; CMD_LEN + 1];
    longer[..CMD_LEN].copy_from_slice(&bytes);
    assert!(Command::from_bytes(&longer).is_none());
    assert!(Command::from_bytes(&[]).is_none());
}
