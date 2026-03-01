# picobootx tinyusb Example

This example provides a complete, bare-metal, working picobootx tinyusb implementation for the RP2350 using tinyusb and pico-sdkless.  It is intended to be used as a reference for building picobootx with tinyusb.

It implements a single vendor interface implementing the picoboot protocol using the standard RP2350 VID/PID 2e8a/000f.  It supports being queried by Raspberry Pi's [picotool](https://github.com/raspberrypi/picotool) and other picoboot compatible tools including [pico⚡flash](https://picoflash.org) and [Rust picoboot](https://docs.rs/picoboot/latest/picoboot/).

## Usage

The arm-gcc-none-ebai toolchain is required.  Install it if required:

```bash
sudo apt install gcc-arm-none-eabi
```

From this directory

```bash
make
```

This creates the following files

```text
build/picobootx.bin
build/picobootx.elf 
build/picobootx.uf2
```

Flash your preferred format to a RP2350-based board and then run picotool.  For example:

```bash
picotool info -a
```

You should see output similar to the following:

```text
Program Information
 target chip:         RP2350
 image type:          ARM Secure

Fixed Pin Information
 none

Build Information
 none

Metadata Block 1
 address:             0x10000110
 next block address:  0x10000110
 block type:          image def
 target chip:         RP2350
 image type:          ARM Secure

Metadata Block 2
 address:             0x10000110
 next block address:  0x10000110
 block type:          image def
 target chip:         RP2350
 image type:          ARM Secure

Device Information
 type:                RP2350
 revision:            Unknown
 package:             QFN60
 chipid:              0x0000000058ad06d6
 rom gitrev:          0xa8bfe860
 flash size:          2048K
```