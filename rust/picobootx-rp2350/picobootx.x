/* Copyright (C) 2026 Piers Finlayson <piers@piers.rocks>
 *
 * MIT License
 */

/* Where picobootx-rp2350's flash erase runs.
 *
 * The part of an erase that runs while flash is answering serial commands
 * cannot be fetched from flash, so it is placed in .ramfunc, which has to be
 * resident in RAM and loaded from the image.
 *
 * This is inserted after cortex-m-rt's .data, which is what carries it.  The
 * section takes .data's output region and .data's load region, and pushes
 * __edata past its end, so the copy cortex-m-rt's startup already makes from
 * __sidata to __sdata..__edata fills this section too.  That is why the
 * regions below are RAM and FLASH rather than anything of picobootx's own
 * choosing, and why nothing here may change them.
 *
 * Reach it with one flag, alongside the one that reaches cortex-m-rt's script:
 *
 *     rustflags = ["-C", "link-arg=-Tlink.x", "-C", "link-arg=-Tpicobootx.x"]
 *
 * That is for rust-lld, the default linker for the thumb targets.  GNU ld does
 * not resolve INSERT AFTER against a script named by a second -T, and fails
 * the link with ".data not found for insert".  Under GNU ld, drop the flag and
 * paste the SECTIONS block below into your own memory.x instead: link.x does
 * INCLUDE memory.x, so the INSERT and the .data it names end up in one script,
 * which is what GNU ld needs.
 *
 * A linker script of your own may place .ramfunc instead.  It has to give the
 * section an address in SRAM and a load address in flash, and the startup has
 * to copy it before anything erases flash.  picobootx-rp2350 checks both while
 * flash still answers, and refuses the erase if either is untrue.
 */

SECTIONS
{
  .ramfunc : ALIGN(4)
  {
    . = ALIGN(4);
    *(.ramfunc .ramfunc.*);
    . = ALIGN(4);
  } > RAM AT>FLASH
} INSERT AFTER .data;
