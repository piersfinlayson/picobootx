/* Copyright (C) 2026 Piers Finlayson <piers@piers.rocks>
 *
 * MIT License
 */

/* An RP2350's flash window and SRAM, and the two blocks its boot ROM looks
 * for.  Nothing here is picobootx's - it is what any cortex-m-rt program for
 * the part needs, and embassy-rp fills the blocks in.
 */

/* The part carries 2048K of flash.  Only the first 1024K is offered to the
 * linker, so the window the flash checks erase and program - which starts at
 * 1024K - cannot be occupied by this firmware whatever it grows into.  A
 * firmware that outgrew the half it has fails to link, which is the point: the
 * alternative is a constant on each side and a comment asking that they agree.
 */
MEMORY
{
  FLASH : ORIGIN = 0x10000000, LENGTH = 1024K
  RAM   : ORIGIN = 0x20000000, LENGTH = 512K
}

/* The boot ROM reads the image definition out of the first 4K of flash, so it
 * goes straight after the vector table.
 */
SECTIONS {
    .start_block : ALIGN(4)
    {
        __start_block_addr = .;
        KEEP(*(.start_block));
        KEEP(*(.boot_info));
    } > FLASH
} INSERT AFTER .vector_table;

_stext = ADDR(.start_block) + SIZEOF(.start_block);

SECTIONS {
    .end_block : ALIGN(4)
    {
        __end_block_addr = .;
        KEEP(*(.end_block));
    } > FLASH
} INSERT AFTER .uninit;

PROVIDE(start_to_end = __end_block_addr - __start_block_addr);
PROVIDE(end_to_start = __start_block_addr - __end_block_addr);
