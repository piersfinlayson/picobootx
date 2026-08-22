/* Copyright (C) 2026 Piers Finlayson <piers@piers.rocks>
 *
 * MIT License
 */

/* An RP2350's flash window and SRAM, which is all cortex-m-rt's link.x asks
 * for.  ci/check-ramfunc.sh reads these two regions back out of this file, so
 * what it checks .ramfunc against is what the link was given.
 */

MEMORY
{
  FLASH : ORIGIN = 0x10000000, LENGTH = 2048K
  RAM   : ORIGIN = 0x20000000, LENGTH = 512K
}
