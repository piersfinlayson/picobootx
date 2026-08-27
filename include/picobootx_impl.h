// Copyright (C) 2026 Piers Finlayson <piers@piers.rocks>
//
// MIT License

// Default picobootx protocol implementations.

#if !defined(PICOBOOTX_IMPL_H)
#define PICOBOOTX_IMPL_H

#include <stdint.h>
#include <stddef.h>
#include "picobootx.h"

// RP2350 memory regions
#define RP2350_ROM_BASE    0x00000000u
#define RP2350_ROM_SIZE    0x00008000u  // 32KB
#define RP2350_FLASH_BASE  0x10000000u
#define RP2350_FLASH_SIZE  0x02000000u  // 32MB
#define RP2350_SRAM_BASE   0x20000000u
#define RP2350_SRAM_SIZE   0x00082000u  // 520KB

#define FLASH_BLOCK_ERASE_CMD 0xd8u

// The bootrom publishes its function table through a lookup routine whose own
// address is stored, as a 16-bit value, at this fixed address low in the
// address map.
#define RP2350_ROM_TABLE_LOOKUP_ADDR  0x00000016u

// Selects the Arm secure entry in a bootrom table entry's flag set.
#define RP2350_ROM_TABLE_FLAG_FUNC_ARM_SEC 0x0004u

// The QMI's mode-0 timing register carries the XIP clock divisor.  The erase
// sequence has to read it before taking flash out of XIP, so that XIP can be
// restored on the same divisor afterwards.
#define RP2350_XIP_QMI_BASE            0x400d0000u
#define RP2350_XIP_QMI_M0_TIMING_ADDR  (RP2350_XIP_QMI_BASE + 0x0cu)
#define RP2350_XIP_QMI_M0_CLKDIV_SHIFT 0u
#define RP2350_XIP_QMI_M0_CLKDIV_MASK  0xffu

// ---------------------------------------------------------------------------
// Host-test seams
//
// Everything in this section exists because the default implementations below
// reach past the picoboot protocol to the chip they run on: a bootrom table at
// an absolute address, a QMI register, the interrupt-enable bit, and reads and
// writes of arbitrary device addresses.  Each is a place where a build for a
// machine that is not an RP2350 would fault rather than misbehave, so each goes
// through a macro here.
//
// Defining PICOBOOTX_HOST_TEST selects the host expansions, which call out to
// functions a test harness supplies.  Leaving it undefined — which is every
// build for a device — expands to exactly the code that was written inline
// before the seam existed, so a device build is unaffected.
// ---------------------------------------------------------------------------

#if !defined(PICOBOOTX_HOST_TEST)
// Device implementation of PICOBOOTX_BOOTROM_LOOKUP.  A function rather than a
// macro body so the diagnostic suppression the absolute dereference needs has
// somewhere ordinary to live: the compiler cannot know address 0x16 holds a
// valid object, and says so.
static inline void *picobootx_bootrom_lookup_impl(uint32_t code, uint32_t mask) {
    typedef void *(*picobootx_rom_table_lookup_fn)(uint32_t code, uint32_t mask);
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Warray-bounds"
    picobootx_rom_table_lookup_fn lookup =
        (picobootx_rom_table_lookup_fn)(uintptr_t) *
        (uint16_t *)(uintptr_t)RP2350_ROM_TABLE_LOOKUP_ADDR;
#pragma GCC diagnostic pop
    return lookup(code, mask);
}
#endif

#if defined(PICOBOOTX_HOST_TEST)
// Host-test seam.  See PICOBOOTX_BOOTROM_LOOKUP.
void *picobootx_host_test_bootrom_lookup(uint32_t code, uint32_t mask);

// Host-test seam.  See PICOBOOTX_XIP_CLKDIV.
uint8_t picobootx_host_test_xip_clkdiv(void);

// Host-test seam.  See PICOBOOTX_IRQ_DISABLE and PICOBOOTX_IRQ_ENABLE.
void picobootx_host_test_irq_disable(void);
void picobootx_host_test_irq_enable(void);

// Host-test seam.  See PICOBOOTX_DEV_PTR.
void *picobootx_host_test_dev_ptr(uint32_t addr, uint32_t len);
#endif

// Look a bootrom function up by its two-character code.
//
// On a device this reads the fixed address the lookup routine's own address is
// stored at, and calls through it.  On a host there is no bootrom and that
// address is not mapped, so the harness supplies stand-ins.
#if defined(PICOBOOTX_HOST_TEST)
#define PICOBOOTX_BOOTROM_LOOKUP(code, mask) \
    picobootx_host_test_bootrom_lookup((code), (mask))
#else
#define PICOBOOTX_BOOTROM_LOOKUP(code, mask) \
    picobootx_bootrom_lookup_impl((code), (mask))
#endif

// The XIP clock divisor currently in force.
//
// On a device this reads the QMI timing register.  On a host there is no QMI.
#if defined(PICOBOOTX_HOST_TEST)
#define PICOBOOTX_XIP_CLKDIV() picobootx_host_test_xip_clkdiv()
#else
#define PICOBOOTX_XIP_CLKDIV()                                                \
    ((uint8_t)((*((volatile uint32_t *)(uintptr_t)                            \
                  RP2350_XIP_QMI_M0_TIMING_ADDR)                              \
                >> RP2350_XIP_QMI_M0_CLKDIV_SHIFT)                            \
               & RP2350_XIP_QMI_M0_CLKDIV_MASK))
#endif

// Disable and re-enable interrupts around a window in which flash cannot be
// read.  Interrupt handlers are themselves served from flash, so one taken
// inside that window would fetch from a bus that is not answering.
//
// On a device these are the Cortex-M instructions.  On a host there is nothing
// to disable, but the harness still records the calls: whether the erase ran
// with interrupts off, and whether they were turned back on, is part of what
// the sequence has to get right.
#if defined(PICOBOOTX_HOST_TEST)
#define PICOBOOTX_IRQ_DISABLE() picobootx_host_test_irq_disable()
#define PICOBOOTX_IRQ_ENABLE()  picobootx_host_test_irq_enable()
#else
#define PICOBOOTX_IRQ_DISABLE() __asm volatile ("cpsid i")
#define PICOBOOTX_IRQ_ENABLE()  __asm volatile ("cpsie i")
#endif

// Place a function in RAM.
//
// A function that runs while flash is unreadable must not itself be fetched
// from flash.  On a device that means a named section the linker script places
// in RAM.  A host has no such section, and no reason for one.
#if defined(PICOBOOTX_HOST_TEST)
#define PICOBOOTX_RAMFUNC __attribute__((noinline))
#else
#define PICOBOOTX_RAMFUNC __attribute__((section(".ramfunc"), noinline))
#endif

// Obtain a dereferenceable pointer for a device address.
//
// READ and WRITE name addresses in the device's own address space, and on a
// device the address already is the pointer.  A host process does not share
// that address space and its pointers are wider, so the harness maps the
// address into the memory it is standing the device's in for.
//
// len is the number of bytes about to be accessed, so that a host mapping can
// reject a range that leaves the region it belongs to.  Callers are expected to
// have validated the range already — picoboot_default_read_prepare and
// picoboot_default_write_prepare do — so a mapping that fails here is a bug in
// the caller or the harness, not a runtime condition to handle.
#if defined(PICOBOOTX_HOST_TEST)
#define PICOBOOTX_DEV_PTR(addr, len) picobootx_host_test_dev_ptr((addr), (len))
#else
#define PICOBOOTX_DEV_PTR(addr, len) ((void)(len), (void *)(uintptr_t)(addr))
#endif

// Helper to take return codes from boot ROM functions and convert to
// pb_status_t
pb_status_t pb_status_from_bootrom(int ret);

// Lookup RP2350 bootrom functions
void *picoboot_lookup_boot_fn(char a, char b);

// Returns PB_STATUS_OK for all EXCLUSIVE_ACCESS types, or PB_STATUS_INVALID_ARG
// for unknown types.
pb_status_t picoboot_default_exclusive_access(
    const pb_exclusive_access_args_t *args, 
    void *ctx
);

// Returns PB_STATUS_OK.
pb_status_t picoboot_default_exit_xip(void *ctx);

// Returns PB_STATUS_OK.
pb_status_t picoboot_default_enter_xip(void *ctx);

// Returns PB_STATUS_OK.  Does not check arguments or reboot.
pb_status_t picoboot_default_reboot2_prepare(
    const pb_reboot2_args_t *args, 
    void *ctx
);

// Reboots into BOOTSEL using the provided arguments.
void picoboot_default_reboot2_execute(
    const pb_reboot2_args_t *args, 
    void *ctx
);

// Validates standard set of addresses for an RP2350
pb_status_t picoboot_default_read_prepare(
    uint32_t addr, 
    uint32_t size, 
    void *ctx
);

// Reads data from the specified address. Does not perform any validation.
pb_status_t picoboot_default_read(
    uint32_t addr, 
    uint8_t *buf, 
    uint32_t size, 
    void *ctx
);

// Validates write is to a supported address for an RP2350 
pb_status_t picoboot_default_write_prepare(
    uint32_t addr,
    uint32_t size,
    bool *is_flash,
    void *ctx
);

// Writes data to the specified address.  Does not perform any validation.
pb_status_t picoboot_default_write(
    uint32_t addr,
    const uint8_t *buf,
    uint32_t len,
    void *ctx
);

// Writes a 256-byte page to flash at the specified address.
// Does not perform any validation.
pb_status_t picoboot_default_flash_page_write(
    uint32_t addr,
    const uint8_t *buf,
    void *ctx
);

// Validates flash erase parameters for an RP2350
pb_status_t picoboot_default_flash_erase_prepare(
    const pb_addr_size_args_t *args,
    void *ctx
);

// Performs flash erase.  Does not perform any validation.
pb_status_t picoboot_default_flash_erase(
    const pb_addr_size_args_t *args,
    void *ctx
);

// Reads OTP data as specified.
pb_status_t picoboot_default_otp_read(
    uint16_t row,
    uint8_t ecc,
    uint8_t *buf,
    uint32_t len,
    void *ctx
);

// Writes OTP data as specified.
// len is the length of the buffer in bytes
pb_status_t picoboot_default_otp_write(
    uint16_t row,
    uint8_t ecc,
    const uint8_t *buf,
    uint32_t len,
    void *ctx
);

// Reports how many words this part's answer to an information request will be,
// by asking the ROM routine that answers it.  PB_INFO_SYS goes to get_sys_info
// and PB_INFO_PARTITION to get_partition_table_info.  PB_INFO_UF2_TARGET is
// answered as nowhere: picobootx presents no mass storage drive for a UF2 to be
// dragged onto and is told of none, so it has nowhere to name.
// PB_INFO_UF2_STATUS is refused with PB_STATUS_INVALID_ARG, since it reports a
// download over such a drive.  A device that presents one answers both itself.
pb_status_t picoboot_default_get_info_prepare(
    pb_info_type_t  type,
    uint32_t        param0,
    uint32_t       *words,
    void           *ctx
);

// Produces that answer, from at_word onwards, in whole words — a max_len that
// is not a whole number of them has the remainder left alone.  Keeps no state
// between calls:
// the ROM routine takes no offset, so the whole answer is produced again and
// the window copied out.
pb_status_t picoboot_default_get_info(
    pb_info_type_t  type,
    uint32_t        param0,
    uint32_t        at_word,
    uint8_t        *buf,
    uint32_t        max_len,
    uint32_t       *bytes_written,
    void           *ctx
);

// Retrieve the device's serial number, as UTF-16, for inclusion in a USB
// descriptor.
size_t picoboot_get_serial(uint16_t *buffer, size_t max_len);

#endif // PICOBOOTX_IMPL_H
