// Copyright (C) 2026 Piers Finlayson <piers@piers.rocks>
//
// MIT License

// picobootx conformance harness.
//
// The library under test is the shipped library: src/picobootx.c and
// src/picobootx_impl.c, compiled for this host with PICOBOOTX_HOST_TEST
// defined.  Nothing about the protocol, the state machine or the default
// command implementations is reimplemented here.
//
// What the harness supplies is everything on the other side of picobootx's two
// boundaries:
//
//   the wire        an implementation of the picoboot_vendor_* API, plus the
//                   two tinyusb control-transfer entry points, backed by packet
//                   queues rather than a USB bus  (pbt_wire.c)
//
//   the device      the memory, OTP and bootrom the default implementations
//                   reach for through the PICOBOOTX_HOST_TEST seams
//                   (pbt_device.c)
//
// Every observable thing either side does is appended to one sequence log, so a
// scenario can assert the order in which the device acted, not merely that it
// acted.

#if !defined(PICOBOOTX_TEST_PBT_H)
#define PICOBOOTX_TEST_PBT_H

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#include "picobootx.h"
#include "picobootx_impl.h"
#include "picobootx_private.h"
#include "picobootx_vendor.h"

// ---------------------------------------------------------------------------
// Fixed choices the harness makes
// ---------------------------------------------------------------------------

// Endpoint addresses picoboot_init is given.  Any pair would do.  These match
// the tinyusb example, so a log read alongside a real capture lines up.
#define PBT_EP_OUT 0x03u
#define PBT_EP_IN  0x84u

#define PBT_RHPORT 0u

// The magic the sample custom ops answer to.  Deliberately not PICOBOOT_MAGIC,
// and deliberately not a near-miss of it either.
#define PBT_CUSTOM_MAGIC 0x5ac3e17bu

// Largest packet the wire moves, which is the bulk endpoint size.
#define PBT_PACKET_MAX 64u

// ---------------------------------------------------------------------------
// Sequence log
// ---------------------------------------------------------------------------

// One observable action.  name identifies what happened and is matched
// literally by the query helpers below.  The four arguments are whatever that
// action carries, documented at each site that records one.
typedef struct {
    uint32_t    seq;
    const char *name;
    uint32_t    a0;
    uint32_t    a1;
    uint32_t    a2;
    uint32_t    a3;
} pbt_event_t;

// Record an action.  Called by the wire, the device model, the ops shims and
// the sample custom ops.
void pbt_log(const char *name, uint32_t a0, uint32_t a1, uint32_t a2, uint32_t a3);

uint32_t           pbt_event_count(void);
const pbt_event_t *pbt_event(uint32_t index);

// How many times an action was recorded.
int pbt_count(const char *name);

// The nth (zero-based) recording of an action, or NULL if there were fewer.
const pbt_event_t *pbt_nth(const char *name, int n);

// The sequence number of the first recording of an action, or -1 if it never
// happened.  Sequence numbers start at 1, so -1 is unambiguous.
int pbt_seq(const char *name);

// True when both actions happened and the first happened before the second.
// False if either is absent — an ordering claim about an action that never
// occurred is not satisfied, it is unanswerable, and silently passing would
// make the assertion worthless.
bool pbt_before(const char *first, const char *second);

// Print the whole log.  The runner does this for a failing scenario.
void pbt_dump_log(void);

// ---------------------------------------------------------------------------
// Assertions
// ---------------------------------------------------------------------------

// Record a failure against the running scenario.
void pbt_fail(const char *file, int line, const char *fmt, ...);

// Drop everything the sequence log holds.
void pbt_log_reset(void);

// True once the running scenario has recorded a failure.
bool pbt_failed(void);

// Forget the failures recorded against the running scenario.  The runner does
// this between scenarios, so pbt_failed answers about the one that just ran.
void pbt_fail_reset(void);

// Failures recorded since the process started, which pbt_fail_reset does not
// touch.  It is what the runner's closing tally counts.
unsigned pbt_fail_total(void);

// Check and carry on, so one run reports every problem it found.
#define PBT_CHECK(cond)                                                       \
    do {                                                                      \
        if (!(cond)) {                                                        \
            pbt_fail(__FILE__, __LINE__, "expected: %s", #cond);              \
        }                                                                     \
    } while (0)

#define PBT_CHECK_EQ(actual, expected)                                        \
    do {                                                                      \
        unsigned long long pbt_a_ = (unsigned long long)(actual);             \
        unsigned long long pbt_e_ = (unsigned long long)(expected);           \
        if (pbt_a_ != pbt_e_) {                                               \
            pbt_fail(__FILE__, __LINE__, "%s: expected %llu, got %llu",       \
                     #actual, pbt_e_, pbt_a_);                                \
        }                                                                     \
    } while (0)

// Check a picoboot status, reporting both by name rather than by number.
#define PBT_CHECK_STATUS(actual, expected)                                    \
    do {                                                                      \
        int pbt_a_ = (int)(actual);                                           \
        int pbt_e_ = (int)(expected);                                         \
        if (pbt_a_ != pbt_e_) {                                               \
            pbt_fail(__FILE__, __LINE__, "%s: expected %s, got %s",           \
                     #actual, pbt_status_name(pbt_e_),                        \
                     pbt_status_name(pbt_a_));                                \
        }                                                                     \
    } while (0)

// Check, and abandon the scenario if it does not hold.  For a precondition the
// rest of the scenario would only produce noise without.
#define PBT_REQUIRE(cond)                                                     \
    do {                                                                      \
        if (!(cond)) {                                                        \
            pbt_fail(__FILE__, __LINE__, "required: %s", #cond);              \
            return;                                                           \
        }                                                                     \
    } while (0)

const char *pbt_status_name(int status);
const char *pbt_state_name(pb_state_t state);

// ---------------------------------------------------------------------------
// Scenarios and suites
// ---------------------------------------------------------------------------

typedef void (*pbt_scenario_fn_t)(void);

typedef struct {
    const char       *name;
    pbt_scenario_fn_t fn;
} pbt_scenario_t;

typedef struct {
    const char           *name;
    const pbt_scenario_t *scenarios;
    unsigned              count;
} pbt_suite_t;

#define PBT_SUITE(symbol, label, table)                                       \
    const pbt_suite_t symbol = {                                              \
        (label), (table), (unsigned)(sizeof(table) / sizeof((table)[0]))      \
    }

// ---------------------------------------------------------------------------
// Setting a scenario up
// ---------------------------------------------------------------------------

// Reset the device model, the wire and the log, and populate pbt_ops with the
// full set of default implementations.  Call first in every scenario.
void pbt_begin(void);

// The callbacks picoboot_init will be given.  pbt_begin fills these in.  A
// scenario that wants to exercise a missing-callback path clears a member
// before calling pbt_start.
extern picoboot_ops_t        pbt_ops;

// The sample custom command implementation.  Registered only when
// pbt_use_custom is set.  A scenario may clear .fill, or point .dispatch
// elsewhere, before pbt_start.
extern picoboot_custom_ops_t pbt_custom_ops;

// Whether picoboot_init is given pbt_custom_ops.  Defaults to false.
extern bool pbt_use_custom;

// Whether picoboot_init is given a 256-byte flash write buffer.  Defaults to
// true.  Clearing it is how the WRITE-to-flash refusal path is armed.
extern bool pbt_use_flash_buf;

// The context pointer picoboot_init is given, which picobootx.h says is "handed
// back untouched on every call".  Defaults to NULL, which is every scenario
// whose callbacks keep nothing.  A scenario whose callback holds its answer
// between calls points this at where it holds it, before pbt_start.
extern void *pbt_ctx;

// Initialise the library with the above.  Call once, after any overrides.
void pbt_start(void);

// The library's state block.  picobootx.h declares the type without its
// layout, so this says which pointer it is without the harness knowing what is
// inside one.  What the state machine is doing is pbt_cur_state's answer.
pb_state_block_t *pbt_state(void);

// What the library is doing.
pb_state_t pbt_cur_state(void);

// ---------------------------------------------------------------------------
// The device model
// ---------------------------------------------------------------------------

// The modelled regions.  Index 0 of each is the region's base address, as
// declared in picobootx_impl.h.  Flash and ROM are modelled from their base for
// the sizes below rather than in full.  An access beyond a modelled window
// aborts with a message, because it means either the scenario or the address
// validation is wrong and neither should pass quietly.
#define PBT_ROM_MODELLED   RP2350_ROM_SIZE
#define PBT_SRAM_MODELLED  RP2350_SRAM_SIZE

// Flash is modelled from its base for this much.  A scenario says which
// addresses it uses, so the suites model a part's worth of it and no more, and
// an address outside that is a scenario asking for something it did not set up.
//
// The usbip bridge overrides it, because on the other end of that bus is a real
// tool choosing its own addresses.  picotool reads eight megabytes in while it
// is working out what is already on the part, and refusing that would be the
// harness deciding what a host may ask for.  It gives itself the whole window
// picobootx admits, so anything the library will accept, the model can answer.
#if !defined(PBT_FLASH_MODELLED)
#define PBT_FLASH_MODELLED 0x00040000u  // 256KB
#endif

// Put the modelled part back to how a part comes out of its packaging: flash
// erased, OTP blown nowhere, XIP up.  Whatever sets a scenario up calls this,
// and so does anything else that starts a device.
void pbt_device_reset(void);

uint8_t *pbt_rom(void);
uint8_t *pbt_flash(void);
uint8_t *pbt_sram(void);

// OTP, one 32-bit word per row.  The ECC view of a row is its low 16 bits.
#define PBT_OTP_ROWS 0x1000u
uint32_t *pbt_otp(void);

// Make a bootrom lookup for this two-character code answer NULL, as it would on
// a chip whose bootrom does not publish the routine.
void pbt_bootrom_withhold(char a, char b);

// Make the modelled OTP access refuse with this bootrom error code, as a part
// does when a row will not read or a fuse will not blow.  Zero puts it back to
// answering normally.
void pbt_otp_fail(int rc);

// The XIP clock divisor the model reports.  The erase sequence must read this
// and hand this same value back to the routine that restores XIP.
void pbt_set_xip_clkdiv(uint8_t clkdiv);

// ---------------------------------------------------------------------------
// The modelled get_sys_info  (RP2350 datasheet 5.4.8.17)
//
// The flags that section defines, and what the modelled part answers.  These
// live here rather than being read out of picobootx: the library holds no table
// of flags, and the suites must say what the datasheet says rather than what
// the implementation happens to do.
// ---------------------------------------------------------------------------

#define PBT_SYS_CHIP_INFO      0x0001u  // 3 words
#define PBT_SYS_CRITICAL       0x0002u  // 1 word
#define PBT_SYS_CPU_INFO       0x0004u  // 1 word
#define PBT_SYS_FLASH_DEV_INFO 0x0008u  // 1 word
#define PBT_SYS_BOOT_RANDOM    0x0010u  // 4 words
#define PBT_SYS_NONCE          0x0020u  // "not supported"
#define PBT_SYS_BOOT_INFO      0x0040u  // 4 words

// Every flag 5.4.8.17 names, which is what a host asking for all of them sends.
#define PBT_SYS_ALL 0x007Fu

// The subset of those the modelled part answers, and so the flags word it
// replies with when asked for all of them.  NONCE is the one 5.4.8.17 itself
// marks unsupported, and it is the flag a real RP2350 drops.
#define PBT_SYS_SERVED (PBT_SYS_ALL & ~PBT_SYS_NONCE)

// How many words of data the served flags carry between them.
#define PBT_SYS_SERVED_WORDS 14u

// Which flags the modelled get_sys_info answers.  A flag outside this set is
// dropped from the flags word it replies with and carries no data.  Defaults to
// PBT_SYS_SERVED.
void pbt_set_sys_info_supported(uint32_t mask);

// The word the modelled get_sys_info returns for a flag, in its first data
// word — the second is that plus one, and so on.  Distinct per flag, so a
// scenario can tell which flag's data came back rather than only how much did.
uint32_t pbt_sys_info_word(uint32_t flag);

// The flags 5.4.8.17 defines, in ascending order, and how many words of data a
// set of them carries between them.  One table, held in the device model, so a
// scenario's expectation and the modelled part cannot disagree about how long a
// flag's data is.  The datasheet is what either is checked against.
unsigned    pbt_sys_flag_count(void);
uint32_t    pbt_sys_flag_at(unsigned index);
const char *pbt_sys_flag_name(uint32_t flag);
uint32_t    pbt_sys_info_words(uint32_t flags);

// Make the modelled get_sys_info refuse with this bootrom error code, as a part
// does when it will not answer at all.  Zero puts it back to answering
// normally.
void pbt_sys_info_fail(int rc);

// The same, after this many calls have been answered.  One GET_INFO reaches the
// chip twice — once for how long the answer is, once for the answer itself — so
// a part that answers the first and refuses the second is one whose state moved
// between them, and it is the only way to reach a refusal partway through.
void pbt_sys_info_fail_after(unsigned calls, int rc);

// ---------------------------------------------------------------------------
// The modelled get_partition_table_info  (RP2350 datasheet 5.4.8.16)
// ---------------------------------------------------------------------------

#define PBT_PART_PT_INFO    0x0001u  // 3 words, about the table as a whole
#define PBT_PART_LOC_FLAGS  0x0010u  // 2 words per partition
#define PBT_PART_ID         0x0020u  // 2 words per partition
#define PBT_PART_FAMILY_IDS 0x0040u  // per partition, and none without one
#define PBT_PART_NAME       0x0080u  // per partition, and none without one
#define PBT_PART_SINGLE     0x8000u  // narrows the per-partition flags to one

// Every flag 5.4.8.16 defines, which is what a host asking for all of them
// sends.
#define PBT_PART_ALL                                                        \
    (PBT_PART_PT_INFO | PBT_PART_LOC_FLAGS | PBT_PART_ID |                  \
     PBT_PART_FAMILY_IDS | PBT_PART_NAME | PBT_PART_SINGLE)

// Every bit of flags_and_partition 5.4.8.16 gives a meaning to: those flags,
// and the top eight bits, which carry "the partition number" SINGLE_PARTITION
// selects.  The complement is the bits that section leaves undefined.
#define PBT_PART_DEFINED_BITS (PBT_PART_ALL | 0xFF000000u)

// The flags the modelled part answers.  PARTITION_FAMILY_IDS and PARTITION_NAME
// are defined by 5.4.8.16 and outside this set, so they are the partition
// side's dropped flags.
#define PBT_PART_SERVED \
    (PBT_PART_PT_INFO | PBT_PART_LOC_FLAGS | PBT_PART_ID | PBT_PART_SINGLE)

// The two words 5.4.8.16 reports for unpartitioned space.  Its note fixes the
// base offset at 0 and the size at 0x2000 sectors, which is what the location
// word carries.  These are the values a real RP2350 with no partition table
// answers with.
#define PBT_PT_UNPARTITIONED_LOCATION 0xFFFFE000u
#define PBT_PT_UNPARTITIONED_FLAGS    0xFC078000u

// ---------------------------------------------------------------------------
// What the RP2350 default answers for PB_INFO_PARTITION
//
// picobootx.h: "Served as a constant — no partitions, no partition table
// loaded, and all of flash unpartitioned and readable and writable by everyone
// ... picobootx does not read a partition table, and a device that has one
// answers this type itself."  So these are the default's own words, and the
// modelled part above is what a device with a partition table would answer
// instead.
//
// 5.4.8.16 gives PT_INFO's three words: partition_count in the low eight bits
// and partition_table_present at bit 8, then unpartitioned space's two words in
// 5.9.4.2's form.  No partitions and no table loaded is a first word of zero.
//
// The location word is the same one 5.4.8.16's note fixes — a base offset of 0
// and a size of 0x2000 sectors — which Table 473 places as a first sector of 0
// and a last sector of 8191, every bit of the thirteen that field has.  Table
// 472's six permission bits sit above it, all set, since nothing here is
// closed to anybody.
//
// The flags word carries those same six permissions and none of Table 474's
// ACCEPTS_DEFAULT_FAMILY bits, which is where it parts company with the
// modelled part.  Those bits say which UF2 families may be dragged onto the
// mass storage drive the bootrom presents in BOOTSEL mode, and a device running
// picobootx runs its own application and presents no such drive.
// ---------------------------------------------------------------------------

#define PBT_DEFAULT_PT_TABLE    0x00000000u
#define PBT_DEFAULT_PT_LOCATION 0xFFFFE000u
#define PBT_DEFAULT_PT_FLAGS    0xFC000000u

// How many words PT_INFO contributes.  A PB_INFO_PARTITION answer carrying it
// is the flags word and these three.
#define PBT_DEFAULT_PT_INFO_WORDS 3u

// ---------------------------------------------------------------------------
// What the RP2350 default answers for PB_INFO_UF2_TARGET
//
// 5.6.4.11 gives the type three words directly, with no flags word in front:
// "Word 0 : Target partition number", of which "-1 : if there is nowhere to
// download the family", and words 1 and 2 the target partition's own two words
// "if the partition number is not -1".
//
// picobootx.h: "Served, as nowhere.  A UF2 reaches a device by being dragged
// onto a mass storage drive, and picobootx has none and is told of none, so it
// has nowhere to name."  So the target is -1, and 5.6.4.11 leaves the two words
// behind it meaningless.  They are the two PB_INFO_PARTITION gives for
// unpartitioned space, "so the same region reads the same way whichever
// question a host asks."
//
// All three go however little the last two have to say — picotool checks the
// count is three before it reads the first word, so a transfer that cannot hold
// three is refused rather than served short.
// ---------------------------------------------------------------------------

#define PBT_DEFAULT_UF2_TARGET       0xFFFFFFFFu
#define PBT_DEFAULT_UF2_TARGET_WORDS 3u

// The most partitions the model will hold.  5.4.8.16 numbers partitions 0-15.
#define PBT_PARTITION_MAX 16u

// How many partitions the modelled table holds.  Defaults to none, which is the
// part the partition expectations were measured against.
void     pbt_set_partitions(unsigned count);
unsigned pbt_partition_count(void);

// Which flags the modelled get_partition_table_info answers.  Defaults to
// PBT_PART_SERVED.
void pbt_set_partition_supported(uint32_t mask);

// The word the modelled routine returns for a partition and a per-partition
// flag, in its first data word.  Distinct per partition and per flag, so a
// scenario can say whose data arrived and in what order.
uint32_t pbt_partition_word(unsigned index, uint32_t flag);

// Make the modelled get_partition_table_info refuse with this bootrom error
// code.  Zero puts it back to answering normally.
void pbt_partition_fail(int rc);

// The same, after this many calls have been answered.  5.4.8.16 describes
// exactly this part: the bootrom holds a hash of the partition table as it
// loaded it, and "If the hash has changed by the time this method is called"
// the routine returns BOOTROM_ERROR_INVALID_STATE.  A table rewritten between
// the two calls one GET_INFO makes is a part that answers the first and refuses
// the second.
void pbt_partition_fail_after(unsigned calls, int rc);

// True while the model has interrupts disabled, and true while flash is mapped
// for execute-in-place.  The erase sequence has to move both, in order.
bool pbt_irq_disabled(void);
bool pbt_xip_active(void);

// ---------------------------------------------------------------------------
// The wire
// ---------------------------------------------------------------------------

typedef struct {
    uint32_t len;
    uint8_t  data[PBT_PACKET_MAX];
} pbt_packet_t;

// Deliver one packet from host to device on the bulk OUT endpoint, exactly as
// the tinyusb vendor driver would: the bytes land in the receive FIFO and
// picoboot_rx_cb is called with what is now available.
void pbt_host_send(const void *data, uint32_t len);

// Deliver a 32-byte command packet.
void pbt_host_send_cmd(const picoboot_cmd_t *cmd);

// Deliver the host's completion packet for a device-to-host transfer.  A real
// host sends a zero-length packet.  picobootx also accepts a single byte, and
// pbt_host_ack_byte is how that second form is exercised.
void pbt_host_ack(void);
void pbt_host_ack_byte(void);

// Run picoboot_task until the device stops doing anything, delivering the
// transmit-completion callback for each packet the device emits, as the vendor
// driver does when the IN transfer finishes.  Fails the scenario rather than
// spinning if the device never settles.
void pbt_pump(void);

// One picoboot_task call, with no transmit completion delivered afterwards.
// Between this and pbt_complete_tx a scenario can look at the device in the
// state it is in once a packet has been queued and before the hardware has
// reported it gone — which is where the protocol's deferred actions live.
void pbt_task(void);

// Deliver the transmit-completion callback for every packet emitted and not yet
// reported.
void pbt_complete_tx(void);

// The packets the device has emitted on the bulk IN endpoint, oldest first.
uint32_t            pbt_packet_count(void);
const pbt_packet_t *pbt_packet(uint32_t index);

// Every emitted packet's payload run together, for asserting the content of a
// transfer without caring how it was split.
uint32_t pbt_payload_len(void);
const uint8_t *pbt_payload(void);

bool pbt_ep_stalled(uint8_t ep_addr);

// Stall an endpoint without the library's involvement, to arm the case where
// GET_COMMAND_STATUS finds an endpoint halted that the library did not halt.
void pbt_force_stall(uint8_t ep_addr);

// The size of the transmit FIFO the wire models, which on a device is
// CFG_TUD_PICOBOOT_TX_BUFSIZE and is therefore the integrator's to choose.
// Defaults to PBT_PACKET_MAX.  One smaller than an item a fill function
// produces in a single piece is what makes that function decline a call and ask
// to be called again, so this is how the retry side of the fill contract is
// reached.  Must not exceed PBT_PACKET_MAX, and is set before the transfer it
// applies to starts.
void pbt_wire_tx_fifo(uint32_t bytes);

// ---------------------------------------------------------------------------
// Transport faults
//
// picoboot_vendor_* is an interface picobootx offers and an integrator
// implements, and picobootx defends against one that accepts less than it was
// handed, or hands back less than it said it had.  Each of these arms that for
// one call, so a scenario can show what the library does with it and then that
// the next call is served normally.
// ---------------------------------------------------------------------------

// Make the next picoboot_vendor_send_zlp refuse, as the device's does when the
// IN endpoint is still claimed by a transfer that has not completed.
void pbt_wire_refuse_zlp(void);

// Make the next picoboot_vendor_read return at most this many bytes, whatever
// picoboot_vendor_available reported, consuming only what it returned.
void pbt_wire_short_read(uint32_t bytes);

// Make the next picoboot_vendor_write accept at most this many bytes.
void pbt_wire_short_write(uint32_t bytes);

// ---------------------------------------------------------------------------
// Control transfers
// ---------------------------------------------------------------------------

// Present a SETUP packet to picoboot_control_xfer_cb and return what it
// returned — false meaning the library declined the request and the
// application would handle it.
bool pbt_ctrl(uint8_t type, uint8_t recipient, uint8_t b_request,
              uint16_t w_value, uint16_t w_index, uint16_t w_length);

// The same, at a chosen stage.  A host drives a control transfer through SETUP
// and then a data stage and an acknowledgement stage, and the class driver is
// given all of them with the same SETUP packet, so a scenario that only ever
// presents SETUP is not showing the whole transfer.
bool pbt_ctrl_at_stage(uint8_t stage, uint8_t type, uint8_t recipient,
                       uint8_t b_request, uint16_t w_value, uint16_t w_index,
                       uint16_t w_length);

// GET_COMMAND_STATUS.  Returns false if the library declined, and otherwise
// fills out with the status block it answered with.
bool pbt_ctrl_get_status(picoboot_status_t *out);

// INTERFACE RESET.
bool pbt_ctrl_interface_reset(void);

// CLEAR_FEATURE(ENDPOINT_HALT).  The host stack unstalls the endpoint before
// the class driver sees the request, which is what the library's re-arm is
// reacting to, so the harness does the same.
bool pbt_ctrl_clear_ep_halt(uint8_t ep_addr);

// The most recent data stage the library answered a control request with.
uint32_t       pbt_ctrl_reply_len(void);
const uint8_t *pbt_ctrl_reply(void);

// ---------------------------------------------------------------------------
// Building commands
// ---------------------------------------------------------------------------

// A command packet with the standard magic, the given identity, and zeroed
// arguments.  Sequential tokens, so a scenario that sends several can tell the
// resulting statuses apart without inventing values.
picoboot_cmd_t pbt_cmd(uint8_t cmd_id, uint8_t cmd_size, uint32_t transfer_len);

// The same, carrying PBT_CUSTOM_MAGIC.
picoboot_cmd_t pbt_custom_cmd(uint8_t cmd_id, uint8_t cmd_size,
                              uint32_t transfer_len);

// Overlay argument structures onto a command's argument bytes.
void pbt_args_addr_size(picoboot_cmd_t *cmd, uint32_t addr, uint32_t size);
void pbt_args_otp(picoboot_cmd_t *cmd, uint16_t row, uint16_t row_count,
                  uint8_t ecc);
void pbt_args_get_info(picoboot_cmd_t *cmd, uint8_t info_type, uint32_t param0);
void pbt_args_reboot2(picoboot_cmd_t *cmd, uint32_t flags, uint32_t delay_ms,
                      uint32_t p0, uint32_t p1);
void pbt_args_exclusive_access(picoboot_cmd_t *cmd, uint8_t ea_type);

// ---------------------------------------------------------------------------
// Composite helpers
// ---------------------------------------------------------------------------

// Send a command, run the device to quiescence, and answer with the status the
// device would report to a host that asked.  The great majority of scenarios
// are shaped like this.
pb_status_t pbt_run_cmd(const picoboot_cmd_t *cmd);

// Clear a stall the way a host does — INTERFACE RESET — so a scenario can send
// a further command after one that halted the endpoints.  Fails the scenario if
// the device is not idle and unhalted afterwards, since every later assertion
// would then be measuring the wrong thing.
void pbt_recover(void);

// ---------------------------------------------------------------------------
// An integrator that serves the two UF2 GET_INFO types
//
// The default implementations answer the two types the bootrom has a routine
// for, and refuse the two UF2 types, which have none.  A scenario that wants a
// device serving those puts this pair into pbt_ops before pbt_start.  It hands
// the other two types to the defaults, so it is a device that serves all four.
//
// Both record under the same names as the default wrappers, since the log says
// which callback the library reached rather than what sits behind it.
// ---------------------------------------------------------------------------

pb_status_t pbt_uf2_get_info_prepare(pb_info_type_t type, uint32_t param0,
                                     uint32_t *words, void *ctx);
pb_status_t pbt_uf2_get_info(pb_info_type_t type, uint32_t param0,
                             uint32_t at_word, uint8_t *buf, uint32_t max_len,
                             uint32_t *bytes_written, void *ctx);

// The family id the modelled partition at this index accepts, and what
// UF2_TARGET answers for a family with nowhere to go.
#define PBT_UF2_FAMILY(index)  (0x5F320000u + (uint32_t)(index))
#define PBT_UF2_TARGET_NOWHERE 0xFFFFFFFFu

// UF2_STATUS's four words, as the model answers them.
#define PBT_UF2_STATUS_WORD0  0x01000000u
#define PBT_UF2_STATUS_FAMILY PBT_UF2_FAMILY(0)
#define PBT_UF2_STATUS_DONE   3u
#define PBT_UF2_STATUS_TOTAL  8u

// How many words each UF2 type answers with.
#define PBT_UF2_TARGET_WORDS 3u
#define PBT_UF2_STATUS_WORDS 4u

// ---------------------------------------------------------------------------
// An integrator that keeps a host out of part of OTP
//
// picoboot_ops_t's two OTP prepares are offered the whole request before any
// row is touched, which is the only place a range can be refused as a range —
// by the time otp_write runs, the rows ahead of the refusal have been blown.
// A device with rows of its own is what those callbacks are for, and this is
// that device.  A scenario puts the pair into pbt_ops before pbt_start.
//
// Rows from PBT_OTP_GUARD_FIRST up are the device's own and are refused with
// PB_STATUS_NOT_PERMITTED.  A request that reaches one is refused whole, even
// where it starts below the boundary.
// ---------------------------------------------------------------------------

#define PBT_OTP_GUARD_FIRST 0x40u

pb_status_t pbt_guarded_otp_read_prepare(uint16_t row, uint16_t row_count,
                                         uint8_t ecc, void *ctx);
pb_status_t pbt_guarded_otp_write_prepare(uint16_t row, uint16_t row_count,
                                          uint8_t ecc, void *ctx);

// ---------------------------------------------------------------------------
// The sample custom command implementation
// ---------------------------------------------------------------------------

// Command identifiers the sample custom ops recognise.  The identifier space of
// a custom magic belongs entirely to the integrator, so these overlap the
// standard command identifiers deliberately: a scenario can then show that a
// custom magic really does route by magic first.
#define PBT_CUSTOM_CMD_PING   0x01u  // no data phase
#define PBT_CUSTOM_CMD_REFUSE 0x02u  // dispatch refuses, with a chosen status
#define PBT_CUSTOM_CMD_COUNT  0x84u  // data in: a run of counted bytes
#define PBT_CUSTOM_CMD_STALL  0x85u  // data in: fill refuses partway through
#define PBT_CUSTOM_CMD_ITEMS  0x86u  // data in: fixed-size items, so fill has
                                     // to decline a call with too little room
#define PBT_CUSTOM_CMD_OVER   0x87u  // data in: fill reports writing more than
                                     // it wrote, and more than the room it was
                                     // offered
#define PBT_CUSTOM_CMD_BIG_ITEM 0x88u // data in: one indivisible item, of a size
                                     // a scenario chooses

// The status PBT_CUSTOM_CMD_REFUSE's dispatch returns, and the one
// PBT_CUSTOM_CMD_STALL's fill returns.  Neither is produced by any built-in
// path, so a scenario asserting them cannot pass by coincidence.
#define PBT_CUSTOM_REFUSE_STATUS PB_STATUS_MODIFIED_DATA
#define PBT_CUSTOM_FILL_STATUS   PB_STATUS_INTERLEAVED_WRITE

// How many bytes PBT_CUSTOM_CMD_STALL's fill produces before refusing.
#define PBT_CUSTOM_STALL_AFTER 8u

// The size of one PBT_CUSTOM_CMD_ITEMS item.  Not a divisor of the packet
// size, so a boundary lands mid-packet and fill has to decline at least once.
#define PBT_CUSTOM_ITEM_SIZE 24u

// The two sizes PBT_CUSTOM_CMD_BIG_ITEM's item is given.  One is larger than
// the buffer the library fills, so no call can ever hold it, and the other is
// exactly that buffer, so every call can.  The item size is the only thing
// between them.
#define PBT_CUSTOM_BIG_ITEM_SIZE 68u
#define PBT_CUSTOM_BIG_ITEM_FITS 64u

// How many bytes past what it wrote PBT_CUSTOM_CMD_OVER's fill claims.  On the
// call that finishes the transfer that figure is also past what the transfer
// had left, which is what pushes a library's count of the remainder below zero.
#define PBT_CUSTOM_OVERSTATE_BY 8u

// The size of PBT_CUSTOM_CMD_BIG_ITEM's item.  pbt_begin puts it back to
// PBT_CUSTOM_BIG_ITEM_SIZE.
void pbt_custom_set_big_item(uint32_t size);

// Reset the sample implementation's own progress tracking.  pbt_begin does
// this.  The callbacks keep their cursor here rather than in the library, which
// is the contract picoboot_custom_ops_t.fill states.
void pbt_custom_reset(void);

// The command the sample fill callback was handed on its most recent call, and
// how many times it has been called.  Used to show that the library preserves
// the originating command for the whole transfer.
const picoboot_cmd_t *pbt_custom_last_cmd(void);
uint32_t              pbt_custom_fill_calls(void);

// How many bytes the sample fill callback has actually written across this
// transfer, as opposed to how many it told the library it wrote.  A scenario
// asserts against this to say that nothing reached the host that the callback
// never produced.
uint32_t              pbt_custom_bytes_produced(void);

// ---------------------------------------------------------------------------
// The suites
//
// The runner in pbt_core.c takes its list from here rather than holding one, so
// that the two binaries built from this directory — the core suite and the usb
// suite — share a runner while each names its own scenarios.  Each supplies
// these two symbols.
// ---------------------------------------------------------------------------

extern const pbt_suite_t *const pbt_suites[];
extern const unsigned           pbt_suite_count;

extern const pbt_suite_t pbt_suite_framing;
extern const pbt_suite_t pbt_suite_stall;
extern const pbt_suite_t pbt_suite_zlp;
extern const pbt_suite_t pbt_suite_data_in;
extern const pbt_suite_t pbt_suite_data_out;
extern const pbt_suite_t pbt_suite_custom;
extern const pbt_suite_t pbt_suite_transport;
extern const pbt_suite_t pbt_suite_ops;
extern const pbt_suite_t pbt_suite_bootrom;
extern const pbt_suite_t pbt_suite_quirks;

#endif // PICOBOOTX_TEST_PBT_H
