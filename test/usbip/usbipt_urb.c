// Copyright (C) 2026 Piers Finlayson <piers@piers.rocks>
//
// MIT License

// URBs, and what the device does with them.
//
// The kernel sends a 48 byte header, followed by the payload when it is sending
// one, and expects a 48 byte header back, followed by the payload when the
// device produced one.  Every number in the header is in network byte order
// except the eight setup bytes, which are the packet the device sees and are
// passed through untouched.
//
// The bus below the socket is usbt_dcd.c, which moves one packet per call and
// reports a transfer complete the way a controller's interrupt does.  So the
// translation is not one URB to one call: a URB is a transfer, and a transfer is
// as many packets as the device chooses to answer with.
//
// A URB the device cannot satisfy yet is held rather than refused.  On a bus the
// device would be NAKing and the host retrying, and the transfer would sit there
// until it was answered or the host gave up — and giving up is what the kernel's
// CMD_UNLINK says.  Holding it is therefore the accurate answer, and it is what
// makes picotool's read of an endpoint with nothing on it behave as it does
// against a real part.

#include <errno.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "tusb.h"
#include "usbt.h"
#include "usbt_dcd.h"
#include "usbipt.h"

// ---------------------------------------------------------------------------
// The protocol
// ---------------------------------------------------------------------------

#define USBIPT_HDR_LEN 48u

#define USBIPT_CMD_SUBMIT 1u
#define USBIPT_CMD_UNLINK 2u
#define USBIPT_RET_SUBMIT 3u
#define USBIPT_RET_UNLINK 4u

#define USBIPT_DIR_OUT 0u
#define USBIPT_DIR_IN  1u

// Offsets into the header.  The first five words are common to every message,
// and what follows depends on which message it is.
#define USBIPT_OFF_COMMAND   0u
#define USBIPT_OFF_SEQNUM    4u
#define USBIPT_OFF_DEVID     8u
#define USBIPT_OFF_DIRECTION 12u
#define USBIPT_OFF_EP        16u

// CMD_SUBMIT
#define USBIPT_OFF_XFER_FLAGS 20u
#define USBIPT_OFF_XFER_LEN   24u
#define USBIPT_OFF_SETUP      40u

// RET_SUBMIT
#define USBIPT_OFF_STATUS     20u
#define USBIPT_OFF_ACTUAL_LEN 24u

// CMD_UNLINK and RET_UNLINK both carry their one word here.
#define USBIPT_OFF_UNLINK 20u

// What the kernel makes of a completion.  These are the errno values Linux uses
// on a URB, negated, and they mean to the host exactly what they would if a
// controller had reported them.
#define USBIPT_EPIPE      (-32)   // the endpoint is halted
#define USBIPT_ECONNRESET (-104)  // the URB was unlinked before it finished
#define USBIPT_EOVERFLOW  (-75)   // more was asked for than can be held

// Largest transfer this will hold.  picotool's transfers are a few kilobytes,
// and a header claiming more than this is a message that was misread rather than
// a request worth serving.
#define USBIPT_XFER_MAX (1u << 20)

// URBs the device may be working on at once.  The kernel submits one transfer at
// a time per endpoint for a tool like picotool, so this is slack rather than a
// figure anything depends on.
#define USBIPT_URB_MAX 16u

// A full speed bulk packet, which is what the descriptors declare.
#define USBIPT_PACKET_MAX 64u

#define USBIPT_EP0_OUT 0x00u
#define USBIPT_EP0_IN  0x80u

typedef struct {
    bool     busy;
    uint32_t seqnum;
    uint8_t  ep_addr;  // endpoint number with the direction bit, as USB writes it
    bool     in;
    uint32_t length;
    uint32_t moved;
    uint8_t *data;
} usbipt_urb_t;

static usbipt_urb_t s_urb[USBIPT_URB_MAX];

// ---------------------------------------------------------------------------
// Bytes on and off the wire
// ---------------------------------------------------------------------------

static uint32_t get32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static void put32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

// read() and write() on a stream may move less than asked for.  Everything here
// is a message of a known length, so a short move is a message to finish rather
// than a message to act on.
static bool read_all(int fd, void *buf, size_t len) {
    uint8_t *p = buf;
    while (len > 0) {
        ssize_t n = read(fd, p, len);
        if (n == 0) {
            return false;  // the kernel closed the bus
        }
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            usbipt_error("read from the bus: %s", strerror(errno));
            return false;
        }
        p += n;
        len -= (size_t)n;
    }
    return true;
}

static bool write_all(int fd, const void *buf, size_t len) {
    const uint8_t *p = buf;
    while (len > 0) {
        ssize_t n = write(fd, p, len);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            usbipt_error("write to the bus: %s", strerror(errno));
            return false;
        }
        p += n;
        len -= (size_t)n;
    }
    return true;
}

// ---------------------------------------------------------------------------
// Answering
// ---------------------------------------------------------------------------

// Report a transfer finished.  The kernel matches the answer to the request by
// sequence number alone and ignores the rest of the first five words, which is
// why they go back as zero — that is what a usbip server sends.
static bool ret_submit(int fd, const usbipt_urb_t *urb, int status) {
    uint8_t hdr[USBIPT_HDR_LEN];
    memset(hdr, 0, sizeof(hdr));

    put32(hdr + USBIPT_OFF_COMMAND, USBIPT_RET_SUBMIT);
    put32(hdr + USBIPT_OFF_SEQNUM, urb->seqnum);
    put32(hdr + USBIPT_OFF_STATUS, (uint32_t)status);
    put32(hdr + USBIPT_OFF_ACTUAL_LEN, status == 0 ? urb->moved : 0u);

    usbipt_trace("  ret  seq %u ep %02x status %d, %u bytes", urb->seqnum,
                 urb->ep_addr, status, status == 0 ? urb->moved : 0u);

    if (!write_all(fd, hdr, sizeof(hdr))) {
        return false;
    }

    // Only a transfer that produced something carries a payload back, and only
    // an IN transfer can have produced one.
    if (status == 0 && urb->in && urb->moved > 0) {
        return write_all(fd, urb->data, urb->moved);
    }
    return true;
}

static bool ret_unlink(int fd, uint32_t seqnum, int status) {
    uint8_t hdr[USBIPT_HDR_LEN];
    memset(hdr, 0, sizeof(hdr));

    put32(hdr + USBIPT_OFF_COMMAND, USBIPT_RET_UNLINK);
    put32(hdr + USBIPT_OFF_SEQNUM, seqnum);
    put32(hdr + USBIPT_OFF_UNLINK, (uint32_t)status);

    usbipt_trace("  ret  unlink seq %u status %d", seqnum, status);
    return write_all(fd, hdr, sizeof(hdr));
}

static void urb_release(usbipt_urb_t *urb) {
    free(urb->data);
    urb->data = NULL;
    urb->busy = false;
}

// ---------------------------------------------------------------------------
// Control transfers
//
// These run to completion in one go.  The device answers a SETUP packet from
// tinyusb's own control machinery, which needs nothing from outside to make
// progress, so there is nothing for a control URB to wait on the way a bulk one
// waits on the protocol.
// ---------------------------------------------------------------------------

// A stall on either half of the control endpoint is the device refusing the
// request as a whole, which is what a host sees.
static bool ctrl_stalled(void) {
    return usbt_dcd_ep_stalled(USBIPT_EP0_IN) ||
           usbt_dcd_ep_stalled(USBIPT_EP0_OUT);
}

static int ctrl_xfer(usbipt_urb_t *urb, const uint8_t setup[8]) {
    const bool     device_to_host = (setup[0] & 0x80u) != 0u;
    const uint16_t wLength = (uint16_t)(setup[6] | ((uint16_t)setup[7] << 8));

    usbt_dcd_setup(setup);
    usbipt_device_pump();

    if (ctrl_stalled()) {
        return USBIPT_EPIPE;
    }

    uint8_t discard[USBIPT_PACKET_MAX];

    if (wLength > 0 && device_to_host) {
        while (urb->moved < urb->length && usbt_dcd_ep_pending(USBIPT_EP0_IN)) {
            uint32_t room = urb->length - urb->moved;
            if (room > USBIPT_PACKET_MAX) {
                room = USBIPT_PACKET_MAX;
            }

            uint32_t took =
                usbt_dcd_take_in(USBIPT_EP0_IN, urb->data + urb->moved, room);
            urb->moved += took;
            usbipt_device_pump();

            if (ctrl_stalled()) {
                return USBIPT_EPIPE;
            }
            if (took < USBIPT_PACKET_MAX) {
                break;  // a short packet ends the data stage
            }
        }

        // The host acknowledges with a zero length OUT.
        usbt_dcd_give_out(USBIPT_EP0_OUT, NULL, 0);
        usbipt_device_pump();
    } else if (wLength > 0) {
        while (urb->moved < urb->length) {
            uint32_t chunk = urb->length - urb->moved;
            if (chunk > USBIPT_PACKET_MAX) {
                chunk = USBIPT_PACKET_MAX;
            }
            if (usbt_dcd_give_out(USBIPT_EP0_OUT, urb->data + urb->moved,
                                  chunk) == 0) {
                break;
            }
            urb->moved += chunk;
            usbipt_device_pump();

            if (ctrl_stalled()) {
                return USBIPT_EPIPE;
            }
        }

        // The device acknowledges with a zero length IN.
        usbt_dcd_take_in(USBIPT_EP0_IN, discard, sizeof(discard));
        usbipt_device_pump();
    } else {
        // No data stage, so the status stage is the whole of the reply.
        usbt_dcd_take_in(USBIPT_EP0_IN, discard, sizeof(discard));
        usbipt_device_pump();
    }

    return ctrl_stalled() ? USBIPT_EPIPE : 0;
}

// ---------------------------------------------------------------------------
// Bulk transfers
// ---------------------------------------------------------------------------

// Move what the device will move now.  Answers the status to report, or leaves
// *done false when the device has not finished and the URB is to be held.
static int bulk_progress(usbipt_urb_t *urb, bool *done) {
    *done = false;

    // A halted endpoint ends whatever was on it.  The host learns of a halt from
    // the transfer that met it, which is this one.
    if (usbt_dcd_ep_stalled(urb->ep_addr)) {
        *done = true;
        return USBIPT_EPIPE;
    }

    while (urb->moved < urb->length) {
        if (!usbt_dcd_ep_pending(urb->ep_addr)) {
            // Nothing queued on the device, so a packet now would be NAKed.
            // Hold the URB — the device may queue something on a later turn.
            return 0;
        }

        uint32_t room = urb->length - urb->moved;
        if (room > USBIPT_PACKET_MAX) {
            room = USBIPT_PACKET_MAX;
        }

        uint32_t took;
        if (urb->in) {
            took = usbt_dcd_take_in(urb->ep_addr, urb->data + urb->moved, room);
        } else {
            took = usbt_dcd_give_out(urb->ep_addr, urb->data + urb->moved, room);
        }
        urb->moved += took;
        usbipt_device_pump();

        if (usbt_dcd_ep_stalled(urb->ep_addr)) {
            // The bytes already moved stay moved: on a bus the device took them
            // before it refused what they said, and the host finds out from the
            // next transaction rather than this one.
            *done = true;
            return USBIPT_EPIPE;
        }

        // A packet shorter than the maximum ends a transfer, and a zero length
        // one is the shortest of those.  It is a message in this protocol, and
        // it reaches the host as a completion carrying no bytes.
        if (urb->in && took < USBIPT_PACKET_MAX) {
            break;
        }
        if (!urb->in && took == 0) {
            return 0;  // the device took none of it, so wait rather than spin
        }
    }

    *done = true;
    return 0;
}

// ---------------------------------------------------------------------------
// What arrives
// ---------------------------------------------------------------------------

static usbipt_urb_t *urb_slot(void) {
    for (unsigned i = 0; i < USBIPT_URB_MAX; i++) {
        if (!s_urb[i].busy) {
            return &s_urb[i];
        }
    }
    return NULL;
}

static bool cmd_submit(int fd, const uint8_t *hdr) {
    const uint32_t seqnum = get32(hdr + USBIPT_OFF_SEQNUM);
    const uint32_t dir    = get32(hdr + USBIPT_OFF_DIRECTION);
    const uint32_t ep     = get32(hdr + USBIPT_OFF_EP);
    const uint32_t length = get32(hdr + USBIPT_OFF_XFER_LEN);

    usbipt_urb_t staged = {
        .busy    = true,
        .seqnum  = seqnum,
        .ep_addr = (uint8_t)((ep & 0x0Fu) | (dir == USBIPT_DIR_IN ? 0x80u : 0u)),
        .in      = dir == USBIPT_DIR_IN,
        .length  = length,
        .moved   = 0,
        .data    = NULL,
    };

    usbipt_trace("cmd  seq %u ep %02x %s %u bytes", seqnum, staged.ep_addr,
                 staged.in ? "in" : "out", length);

    if (length > USBIPT_XFER_MAX) {
        usbipt_error("transfer of %u bytes, which is more than this holds",
                     length);
        return ret_submit(fd, &staged, USBIPT_EOVERFLOW);
    }

    if (length > 0) {
        staged.data = malloc(length);
        if (staged.data == NULL) {
            return ret_submit(fd, &staged, USBIPT_EOVERFLOW);
        }
    }

    // An OUT transfer's payload follows its header.  It has to come off the
    // socket whatever happens to the transfer, or the next header is read from
    // the middle of it.
    if (!staged.in && length > 0) {
        if (!read_all(fd, staged.data, length)) {
            free(staged.data);
            return false;
        }
    }

    if (ep == 0) {
        int status = ctrl_xfer(&staged, hdr + USBIPT_OFF_SETUP);
        bool ok = ret_submit(fd, &staged, status);
        free(staged.data);
        return ok;
    }

    usbipt_urb_t *urb = urb_slot();
    if (urb == NULL) {
        // Every slot is held by a transfer the device has not answered.  A
        // device with that many outstanding is not one the host can make
        // progress against, so say so rather than dropping the request.
        usbipt_error("%u transfers outstanding, which is all of them",
                     USBIPT_URB_MAX);
        bool ok = ret_submit(fd, &staged, USBIPT_EOVERFLOW);
        free(staged.data);
        return ok;
    }

    *urb = staged;

    bool done   = false;
    int  status = bulk_progress(urb, &done);
    if (!done) {
        return true;  // held until the device answers, or until it is unlinked
    }

    bool ok = ret_submit(fd, urb, status);
    urb_release(urb);
    return ok;
}

static bool cmd_unlink(int fd, const uint8_t *hdr) {
    const uint32_t seqnum = get32(hdr + USBIPT_OFF_SEQNUM);
    const uint32_t target = get32(hdr + USBIPT_OFF_UNLINK);

    usbipt_trace("cmd  unlink seq %u, of seq %u", seqnum, target);

    for (unsigned i = 0; i < USBIPT_URB_MAX; i++) {
        if (s_urb[i].busy && s_urb[i].seqnum == target) {
            urb_release(&s_urb[i]);
            // The transfer was still waiting, so it is being taken off the
            // device rather than having finished.  No completion follows it.
            return ret_unlink(fd, seqnum, USBIPT_ECONNRESET);
        }
    }

    // It finished before the host gave up on it, and its completion is already
    // on its way.  Nothing was cancelled, and zero says so.
    return ret_unlink(fd, seqnum, 0);
}

// ---------------------------------------------------------------------------
// The loop's entry point
// ---------------------------------------------------------------------------

static bool urb_waiting(void) {
    for (unsigned i = 0; i < USBIPT_URB_MAX; i++) {
        if (s_urb[i].busy) {
            return true;
        }
    }
    return false;
}

// Try every held transfer against a device that has just been turned.
static bool urb_retry(int fd) {
    for (unsigned i = 0; i < USBIPT_URB_MAX; i++) {
        if (!s_urb[i].busy) {
            continue;
        }

        bool done   = false;
        int  status = bulk_progress(&s_urb[i], &done);
        if (!done) {
            continue;
        }

        bool ok = ret_submit(fd, &s_urb[i], status);
        urb_release(&s_urb[i]);
        if (!ok) {
            return false;
        }
    }
    return true;
}

// How long to wait on the socket before turning the device again.  A held
// transfer is only ever finished by the device, so waiting on the socket alone
// would wait for something that is not coming.  With nothing held there is
// nothing to turn for, and the wait is long enough to leave the machine alone.
#define USBIPT_WAIT_BUSY_MS 1
#define USBIPT_WAIT_IDLE_MS 20

bool usbipt_urb_poll(int sockfd) {
    usbipt_device_pump();

    if (!urb_retry(sockfd)) {
        return false;
    }

    struct pollfd pfd = { .fd = sockfd, .events = POLLIN, .revents = 0 };
    int n = poll(&pfd, 1, urb_waiting() ? USBIPT_WAIT_BUSY_MS
                                        : USBIPT_WAIT_IDLE_MS);
    if (n < 0) {
        if (errno == EINTR) {
            return true;  // a signal, which the loop reads for itself
        }
        usbipt_error("waiting on the bus: %s", strerror(errno));
        return false;
    }
    if (n == 0) {
        return true;  // nothing arrived, so turn the device again
    }

    uint8_t hdr[USBIPT_HDR_LEN];
    if (!read_all(sockfd, hdr, sizeof(hdr))) {
        return false;
    }

    switch (get32(hdr + USBIPT_OFF_COMMAND)) {
        case USBIPT_CMD_SUBMIT:
            return cmd_submit(sockfd, hdr);
        case USBIPT_CMD_UNLINK:
            return cmd_unlink(sockfd, hdr);
        default:
            usbipt_error("the kernel sent command %u, which is not one this "
                         "answers",
                         get32(hdr + USBIPT_OFF_COMMAND));
            return false;
    }
}
