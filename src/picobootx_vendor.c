// Copyright (C) 2026 Piers Finlayson <piers@piers.rocks>
//
// MIT License

// picobootx's tinyusb vendor device implementation.
//
// This handles all USB interactions for the picoboot interface.
//
// It is based on the tinyusb vendor device implementation, with some
// significant modifications:
// - Only a single vendor interface is supported for simplicity.
// - Handles the protocol controlling stalling and unstalling of its
//   endpoints.
// - Provides n API for sending true zero length ZLPs.

/*
 * tinyusb License and Copyright Notice
 *
 * The MIT License (MIT)
 *
 * Copyright (c) 2019 Ha Thach (tinyusb.org)
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 *
 * This file is part of the TinyUSB stack.
 */

#include "tusb_option.h"

// Some compile time checking
#if !defined(CFG_TUD_ENABLED) || !defined(CFG_TUD_VENDOR)
#error "picoboot requires CFG_TUD_ENABLED and CFG_TUD_VENDOR to be both set to 1"
#endif
#if CFG_TUD_VENDOR > 1
#error "picoboot supports only a single vendor instance"
#endif

#include "device/usbd.h"
#include "device/usbd_pvt.h"
#include "picobootx_vendor.h"
#include "usb_plugin.h"

// The vendor device's interface configuration.
typedef struct {
  uint8_t rhport;
  uint8_t itf_num;

  // From this point, data is not cleared by bus reset
  tu_edpt_stream_t tx_stream;
  tu_edpt_stream_t rx_stream;
  uint8_t          tx_ff_buf[CFG_TUD_PICOBOOT_TX_BUFSIZE];
  uint8_t          rx_ff_buf[CFG_TUD_PICOBOOT_RX_BUFSIZE];
} picoboot_interface_t;

// Some magic so TUD can reset bits of our interface structure
#define ITF_MEM_RESET_SIZE (offsetof(picoboot_interface_t, itf_num) + TU_FIELD_SIZE(picoboot_interface_t, itf_num))

// Global picoboot vendor interface instances.
static picoboot_interface_t p_itf;

// Callbacks to be provided by the application that wraps picoboot.  It must
// look up the picoboot state and call picoboot_rx_cb and picoboot_tx_cb with
// the appropriate state pointer.
//
// If you get a linker error about these symbols, you need to provide an
// implementation in your application code.  It can be as simple as just
// calling picoboot_vendor_rx_cb() and picoboot_vendor_tx_cb() directly, with
// the same state that you passed to picoboot_init().
extern void app_picoboot_rx_cb(uint32_t available_bytes);
extern void app_picoboot_tx_cb(uint32_t sent_bytes);

//
// Read API
//
uint32_t picoboot_vendor_available(void) {
    return tu_edpt_stream_read_available(&p_itf.rx_stream);
}

bool picoboot_vendor_peek(uint8_t *u8) {
    return tu_edpt_stream_peek(&p_itf.rx_stream, u8);
}

uint32_t picoboot_vendor_read(void *buffer, uint32_t bufsize) {
    return tu_edpt_stream_read(&p_itf.rx_stream, buffer, bufsize);
}

void picoboot_vendor_read_clear(void) {
    tu_edpt_stream_clear(&p_itf.rx_stream);
    tu_edpt_stream_read_xfer(&p_itf.rx_stream);
}

bool picoboot_vendor_read_xfer(void) {
    return tu_edpt_stream_read_xfer(&p_itf.rx_stream);
}

//
// Write API
//
uint32_t picoboot_vendor_write(const void *buffer, uint32_t bufsize) {
    return tu_edpt_stream_write(&p_itf.tx_stream, buffer, (uint16_t)bufsize);
}

uint32_t picoboot_vendor_write_available(void) {
  return tu_edpt_stream_write_available(&p_itf.tx_stream);
}

uint32_t picoboot_vendor_write_flush(void) {
  return tu_edpt_stream_write_xfer(&p_itf.tx_stream);
}

bool picoboot_vendor_write_clear(void) {
  tu_edpt_stream_clear(&p_itf.tx_stream);
  return true;
}

// Management API
void picoboot_vendor_stall_endpoint(uint8_t ep_addr) {
    if (usbd_edpt_stalled(p_itf.rhport, ep_addr)) {
        // Already stalled
        return;
    }

    // This is a bit weird.  I have tried a LOT of ways to successfully stall
    // and then later unstall the endpoints.  This is the specific sequence
    // which works:
    // - clear_stall sets busy to 0
    // - release sets claimed to 0
    // - stall sets busy to 1
    //
    // The calls HAVE to be done in this order as claimed can only be cleared
    // when busy is 0.  If claimed is left true, the subsequent unstall and
    // re-arm does NOT re-arm the hardware but leaves the ctrl_buf zeroed out.
    //
    // Two other things I tried, both of which required changes to tinyusb
    // itself.
    //
    // 1.
    // 
    // To usbd_edpt_stall() add, at the end:
    // _usbd_dev.ep_status[epnum][dir].claimed = 0;
    //
    // 2.
    //
    // In dcd_rp2040.c, dcd_ept_stall(), change:
    // hwbuf_ctrl_set(...)
    // to
    // hwbut_ctrl_set_mask(...)
    //
    // This leaves the buffer as it was previously set, but only sets the
    // stall flag instead of clearing it and settig stall which is what the
    // original code does.
    usbd_edpt_clear_stall(p_itf.rhport, ep_addr);
    usbd_edpt_release(p_itf.rhport, ep_addr);
    usbd_edpt_stall(p_itf.rhport, ep_addr);
}

void picoboot_vendor_unstall_endpoint(uint8_t ep_addr) {
    if (usbd_edpt_stalled(p_itf.rhport, ep_addr)) {
        // Only clear stall if it's currently stalled
        usbd_edpt_clear_stall(p_itf.rhport, ep_addr);
    }
}

//
// USBD Driver API, used by usbd.c
//
void vendord_init(void) {
    tu_memclr(&p_itf, sizeof(p_itf));

    tu_edpt_stream_init(
        &p_itf.rx_stream,
        false,
        false,
        false,
        p_itf.rx_ff_buf,
        CFG_TUD_PICOBOOT_RX_BUFSIZE,
        NULL,
        CFG_TUD_PICOBOOT_EPSIZE
    );

    tu_edpt_stream_init(
        &p_itf.tx_stream,
        false,
        true,
        false,
        p_itf.tx_ff_buf,
        CFG_TUD_PICOBOOT_TX_BUFSIZE,
        NULL,
        CFG_TUD_PICOBOOT_EPSIZE
    );
}

bool vendord_deinit(void) {
    tu_edpt_stream_deinit(&p_itf.rx_stream);
    tu_edpt_stream_deinit(&p_itf.tx_stream);
    return true;
}

void vendord_reset(uint8_t rhport) {
    (void)rhport;

    tu_memclr(&p_itf, ITF_MEM_RESET_SIZE);

    tu_edpt_stream_clear(&p_itf.rx_stream);
    tu_edpt_stream_close(&p_itf.rx_stream);
    tu_edpt_stream_clear(&p_itf.tx_stream);
    tu_edpt_stream_close(&p_itf.tx_stream);
}

uint16_t vendord_open(
    uint8_t rhport,
    const tusb_desc_interface_t *desc_itf,
    uint16_t max_len
) {
    TU_VERIFY(TUSB_CLASS_VENDOR_SPECIFIC == desc_itf->bInterfaceClass, 0);
    const uint8_t* desc_end = (const uint8_t*)desc_itf + max_len;
    const uint8_t* p_desc = tu_desc_next(desc_itf);

    p_itf.rhport  = rhport;
    p_itf.itf_num = desc_itf->bInterfaceNumber;

    while (tu_desc_in_bounds(p_desc, desc_end)) {
        const uint8_t desc_type = tu_desc_type(p_desc);
        if (desc_type == TUSB_DESC_INTERFACE || desc_type == TUSB_DESC_INTERFACE_ASSOCIATION) {
            break; // end of this interface
        } else if (desc_type == TUSB_DESC_ENDPOINT) {
            const tusb_desc_endpoint_t* desc_ep = (const tusb_desc_endpoint_t*) p_desc;
            TU_ASSERT(usbd_edpt_open(rhport, desc_ep));

            // open endpoint stream
            if (tu_edpt_dir(desc_ep->bEndpointAddress) == TUSB_DIR_IN) {
                tu_edpt_stream_t *tx_stream = &p_itf.tx_stream;
                tu_edpt_stream_open(tx_stream, rhport, desc_ep);
                tu_edpt_stream_write_xfer(tx_stream); // flush pending data
            } else {
                tu_edpt_stream_t *rx_stream = &p_itf.rx_stream;
                tu_edpt_stream_open(rx_stream, rhport, desc_ep);
                TU_ASSERT(tu_edpt_stream_read_xfer(rx_stream) > 0, 0); // prepare for incoming data
            }
        }

        p_desc = tu_desc_next(p_desc);
    }

    return (uint16_t)((uintptr_t)p_desc - (uintptr_t)desc_itf);
}

bool vendord_xfer_cb(uint8_t rhport, uint8_t ep_addr, xfer_result_t result, uint32_t xferred_bytes) {
    (void)rhport;
    (void)result;

    if (ep_addr == p_itf.rx_stream.ep_addr) {
        // Put received data to FIFO
        tu_edpt_stream_read_xfer_complete(&p_itf.rx_stream, xferred_bytes);

        // Let the picoboot protocol handler know - this has to go via the
        // application, so it can provide picoboot its state
        app_picoboot_rx_cb(picoboot_vendor_available());

        // Prepare for the next data
        tu_edpt_stream_read_xfer(&p_itf.rx_stream);
    } else if (ep_addr == p_itf.tx_stream.ep_addr) {
        // Let the picoboot protocol handler know - this has to go via the
        // application, so it can provide picoboot its state
        app_picoboot_tx_cb((uint16_t)xferred_bytes);

        // Try to send more if possible
        tu_edpt_stream_write_xfer(&p_itf.tx_stream);

        // Standard vendor drive sends a ZLP if the last packet is exactly the
        // endpoint size, but for picoboot we want to suppress it ZLPs have a
        // special meaning in the protocol.
    }

    return true;
}

bool picoboot_vendor_send_zlp(void) {
    // This is exactly how tusb.c sends a ZLP packet in
    // tu_edpt_stream_write_zlp_if_needed()
    tu_edpt_stream_t *tx = &p_itf.tx_stream;
    TU_VERIFY(usbd_edpt_claim(p_itf.rhport, tx->ep_addr), false);
    if (!usbd_edpt_xfer_fifo(p_itf.rhport, tx->ep_addr, &tx->ff, 0, false)) {
        usbd_edpt_release(p_itf.rhport, tx->ep_addr);
        return false;
    }
    return true;
}
