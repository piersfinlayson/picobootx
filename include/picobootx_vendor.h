// Copyright (C) 2026 Piers Finlayson <piers@piers.rocks>
//
// MIT License

// Based on TinyUSB's vendor_device.c, with modifications to handle the
// picoboot protocol, spefically around ZLP handling:
//
// - The stock vendor device sends a ZLP automatically after a transfer
//   completes if the transfer size is a multiple of the endpoint size.  This
//   is contrary to the picoboot protocol.
//
// - The stock vendor device does not allow a ZLP to be sent on demand, which
//   is required by the picoboot protocol.

/*
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
 */

#ifndef PICOBOOTX_VENDOR_H
#define PICOBOOTX_VENDOR_H

#ifdef __cplusplus
extern "C" {
#endif

#include "common/tusb_common.h"

//--------------------------------------------------------------------+
// Configuration
//--------------------------------------------------------------------+
#define CFG_TUD_PICOBOOT_EPSIZE 64
#define CFG_TUD_PICOBOOT_RX_BUFSIZE 64
#define CFG_TUD_PICOBOOT_TX_BUFSIZE 64

//--------------------------------------------------------------------+
// Application API (Multiple Interfaces) i.e CFG_TUD_PICOBOOT > 1
//--------------------------------------------------------------------+

//------------- RX -------------//
// Return number of available bytes for reading
uint32_t picoboot_vendor_available(void);

// Peek a byte from RX buffer
bool picoboot_vendor_peek(uint8_t *ui8);

// Read from RX FIFO
uint32_t picoboot_vendor_read(void *buffer, uint32_t bufsize);

// Flush (clear) RX FIFO
void picoboot_vendor_read_clear(void);

// Start a new RX transfer to fill the RX FIFO, return false if previous
// transfer is still ongoing
bool picoboot_vendor_read_xfer(void);

//------------- TX -------------//
// Write to TX FIFO. This will be buffered and not sent immediately unless
// buffered bytes >= USB endpoint size
uint32_t picoboot_vendor_write(const void *buffer, uint32_t bufsize);

// Return number of bytes available for writing in TX FIFO
uint32_t picoboot_vendor_write_available(void);

// Force sending buffered data, return number of bytes sent
uint32_t picoboot_vendor_write_flush(void);

// Clear the transmit FIFO
bool picoboot_vendor_write_clear(void);

// Write a null-terminated string to TX FIFO
TU_ATTR_ALWAYS_INLINE static inline uint32_t picoboot_vendor_write_str(const char *str) {
  return picoboot_vendor_write(str, strlen(str));
}

// Send a ZLP packet.
bool picoboot_vendor_send_zlp(void);

//
// Management API
//

// Stall an endpoint
void picoboot_vendor_stall_endpoint(uint8_t ep_addr);

// Unstall an endpoint
void picoboot_vendor_unstall_endpoint(uint8_t ep_addr);

//--------------------------------------------------------------------+
// Internal Class Driver API, used by usbd.c
//--------------------------------------------------------------------+
void     vendord_init(void);
bool     vendord_deinit(void);
void     vendord_reset(uint8_t rhport);
uint16_t vendord_open(uint8_t rhport, const tusb_desc_interface_t *idx_desc, uint16_t max_len);
bool     vendord_xfer_cb(uint8_t rhport, uint8_t ep_addr, xfer_result_t event, uint32_t xferred_bytes);

#ifdef __cplusplus
}
#endif

#endif /* PICOBOOTX_VENDOR_H */
