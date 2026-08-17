// Copyright (C) 2026 Piers Finlayson <piers@piers.rocks>
//
// MIT License

// The kernel side of the bus.
//
// vhci-hcd is a USB host controller whose downstream is a socket rather than a
// wire.  It is told about a device by writing a port number, a file descriptor,
// a device id and a speed to one sysfs file, and told to forget it by writing
// the port number to another.
//
// The descriptor is looked up in the calling process's own table, so the process
// that writes has to be the process that holds the socket.  That is why this
// program attaches itself rather than leaving it to usbip(8): the alternative is
// a second program holding the socket, and the linux-tools package that carries
// it is built per kernel version.  The kernel takes its own reference to the
// socket as it accepts it, so the copy written here can be closed straight
// after.

#include <errno.h>
#include <stdio.h>
#include <string.h>

#include "usbipt.h"

#define USBIPT_VHCI_DIR "/sys/devices/platform/vhci_hcd.0"

// enum usb_device_speed, which is what the controller is asking for.  The
// device's descriptors declare a full speed device and tinyusb is brought up as
// one, so this has to agree with them.
#define USBIPT_SPEED_FULL 2u

// The device id a real usbip server would take from the device it is exporting.
// Nothing here has a bus to be on, and the kernel only echoes it back in the
// URBs it sends, so any non-zero value does.
#define USBIPT_DEVID 0x00010001u

// enum usbip_device_status.  A port with no device on it reads as this, and is
// the only kind worth claiming.
#define USBIPT_ST_NULL 4

// A free port on the controller's full and high speed hub, or -1.  Ports are
// shared with anything else on the machine using usbip, so the first free one is
// taken rather than assuming port zero.
static int vhci_free_port(void) {
    FILE *f = fopen(USBIPT_VHCI_DIR "/status", "re");
    if (f == NULL) {
        usbipt_error("no %s: is vhci-hcd loaded?  modprobe vhci-hcd",
                     USBIPT_VHCI_DIR);
        return -1;
    }

    // hub port sta spd dev      sockfd local_busid
    // hs  0000 004 000 00000000 000000 0-0
    char line[256];
    int  port = -1;
    while (port < 0 && fgets(line, sizeof(line), f) != NULL) {
        char hub[8];
        int  n, sta;
        if (sscanf(line, "%7s %d %d", hub, &n, &sta) != 3) {
            continue;  // the heading, or a line this kernel writes differently
        }
        // A full speed device belongs on the full and high speed hub.  The
        // superspeed ports are in the same table and would refuse it.
        if (strcmp(hub, "hs") == 0 && sta == USBIPT_ST_NULL) {
            port = n;
        }
    }

    fclose(f);

    if (port < 0) {
        usbipt_error("every vhci-hcd port is in use");
    }
    return port;
}

int usbipt_vhci_attach(int sockfd) {
    int port = vhci_free_port();
    if (port < 0) {
        return -1;
    }

    FILE *f = fopen(USBIPT_VHCI_DIR "/attach", "we");
    if (f == NULL) {
        usbipt_error("cannot open %s/attach: %s.  This needs root.",
                     USBIPT_VHCI_DIR, strerror(errno));
        return -1;
    }

    // The controller parses one line of four numbers, and rejects the write
    // rather than the line if it does not like them.
    if (fprintf(f, "%d %d %u %u", port, sockfd, USBIPT_DEVID,
                USBIPT_SPEED_FULL) < 0 ||
        fclose(f) != 0) {
        usbipt_error("vhci-hcd refused port %d: %s", port, strerror(errno));
        return -1;
    }

    usbipt_trace("attached to vhci-hcd port %d", port);
    return port;
}

void usbipt_vhci_detach(int port) {
    if (port < 0) {
        return;
    }

    FILE *f = fopen(USBIPT_VHCI_DIR "/detach", "we");
    if (f == NULL) {
        usbipt_error("cannot open %s/detach: %s", USBIPT_VHCI_DIR,
                     strerror(errno));
        return;
    }

    if (fprintf(f, "%d", port) < 0 || fclose(f) != 0) {
        usbipt_error("vhci-hcd would not give up port %d: %s", port,
                     strerror(errno));
        return;
    }

    usbipt_trace("detached from vhci-hcd port %d", port);
}
