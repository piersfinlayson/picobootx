// Copyright (C) 2026 Piers Finlayson <piers@piers.rocks>
//
// MIT License

// The program: put the device on the bus, and serve it until told to stop.
//
// The socket is a loopback connection this process makes to itself.  One end
// goes to the kernel, which drives it as a USB bus, and the other stays here and
// is answered from.  Nothing else on the machine can reach it — the listening
// socket is bound to the loopback address, and it is closed as soon as the one
// connection has been accepted.

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "pbt.h"
#include "usbipt.h"

bool usbipt_verbose;

void usbipt_trace(const char *fmt, ...) {
    if (!usbipt_verbose) {
        return;
    }
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
}

void usbipt_error(const char *fmt, ...) {
    fputs("picobootx-usbip: ", stderr);
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
}

// Set by a signal, read by the loop.  Nothing else is safe to do from a handler,
// and nothing else is needed: the loop comes back from the socket promptly
// whether or not anything arrived.
static volatile sig_atomic_t s_stop;

static void on_signal(int sig) {
    (void)sig;
    s_stop = 1;
}

// Connect this process to itself, and answer the resulting connection.  Both
// ends are returned: the first is the kernel's, the second is this program's.
static bool loopback_pair(int *kernel_end, int *our_end) {
    int listener = socket(AF_INET, SOCK_STREAM, 0);
    if (listener < 0) {
        usbipt_error("socket: %s", strerror(errno));
        return false;
    }

    // Port zero, so the kernel picks one that is free.  The address it settles
    // on is read back, because that is what the other end has to connect to.
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port        = 0;

    socklen_t addr_len = sizeof(addr);
    if (bind(listener, (struct sockaddr *)&addr, sizeof(addr)) != 0 ||
        listen(listener, 1) != 0 ||
        getsockname(listener, (struct sockaddr *)&addr, &addr_len) != 0) {
        usbipt_error("listening on the loopback address: %s", strerror(errno));
        close(listener);
        return false;
    }

    int client = socket(AF_INET, SOCK_STREAM, 0);
    if (client < 0 ||
        connect(client, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        usbipt_error("connect: %s", strerror(errno));
        close(listener);
        if (client >= 0) {
            close(client);
        }
        return false;
    }

    int served = accept(listener, NULL, NULL);
    close(listener);  // one connection is all there is to accept
    if (served < 0) {
        usbipt_error("accept: %s", strerror(errno));
        close(client);
        return false;
    }

    *kernel_end = client;
    *our_end    = served;
    return true;
}

static void usage(void) {
    fprintf(stderr,
            "usage: picobootx-usbip [-v]\n"
            "\n"
            "Puts a picobootx device on this machine's USB bus, through\n"
            "vhci-hcd, and serves it until interrupted.  Needs root.\n"
            "\n"
            "  -v   trace every transfer\n");
}

int main(int argc, char **argv) {
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-v") == 0) {
            usbipt_verbose = true;
        } else {
            usage();
            return 2;
        }
    }

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_signal;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    usbipt_device_start();

    int kernel_end = -1;
    int our_end    = -1;
    if (!loopback_pair(&kernel_end, &our_end)) {
        return 1;
    }

    int port = usbipt_vhci_attach(kernel_end);
    if (port < 0) {
        close(kernel_end);
        close(our_end);
        return 1;
    }

    // The kernel took its own reference as it accepted the descriptor, so this
    // copy has done its work.  Closing it is also what lets a detach reach this
    // program: while it is open, the connection stays up whatever the kernel
    // does with its end, and the loop would wait on a bus nothing is driving.
    close(kernel_end);

    // The line a script waits for before it runs anything against the device.
    printf("picobootx on vhci-hcd port %d\n", port);
    fflush(stdout);

    while (!s_stop) {
        // The sequence log is how a scenario asserts what the device did, and it
        // stops the process when it fills.  Nothing here asserts on it, and one
        // picotool session records far more than it holds.
        pbt_log_reset();

        if (!usbipt_urb_poll(our_end)) {
            break;
        }
    }

    usbipt_vhci_detach(port);
    close(our_end);
    return 0;
}
