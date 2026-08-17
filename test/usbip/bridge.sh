# Copyright (C) 2026 Piers Finlayson <piers@piers.rocks>
#
# MIT License

# Putting picobootx on this machine's USB bus, and taking it off again.
#
# Sourced, not run.  The caller sets test_dir to picobootx's test directory
# first, and afterwards has a device on the bus, $work to keep files in, and a
# teardown that runs whichever way it exits.
#
#   test_dir=...
#   . "$test_dir/usbip/bridge.sh"
#   bridge_start "$@"
#
# There is one of these because there is more than one host tool driving the same
# device, and only one way to put it there.

bridge=$test_dir/build/usbip/picobootx-usbip
work=$(mktemp -d)
bridge_log=$work/bridge.log

bridge_die() {
    echo "bridge: $*" >&2
    exit 2
}

bridge_pid=
bridge_cleanup() {
    if [ -n "$bridge_pid" ]; then
        kill "$bridge_pid" 2>/dev/null
        wait "$bridge_pid" 2>/dev/null
    fi
    rm -rf "$work"
}

# The device this puts on the bus, as its descriptors declare it.  Waiting for
# the kernel to have enumerated it is waiting for this pair to appear.
bridge_vid=2e8a
bridge_pid_usb=000f

# Whether the kernel has finished enumerating what was put on the bus.  Asked of
# sysfs rather than of a host tool, so that a tool failing to see the device is
# something its own checks report rather than something this waits forever for.
bridge_enumerated() {
    for id in /sys/bus/usb/devices/*/idVendor; do
        [ -r "$id" ] || continue
        [ "$(cat "$id")" = "$bridge_vid" ] || continue
        dir=$(dirname "$id")
        [ "$(cat "$dir/idProduct" 2>/dev/null)" = "$bridge_pid_usb" ] && return 0
    done
    return 1
}

# Start the bridge and wait until the device is on the bus.  Any argument is
# passed to the bridge, which is how -v reaches it.
bridge_start() {
    [ "$(uname -s)" = "Linux" ] ||
        bridge_die "Linux only — vhci-hcd is a Linux driver"
    [ "$(id -u)" = "0" ] ||
        bridge_die "needs root, for vhci-hcd and the socket it is given"
    [ -x "$bridge" ] ||
        bridge_die "$bridge has not been built: make -C '$test_dir' usbip-build"

    modprobe vhci-hcd || bridge_die "cannot load vhci-hcd"

    trap bridge_cleanup EXIT INT TERM

    "$bridge" "$@" >"$bridge_log" 2>&1 &
    bridge_pid=$!

    # The bridge says so once the controller has taken the bus.
    waited=0
    while ! grep -q "vhci-hcd port" "$bridge_log" 2>/dev/null; do
        kill -0 "$bridge_pid" 2>/dev/null || {
            cat "$bridge_log" >&2
            bridge_die "the bridge stopped before it reached the bus"
        }
        waited=$((waited + 1))
        [ "$waited" -lt 50 ] || bridge_die "the bridge never reached the bus"
        sleep 0.1
    done

    # Enumeration is the kernel's, and happens after the bus is taken.
    waited=0
    until bridge_enumerated; do
        waited=$((waited + 1))
        [ "$waited" -lt 100 ] || {
            cat "$bridge_log" >&2
            bridge_die "the kernel never enumerated the device"
        }
        sleep 0.1
    done
}
