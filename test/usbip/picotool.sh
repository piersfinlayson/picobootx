#!/bin/sh
# Copyright (C) 2026 Piers Finlayson <piers@piers.rocks>
#
# MIT License

# Drive picobootx with real picotool, over a real USB bus.
#
# Starts the bridge, waits for the kernel to enumerate what it put on the bus,
# and then runs picotool against it — the released tool, unmodified, with no
# notion that the device it is talking to is a process on the same machine.
#
# Every check here is one picotool performs or one this script performs on what
# picotool produced.  Nothing reaches inside the bridge, because the point of
# this suite is what a host can do with picobootx and not what the model holds.
#
#   sudo test/usbip/picotool.sh              from anywhere in the tree
#   sudo test/usbip/picotool.sh -v           with the bridge tracing transfers
#
# Needs root, for the same two reasons the bridge does: loading vhci-hcd, and
# handing it a socket.

set -u

here=$(cd "$(dirname "$0")" && pwd)
test_dir=$(dirname "$here")

bridge=$test_dir/build/usbip/picobootx-usbip
work=$(mktemp -d)
log=$work/bridge.log

verbose=
[ "${1:-}" = "-v" ] && verbose=-v

passed=0
failed=0

ok() {
    passed=$((passed + 1))
    echo "  ok    $1"
}

fail() {
    failed=$((failed + 1))
    echo "  FAIL  $1"
}

# Everything below runs with a device on the bus, so the bridge is stopped
# whichever way this exits — including the failures that stop it early.
bridge_pid=
cleanup() {
    if [ -n "$bridge_pid" ]; then
        kill "$bridge_pid" 2>/dev/null
        wait "$bridge_pid" 2>/dev/null
    fi
    rm -rf "$work"
}
trap cleanup EXIT INT TERM

die() {
    echo "picotool.sh: $*" >&2
    exit 2
}

# ---------------------------------------------------------------------------
# What this needs before it can start
# ---------------------------------------------------------------------------

[ "$(uname -s)" = "Linux" ] || die "Linux only — vhci-hcd is a Linux driver"
[ "$(id -u)" = "0" ] || die "needs root, for vhci-hcd and the socket it is given"
command -v picotool >/dev/null || die "picotool is not on PATH"
[ -x "$bridge" ] || die "$bridge has not been built: make usbip-build"

modprobe vhci-hcd || die "cannot load vhci-hcd"

echo "picobootx against picotool: $(picotool version 2>/dev/null | head -1)"

# ---------------------------------------------------------------------------
# The device
# ---------------------------------------------------------------------------

"$bridge" $verbose >"$log" 2>&1 &
bridge_pid=$!

# The bridge says so once the controller has taken the bus.
waited=0
while ! grep -q "vhci-hcd port" "$log" 2>/dev/null; do
    kill -0 "$bridge_pid" 2>/dev/null || {
        cat "$log" >&2
        die "the bridge stopped before it reached the bus"
    }
    waited=$((waited + 1))
    [ "$waited" -lt 50 ] || die "the bridge never reached the bus"
    sleep 0.1
done

# Enumeration is the kernel's, and happens after the bus is taken.  Waiting for
# picotool to see the device is waiting for the whole of it to have worked.
waited=0
until picotool info >/dev/null 2>&1; do
    waited=$((waited + 1))
    [ "$waited" -lt 100 ] || {
        cat "$log" >&2
        die "picotool never saw the device"
    }
    sleep 0.1
done

echo
echo "picotool"

# ---------------------------------------------------------------------------
# What picotool makes of it
# ---------------------------------------------------------------------------

# A device picotool will not identify is one every check below would fail
# against, so it is worth naming on its own.  info reads the bootrom magic out
# of the modelled ROM before it reads anything else.
if picotool info >"$work/info.txt" 2>&1; then
    ok "picotool info reads the device"
else
    cat "$work/info.txt"
    fail "picotool info reads the device"
fi

# ---------------------------------------------------------------------------
# Flash
# ---------------------------------------------------------------------------

flash_base=0x10000000
flash_end=0x10001000
size=4096

# Two unrelated patterns, so the second load can only read back as itself if the
# erase before it really happened.  Programming flash can clear a bit and never
# set one, so a load that skipped its erase leaves the two ANDed together — and
# for that to equal the second pattern, every bit set in it would have to be set
# in the first as well.
head -c $size /dev/urandom >"$work/first.bin"
head -c $size /dev/urandom >"$work/second.bin"

load_and_save() {
    picotool load -v "$1" -t bin -o $flash_base >"$work/load.txt" 2>&1 &&
        picotool save -r $flash_base $flash_end "$2" -t bin \
            >"$work/save.txt" 2>&1
}

if load_and_save "$work/first.bin" "$work/back1.bin" &&
    cmp -s "$work/first.bin" "$work/back1.bin"; then
    ok "picotool loads a program and reads back what it wrote"
else
    cat "$work/load.txt" "$work/save.txt" 2>/dev/null
    fail "picotool loads a program and reads back what it wrote"
fi

if load_and_save "$work/second.bin" "$work/back2.bin" &&
    cmp -s "$work/second.bin" "$work/back2.bin"; then
    ok "a second load replaces the first rather than being merged into it"
else
    cat "$work/load.txt" "$work/save.txt" 2>/dev/null
    fail "a second load replaces the first rather than being merged into it"
fi

# Erased flash is all ones.  This is the same range the loads have just been
# using, so it also says the erase reached what was there rather than only the
# part a load happened to program.
if picotool erase -r $flash_base $flash_end >"$work/erase.txt" 2>&1 &&
    picotool save -r $flash_base $flash_end "$work/erased.bin" -t bin \
        >"$work/save.txt" 2>&1 &&
    [ "$(tr -d '\377' <"$work/erased.bin" | wc -c)" -eq 0 ]; then
    ok "picotool erases flash, and erased flash reads as ones"
else
    cat "$work/erase.txt" "$work/save.txt" 2>/dev/null
    fail "picotool erases flash, and erased flash reads as ones"
fi

# ---------------------------------------------------------------------------
# OTP
# ---------------------------------------------------------------------------

# A row well past the ones the part gives meaning to, so what is read back is
# what was written and not something the model holds for another reason.
otp_row=0xc0

if picotool otp set -r $otp_row 0x1234 >"$work/otp.txt" 2>&1 &&
    picotool otp get -r $otp_row >>"$work/otp.txt" 2>&1 &&
    grep -q "0x001234" "$work/otp.txt"; then
    ok "picotool blows an OTP row and reads the value back"
else
    cat "$work/otp.txt"
    fail "picotool blows an OTP row and reads the value back"
fi

# A fuse goes one way only, and picotool reads a row before it writes it so it
# can refuse a write that would ask a bit to go back.  The value it names in that
# refusal came off this device, so a row that had read as zero would have let the
# write through — which is what makes this a statement about picobootx and not
# only about picotool.
if picotool otp set -r $otp_row 0x4100 >"$work/otp2.txt" 2>&1; then
    cat "$work/otp2.txt"
    fail "a write that would clear an OTP bit is refused"
elif grep -q "current value 001234" "$work/otp2.txt"; then
    ok "a write that would clear an OTP bit is refused"
else
    cat "$work/otp2.txt"
    fail "a write that would clear an OTP bit is refused"
fi

# The same row, with the one thing that made the write above impossible put
# back: every bit it already holds is still set.  So the refusal was about the
# value and not about the row having been written once already.
if picotool otp set -r $otp_row 0x1274 >"$work/otp3.txt" 2>&1 &&
    picotool otp get -r $otp_row >>"$work/otp3.txt" 2>&1 &&
    grep -q "0x001274" "$work/otp3.txt"; then
    ok "a write that only sets further bits goes through"
else
    cat "$work/otp3.txt"
    fail "a write that only sets further bits goes through"
fi

# ---------------------------------------------------------------------------

echo
echo "$((passed + failed)) checks, $failed failed"
[ "$failed" -eq 0 ]
