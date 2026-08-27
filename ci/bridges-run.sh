#!/usr/bin/env bash
# The two bridge gates, from inside the container ci/bridges-docker.sh starts.
#
# Usage: ci/bridges-run.sh [picotool|picoboot-rs] [--trace]
#
# Not run from macOS - it wants the Linux kernel underneath it, root, and the
# tree mounted at /src.  ci/bridges-docker.sh is what arranges all three.
#
# The tree is copied out of the read-only mount before anything builds.  Both
# targets write: the suite's objects land in test/build, and `make test-rust`
# runs `cargo update -p picoboot`, which rewrites rust/interop/Cargo.lock - a
# tracked file.  Copying means a run cannot touch the working tree at all,
# which matters because the machine this runs from is somebody's development
# machine and not a runner with a fresh checkout.
set -u

usage() {
    echo "usage: ci/bridges-run.sh [picotool|picoboot-rs] [--trace]" >&2
    exit 2
}

gates="picotool picoboot-rs"
trace=

for arg in "$@"; do
    case $arg in
    picotool | picoboot-rs) gates=$arg ;;
    --trace) trace=TRACE=1 ;;
    *) usage ;;
    esac
done

die() {
    echo "bridges-run: $*" >&2
    exit 2
}

[ "$(uname -s)" = Linux ] || die "Linux only"
[ "$(id -u)" = 0 ] || die "needs root, for vhci-hcd and the socket it is given"
[ -f /src/Makefile ] || die "the tree is not mounted at /src"

# The same precondition CI's own two jobs check, asked here so a machine whose
# kernel has no vhci-hcd says so before anything is built.  The module files
# come from the mount ci/bridges-docker.sh makes of the host's /lib/modules.
modprobe vhci-hcd || die "cannot load vhci-hcd: is /lib/modules mounted?"
[ -d /sys/devices/platform/vhci_hcd.0 ] ||
    die "vhci-hcd loaded but /sys/devices/platform/vhci_hcd.0 is not there"

# Everything git-ignored or rebuildable is left behind: the cargo target
# directories alone are several gigabytes, and reading them over the file share
# would cost more than rebuilding what is needed.  test/tinyusb is carried, so
# the suite's makefile finds it rather than fetching it again.
echo "=== copying the tree out of the read-only mount ==="
mkdir -p /work
tar -C /src -cf - \
    --exclude=.git \
    --exclude=target \
    --exclude=test/build \
    --exclude=examples/tinyusb/build \
    --exclude=examples/tinyusb/tinyusb-repo \
    --exclude=examples/tinyusb/pico-sdkless-repo \
    --exclude=examples/tinyusb/tools \
    . | tar -C /work -xf -

cd /work

status=0
ran=

run_gate() {
    echo
    echo "=== $1 ==="
    if make "$2" $trace; then
        ran="$ran  $1: passed"$'\n'
    else
        ran="$ran  $1: FAILED"$'\n'
        status=1
    fi
}

# Both, unless one was named.  CI runs them as two jobs, so one failing does
# not stop the other being reported - they are separate host stacks and which
# of them broke is the finding.
case $gates in
*picotool*) run_gate "picotool" test-usbip ;;
esac
case $gates in
*picoboot-rs*) run_gate "picoboot-rs" test-rust ;;
esac

echo
printf '%s' "$ran"
exit $status
