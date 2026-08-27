#!/usr/bin/env bash
# The picotool and picoboot-rs bridges, from macOS.
#
# Usage: ci/bridges-docker.sh [picotool|picoboot-rs] [--trace] [--rebuild]
#
#   (no gate named) both, as CI runs both
#   --trace         the bridge traces every transfer
#   --rebuild       build the image from scratch, ignoring layer cache
#
# These are CI's last two jobs.  They put picobootx on a real USB bus through
# the kernel's virtual host controller and drive it with real picotool and with
# picoboot-rs, so they want a Linux kernel with vhci-hcd, and root to hand that
# controller a socket.  macOS has neither.
#
# What it does have is a Linux kernel already.  A docker daemon on a Mac runs
# inside a Linux virtual machine, and a container shares that machine's kernel.
# So the requirement is not a Linux machine, it is a Linux kernel carrying the
# usbip modules and a container privileged enough to load one and write to
# sysfs.  The controller, the bus and the device nodes that appear on it are
# then that kernel's - shared, not emulated a second time.  Nothing here is a
# stand-in for the gate: the same `make test-usbip` and `make test-rust` run,
# driven by picotool built from the same release tag CI pins, against the same
# kernel driver.
#
# Three mounts carry that:
#
#   /lib/modules  the host kernel's modules, so modprobe has vhci-hcd to load.
#                 It is the virtual machine's own /lib/modules and not this
#                 Mac's - the docker daemon runs in there.
#   /dev/bus/usb  the device nodes libusb and nusb open.  --privileged alone is
#                 not enough: it copies the host's device nodes in as the
#                 container is created, and the device this puts on the bus is
#                 not there yet - so picotool saw it in sysfs and could not
#                 open it.  A bind mount is the live directory, and the node
#                 appears in it when the kernel creates it.
#   /src          this tree, read only.  ci/bridges-run.sh copies it before it
#                 builds anything, so a run cannot write to the working tree.
#
# The colima virtual machine shares the user's home directory, so a tree under
# it mounts.  A tree elsewhere reaches the container empty, and the run says so
# rather than building nothing.
set -e

cd "$(dirname "$0")/.."

IMAGE=picobootx-bridges:latest
# Named, so the crates picoboot-rs pulls in survive between runs.  The tree is
# copied into the container each time and its target directories are not, so
# without this every run downloads the index again.
CARGO_VOLUME=picobootx-bridges-cargo

build_args=()
run_args=()
for arg in "$@"; do
    case $arg in
    --rebuild) build_args+=(--no-cache) ;;
    *) run_args+=("$arg") ;;
    esac
done

command -v docker >/dev/null || {
    echo "docker is not on PATH, and this needs it" >&2
    exit 2
}

echo "=== the image ==="
# The dockerfile on stdin, which is docker's way of saying the build context is
# empty.  It copies nothing out of the tree, and handing it ci/ would ship
# ci/ramfunc-probe's target directory to the daemon before the build starts.
docker build "${build_args[@]}" -t "$IMAGE" - <ci/bridges.dockerfile

docker run --rm --privileged \
    -v "$PWD:/src:ro" \
    -v /lib/modules:/lib/modules:ro \
    -v /dev/bus/usb:/dev/bus/usb \
    -v "$CARGO_VOLUME:/cargo" \
    -e CARGO_HOME=/cargo \
    "$IMAGE" /src/ci/bridges-run.sh "${run_args[@]}"
