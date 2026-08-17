#!/bin/sh
# Copyright (C) 2026 Piers Finlayson <piers@piers.rocks>
#
# MIT License

# Drive picobootx with picoboot-rs, over a real USB bus.
#
# The same bridge picotool.sh uses, with the other host implementation on the end
# of it.  The checks are in the Rust binary, which prints them and decides the
# exit status — this puts the device on the bus and takes it off again.
#
#   sudo rust/interop.sh              from anywhere in the tree
#   sudo rust/interop.sh -v           with the bridge tracing transfers
#
# Needs root, for the same two reasons the bridge does.  Build it first with
# `make test-rust`, which builds as you and hands only this to sudo.

set -u

here=$(cd "$(dirname "$0")" && pwd)
test_dir=$(cd "$here/../test" && pwd)

interop=$here/target/release/picobootx-interop

. "$test_dir/usbip/bridge.sh"

[ -x "$interop" ] ||
    bridge_die "$interop has not been built: make test-rust"

bridge_start "$@"

"$interop"
