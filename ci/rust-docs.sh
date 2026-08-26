#!/usr/bin/env bash
# Do the Rust crates' documents build, and do their links resolve?
#
# Usage: ci/rust-docs.sh
#
# `missing_docs = "deny"` catches a public item with no documentation, and
# nothing catches documentation that no longer builds.  An intra-doc link to an
# item that has been renamed, or a `#[doc = include_str!]` README whose example
# stopped compiling, both land without a word - rustdoc reports them as
# warnings, and warnings are not read.  RUSTDOCFLAGS makes them errors.
#
# --no-deps, so what is checked is this repository's documentation rather than
# every dependency's as well.
set -e

cd "$(dirname "$0")/.."

export RUSTDOCFLAGS="-D warnings"

echo "Documenting the library and the crates around it"
(cd rust && cargo doc --workspace --no-deps)

# Again for the part, because picobootx-embassy's Rp2350EndpointControl and the
# whole of picobootx-rp2350's usb module are compiled only there.  Documenting on this
# machine alone leaves both unread, and docs.rs renders the part's build - so a
# broken link in either would be found by the world rather than here.
echo "Documenting the parts that exist only in a build for the part"
(cd rust && cargo doc -p picobootx-embassy -p picobootx-rp2350 --features picobootx-embassy/rp2350 \
    --target thumbv8m.main-none-eabi --no-deps)

# The workspaces of their own.  Each is named or nothing documents it.
echo "Documenting the interop driver"
(cd rust/interop && cargo doc --no-deps)

echo "Documenting the hardware test"
(cd test/hw/device && cargo doc --no-deps)
(cd test/hw/host && cargo doc --no-deps)

echo "Documenting the examples and the probe"
(cd examples/embassy && cargo doc --no-deps)
(cd ci/ramfunc-probe && cargo doc --no-deps)
