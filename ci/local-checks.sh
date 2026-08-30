#!/usr/bin/env bash
# Every gate CI applies, in CI's order.
#
# Usage: ci/local-checks.sh
#
# The point is that there is one list and it is executable.  A checklist
# assembled by hand before each push drifts from what .github/workflows/build.yml
# actually gates on, and what drifts out is whatever was last inconvenient - the
# coverage gate, say, which catches a renamed file or a new source nothing
# reaches and needs no CI to do it.
#
# Stops at the first failure, so what you see last is what to fix.
#
# Every one of CI's jobs is here.  The picotool and picoboot-rs bridges want a
# Linux kernel with vhci-hcd and root, which this machine has not got directly
# — but Docker runs one, and ci/bridges-docker.sh gates them through it.  Like
# the minimum-Rust check below, they are skipped rather than failed when what
# they need is absent, and said out loud either way.
set -e

cd "$(dirname "$0")/.."

step() {
    echo
    echo "=== $* ==="
}

# --- device -----------------------------------------------------------------
# The builds that produce a binary for the part.  Where a section lands is a
# property of a link, so nothing that builds for this machine can see it.

step "The tinyusb example, for the part"
make example

step "The embassy example, for the part"
make example-embassy

step "The hardware test, for the part"
make hw-device hw-host

# Four links, and each is asked the question its own toolchain answers.  The
# bare calls are the probe and the tinyusb example, and the two with arguments
# are the hardware test's firmwares - a consumer's link either side, which is a
# different question from the crate's own.
step "Where .ramfunc landed"
ci/check-ramfunc.sh
ci/check-ramfunc.sh test/hw/device-embassy picobootx-hw-device-embassy
ci/check-ramfunc-c.sh
ci/check-ramfunc-c.sh \
    test/hw/device-tinyusb/build/picobootx-hw-device-tinyusb.elf \
    test/hw/device-tinyusb/pico-sdkless-repo/examples/common/common.ld

# --- test -------------------------------------------------------------------
# Both suites, under both implementations, and under the two build flags that
# change what the compiler does rather than what the library does.  Each
# combination has a build directory of its own, so none of them cleans.

step "The conformance suites, against the C"
make test LIB=c

step "The conformance suites, against the Rust"
make test LIB=rust

step "The conformance suites, under the sanitizers"
make test SANITIZE=1

step "The conformance suites, with logging on"
make test LOGGING=1

# --- rust -------------------------------------------------------------------
# Six workspaces, and --all reaches only the members of the one it is asked in,
# so each is named here or nothing checks it.

step "Formatting"
(cd rust && cargo fmt --all -- --check)
(cd rust/interop && cargo fmt -- --check)
(cd examples/embassy && cargo fmt -- --check)
(cd ci/ramfunc-probe && cargo fmt -- --check)
(cd test/hw/device-embassy && cargo fmt -- --check)
(cd test/hw/host && cargo fmt -- --check)

step "The crates' own tests"
make test-unit

step "The interop driver's tests"
(cd rust/interop && cargo test)

step "Lints"
(cd rust && cargo clippy --workspace --all-targets --release -- -D warnings)
(cd rust/interop && cargo clippy --all-targets --release -- -D warnings)
(cd examples/embassy && cargo clippy --all-targets --release -- -D warnings)
(cd ci/ramfunc-probe && cargo clippy --all-targets --release -- -D warnings)
(cd test/hw/device-embassy && cargo clippy --all-targets --release -- -D warnings)
(cd test/hw/host && cargo clippy --all-targets --release -- -D warnings)

step "Lints for the part"
# The lints above run on this machine, where the host half of the chip seam is
# selected and the device half is compiled by nobody.
(cd rust && cargo clippy -p picobootx-rp2350 \
    --target thumbv8m.main-none-eabi --release -- -D warnings)
(cd rust && cargo clippy -p picobootx-embassy --features rp2350 \
    --target thumbv8m.main-none-eabi --release -- -D warnings)

step "The documents"
ci/rust-docs.sh

# --- msrv -------------------------------------------------------------------
# The floor the crates claim, read from where they claim it, so this cannot
# drift from the declaration.  Skipped rather than failed when the toolchain is
# absent, and said out loud either way.

MSRV=$(sed -n 's/^rust-version = "\(.*\)"$/\1/p' rust/Cargo.toml)
if rustup toolchain list 2>/dev/null | grep -q "^${MSRV}"; then
    step "The oldest Rust the crates claim, ${MSRV}"
    (cd rust && cargo +"${MSRV}" check --locked \
        -p picobootx -p picobootx-rp2350 -p picobootx-embassy)
    (cd rust && cargo +"${MSRV}" check --locked \
        -p picobootx-rp2350 -p picobootx-embassy \
        --features picobootx-embassy/rp2350 \
        --target thumbv8m.main-none-eabi)
    MSRV_RAN="checked against ${MSRV}"
else
    MSRV_RAN="SKIPPED - install it with: rustup toolchain install ${MSRV}"
fi

# --- coverage ---------------------------------------------------------------
# Last because it is the slowest, and it is the gate that catches what no
# compiler does: a source nothing reaches, a floor with no file behind it, a
# file renamed out from under the lists in ci/.

step "Coverage, both languages, gated"
make cov

# --- bridges ----------------------------------------------------------------
# picobootx on a real USB bus, driven by real picotool and by picoboot-rs.  The
# kernel is the one Docker is running, reached by ci/bridges-docker.sh — read
# its header for what that needs and why it is not a stand-in for the gate.
# Skipped rather than failed with no docker, since the rest of this list wants
# nothing but a compiler and cargo.

if command -v docker >/dev/null && docker info >/dev/null 2>&1; then
    step "The picotool and picoboot-rs bridges, on a real bus"
    ci/bridges-docker.sh
    BRIDGES_RAN="ran"
else
    BRIDGES_RAN="SKIPPED - start docker and run: ci/bridges-docker.sh"
fi

echo
echo "=== all local checks passed ==="
echo "  minimum Rust: ${MSRV_RAN}"
echo "  bridges: ${BRIDGES_RAN}"
