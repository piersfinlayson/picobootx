# Copyright (C) 2026 Piers Finlayson <piers@piers.rocks>
#
# MIT License

# What the picotool and picoboot-rs bridge jobs need, in one image.
#
# Built and run by ci/bridges-docker.sh — see that script for why the image
# exists and how the container is given the bus.  Nothing here is picobootx:
# the tree is handed to the container at run time, so a change to the library
# does not rebuild any of this.
#
# Ubuntu 24.04 because that is what ubuntu-latest is, and these two jobs are
# the ones whose answer depends on the kernel and its USB stack.
FROM ubuntu:24.04

# kmod carries modprobe, which the bridge calls.  sudo is here because the
# makefile targets hand the run to it, and the point of this image is to run
# those targets as written rather than a paraphrase of them - the container's
# root needs no password and sudo is a passthrough, but the command line CI
# runs and the command line this runs are then the same string.  The rest is
# what CI's own picotool job installs, plus git and curl for the two things
# built below.
#
# Retries, because ports.ubuntu.com serves an index naming a version its pool
# does not yet carry while a mirror is part way through a sync, and the fetch
# 404s on a package nothing here asked for by name.
RUN echo 'Acquire::Retries "5";' >/etc/apt/apt.conf.d/99retries \
    && apt-get update && apt-get install -y --no-install-recommends \
        build-essential cmake pkg-config libusb-1.0-0-dev \
        git ca-certificates curl kmod sudo \
    && rm -rf /var/lib/apt/lists/*

# picotool from its own release tag rather than from a distribution, for the
# reason CI gives: what this measures compatibility against has to be a version
# that can be named.  Keep the default in step with PICOTOOL_TAG in
# .github/workflows/build.yml.
ARG PICOTOOL_TAG=2.1.1
RUN git clone --depth 1 --branch "$PICOTOOL_TAG" \
        https://github.com/raspberrypi/picotool.git /tmp/picotool \
    && git clone --depth 1 --branch "$PICOTOOL_TAG" \
        https://github.com/raspberrypi/pico-sdk.git /tmp/pico-sdk \
    && cmake -S /tmp/picotool -B /tmp/picotool/build \
        -DPICO_SDK_PATH=/tmp/pico-sdk \
    && cmake --build /tmp/picotool/build -j"$(nproc)" \
    && cp /tmp/picotool/build/picotool /usr/local/bin/ \
    && rm -rf /tmp/picotool /tmp/pico-sdk \
    && picotool version

# Rust, for the picoboot-rs bridge.  Stable, as CI takes it.
ENV RUSTUP_HOME=/usr/local/rustup CARGO_HOME=/usr/local/cargo
ENV PATH=/usr/local/cargo/bin:$PATH
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
        | sh -s -- -y --default-toolchain stable --profile minimal \
    && chmod -R a+w "$CARGO_HOME" \
    && cargo --version
