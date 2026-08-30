# Copyright (C) 2026 Piers Finlayson <piers@piers.rocks>
#
# MIT License

# The tinyusb every build in this tree uses, and how it is fetched.
#
# Three builds compile tinyusb - the usb conformance suite, the tinyusb example
# and the tinyusb half of the hardware test - and they must all compile the same
# one.  Two of them ran against different commits once, which costs a finding on
# a board the suite cannot reproduce, with nothing saying the two were not
# comparing like with like.
#
# The fork exists because stock tinyusb cannot stall an endpoint and leave it
# unclaimed, cannot clear a stall without resetting the data toggle, cannot
# correct the toggle of a buffer armed when the host cleared a halt, and cannot
# take back a transfer the host has not collected.  All four are what a protocol
# that stalls to refuse a command needs.
#
# The source list is not shared, because the suite supplies its own device
# controller and compiles no port while both device builds compile the rp2040
# one.  What is below is the device list those two use.

TINYUSB_URL    := https://github.com/piersfinlayson/tinyusb.git
TINYUSB_COMMIT := 05fb334d021df621141b1dd4a8b747ee7f4d6760

# Put the pinned commit in $(1), and put it back if what is there is something
# else.  git clone cannot reach a commit, so this is init plus a shallow fetch
# of the exact object, and the commit fetched is stamped in $(1).pin beside it.
#
# Comparing the stamp is what makes moving the pin above enough on its own.
# Asking only whether the directory exists leaves a tree that has fetched once
# building against whatever it fetched then, silently.  A stamp rather than git
# rev-parse because ci/bridges-run.sh copies this tree without .git, and beside
# the directory rather than in it because what is fetched is somebody else's
# repository.
define tinyusb-fetch
[ "$$(cat $(1).pin 2>/dev/null)" = "$(TINYUSB_COMMIT)" ] || ( \
	rm -rf $(1) && \
	git init -q $(1) && \
	git -C $(1) remote add origin $(TINYUSB_URL) && \
	git -C $(1) fetch -q --depth 1 origin $(TINYUSB_COMMIT) && \
	git -C $(1) checkout -q FETCH_HEAD && \
	echo $(TINYUSB_COMMIT) > $(1).pin )
endef

# What a device build compiles and includes.  Paths are relative to the fetched
# directory, so each build prefixes them with wherever it put it.
TINYUSB_SRC_C += \
	src/tusb.c \
	src/common/tusb_fifo.c \
	src/device/usbd.c \
	src/device/usbd_control.c \
	src/portable/raspberrypi/rp2040/dcd_rp2040.c \
	src/portable/raspberrypi/rp2040/rp2040_usb.c

TINYUSB_INCLUDE_DIRS += \
	src \
	src/common \
	src/device \
	src/class/cdc \
	src/portable/raspberrypi/rp2040
