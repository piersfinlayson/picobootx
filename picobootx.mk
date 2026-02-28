# Makefile fragment to make it easier to integrate picobootx into another
# project's build system.

PICOBOOTX_SRC_C := \
	src/picobootx.c \
	src/picobootx_vendor.c \
	src/picobootx_impl.c

PICOBOOTX_INCLUDE_DIRS := \
	include