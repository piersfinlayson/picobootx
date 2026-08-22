#!/usr/bin/env bash
# Where picobootx-rp2350's RAM function ends up in a real link.
#
# Usage: ci/check-ramfunc.sh
#
# The flash erase's critical part is placed in .ramfunc because it cannot be
# fetched from flash while flash is answering serial commands.  A section name
# places nothing: the linker script decides where the section lands and the
# startup decides whether its bytes are carried there.  A project missing
# either links without a warning, which is exactly the defect this exists to
# catch.
#
# None of that is visible in the crate.  It is a property of a link, and an
# rlib is not one - so this builds ci/ramfunc-probe, a cortex-m-rt program
# that calls flash_erase and is linked the way the crate's documentation tells
# a consumer to link it, and reads .ramfunc's two addresses out of the ELF.
#
#   VMA in RAM   - the section is placed where it can run with flash quiet.
#   LMA in FLASH - and it is carried in the image, so the startup copy has
#                  something to copy from.
#   __edata past the section's end - and the copy reaches all of it.  The
#                  startup fills __sdata..__edata from __sidata, so a section
#                  that sits outside that span is placed, loaded, and left as
#                  whatever RAM held.  Getting .ramfunc inside the span is the
#                  whole job of INSERT AFTER .data.
#   LMA right after .data's - and it reads the right bytes.  That one copy
#                  walks the load image in step with RAM, so .ramfunc's bytes
#                  have to sit immediately after .data's in flash.  A section
#                  inside the span but loaded from somewhere else is copied
#                  from whatever the gap holds.
#
# The regions are read from the probe's own memory.x, so what is checked is
# what the link was given rather than a second copy of the numbers.
set -e

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PROBE="$ROOT/ci/ramfunc-probe"
TARGET="thumbv8m.main-none-eabi"
ELF="$PROBE/target/$TARGET/release/ramfunc-probe"

# objdump rather than readelf, because the section header carries the VMA and
# only objdump prints the LMA beside it - and the LMA is half of what is being
# asked.  Overridable, since the name differs between toolchains.
OBJDUMP="${OBJDUMP:-arm-none-eabi-objdump}"
command -v "$OBJDUMP" >/dev/null || {
    echo "$OBJDUMP is not on PATH - set OBJDUMP to an objdump that reads Arm ELF" >&2
    exit 1
}

# __edata is a symbol rather than a section boundary, so it takes nm.
NM="${NM:-arm-none-eabi-nm}"
command -v "$NM" >/dev/null || {
    echo "$NM is not on PATH - set NM to an nm that reads Arm ELF" >&2
    exit 1
}

echo "Building the probe"
(cd "$PROBE" && cargo build --release)

# ORIGIN and LENGTH of one region, as two decimal numbers.  The shell reads 0x
# for itself, so only the K and M suffixes a linker script may write need
# handling here.
region() {
    local line origin len mult=1
    line="$(grep -E "^[[:space:]]*$1[[:space:]]*:" "$PROBE/memory.x")"
    origin="$(echo "$line" | sed -n 's/.*ORIGIN[[:space:]]*=[[:space:]]*\([^,[:space:]]*\).*/\1/p')"
    len="$(echo "$line" | sed -n 's/.*LENGTH[[:space:]]*=[[:space:]]*\([^,[:space:]]*\).*/\1/p')"
    case "$len" in
        *[kK]) mult=1024;    len="${len%?}" ;;
        *[mM]) mult=1048576; len="${len%?}" ;;
    esac
    echo "$((origin)) $((len * mult))"
}

read -r FLASH_ORIGIN FLASH_LEN <<EOF
$(region FLASH)
EOF
read -r RAM_ORIGIN RAM_LEN <<EOF
$(region RAM)
EOF
[ -n "$FLASH_LEN" ] && [ -n "$RAM_LEN" ] || {
    echo "could not read FLASH and RAM out of $PROBE/memory.x" >&2
    exit 1
}

# Idx Name  Size  VMA  LMA  File-off  Algn
SECTION="$("$OBJDUMP" -h "$ELF" | awk '$2 == ".ramfunc" { print $3, $4, $5; exit }')"
[ -n "$SECTION" ] || {
    echo "the probe has no .ramfunc section" >&2
    echo "erase_critical was not linked in, or the section was placed nowhere" >&2
    "$OBJDUMP" -h "$ELF" >&2
    exit 1
}

read -r SIZE VMA LMA <<EOF
$SECTION
EOF

# .data's, for the same reason - the startup copies the two as one run, so
# where .data's bytes end is where .ramfunc's have to start.
DATA="$("$OBJDUMP" -h "$ELF" | awk '$2 == ".data" { print $3, $5; exit }')"
[ -n "$DATA" ] || {
    echo "the probe has no .data section" >&2
    exit 1
}

read -r DATA_SIZE DATA_LMA <<EOF
$DATA
EOF

size=$((0x$SIZE)); vma=$((0x$VMA)); lma=$((0x$LMA))
data_size=$((0x$DATA_SIZE)); data_lma=$((0x$DATA_LMA))

# An empty .data ends where anything could start, so the comparison below
# would hold whatever the linker script did.  ci/ramfunc-probe carries a
# static to stop that, and this is what says the static is still there.
[ "$data_size" -gt 0 ] || {
    echo "the probe's .data is empty, so where .ramfunc is loaded from cannot" >&2
    echo "be checked against it - ci/ramfunc-probe carries a static for this" >&2
    exit 1
}

# Where cortex-m-rt's startup copy stops.
EDATA="$("$NM" "$ELF" | awk '$3 == "__edata" { print $1; exit }')"
[ -n "$EDATA" ] || {
    echo "the probe defines no __edata, so where the startup copy stops cannot" >&2
    echo "be read - it is cortex-m-rt's link.x that defines it" >&2
    exit 1
}
edata=$((0x$EDATA))

printf '.ramfunc  size 0x%x  VMA 0x%08x  LMA 0x%08x\n' "$size" "$vma" "$lma"
printf '.data     size 0x%x  LMA 0x%08x\n' "$data_size" "$data_lma"
printf '__edata   0x%08x\n' "$edata"
printf 'RAM   0x%08x + 0x%x\n' "$RAM_ORIGIN" "$RAM_LEN"
printf 'FLASH 0x%08x + 0x%x\n' "$FLASH_ORIGIN" "$FLASH_LEN"

bad=0
[ "$size" -gt 0 ] || { echo "FAIL: .ramfunc is empty" >&2; bad=1; }

if [ "$vma" -lt "$RAM_ORIGIN" ] || [ $((vma + size)) -gt $((RAM_ORIGIN + RAM_LEN)) ]; then
    echo "FAIL: .ramfunc runs from outside RAM, so an erase would fetch it from" >&2
    echo "      a flash that has stopped answering" >&2
    bad=1
fi

if [ "$lma" -lt "$FLASH_ORIGIN" ] || [ $((lma + size)) -gt $((FLASH_ORIGIN + FLASH_LEN)) ]; then
    echo "FAIL: .ramfunc is not loaded from flash, so nothing carries it into RAM" >&2
    bad=1
fi

if [ "$edata" -lt $((vma + size)) ]; then
    echo "FAIL: the startup copy stops at __edata, short of .ramfunc's end at" >&2
    printf '      0x%08x, so the rest of the routine is whatever RAM held\n' \
        $((vma + size)) >&2
    bad=1
fi

if [ "$lma" -ne $((data_lma + data_size)) ]; then
    echo "FAIL: .ramfunc is loaded from a different place than the one the" >&2
    printf '      startup copy reads for it - .data ends at 0x%08x and\n' \
        $((data_lma + data_size)) >&2
    printf '      .ramfunc is loaded from 0x%08x, so the copy fills the\n' "$lma" >&2
    echo "      routine with whatever lies between" >&2
    bad=1
fi

[ "$bad" -eq 0 ] || exit 1
echo "PASS: .ramfunc runs from RAM, is loaded from flash right after .data, and the startup copy covers it"
