#!/usr/bin/env bash
# Where the C library's RAM functions end up in a real link.
#
# Usage: ci/check-ramfunc-c.sh [elf linker-script]
#
# With no arguments it checks examples/tinyusb, which is the only C link this
# repository makes.  With an ELF and the linker script that produced it, it
# checks that link instead - an integrator's own, which is a different question:
# whether their script and startup did what INTEGRATION.md asks.  A project that
# did neither links clean and faults at runtime.
#
# ci/check-ramfunc.sh is the Rust's counterpart.  The two differ because the
# copies differ: cortex-m-rt carries .ramfunc as part of its .data run, so the
# Rust's is asked whether the section lies inside that span.  A C integrator is
# told to copy .ramfunc with a loop of its own, bracketed by three symbols, so
# what is asked here is whether those three symbols really do bracket this
# section.
#
# The critical parts of a flash erase and a flash page program are placed in
# .ramfunc because they cannot be fetched from flash while flash is answering
# serial commands.  A section name places nothing: the linker script decides
# where the section lands and the startup decides whether its bytes are carried
# there.
#
#   .ramfunc non-empty  - the routines were linked in rather than dropped.
#   VMA in RAM          - they run from somewhere flash being quiet cannot
#                         reach.
#   LMA in FLASH        - and they are carried in the image, so the startup
#                         copy has something to copy from.
#   __ramfunc_start,    - and the copy covers the whole section.  Those three
#   __ramfunc_end,        are what INTEGRATION.md's reset handler reads, so a
#   __ramfunc_load        script that defines them around something else, or
#                         not at all, copies the wrong bytes or none.
#   pb_ramfunc_mark     - and the word the library reads back at run time is
#                         inside that section.  The marker lives in
#                         .ramfunc.mark, because a compiler will not put data
#                         and code in one section, and INTEGRATION.md's
#                         *(.ramfunc*) is what gathers the two together.  A
#                         script matching .ramfunc exactly leaves the marker
#                         elsewhere, and the library then refuses every erase on
#                         a device that would have worked.
#
# The regions are read from the linker script the link was given, rather than
# from a second copy of the numbers.
set -e

ROOT="$(cd "$(dirname "$0")/.." && pwd)"

if [ "$#" -eq 2 ]; then
    ELF="$1"
    LD="$2"
    BUILD=0
elif [ "$#" -eq 0 ]; then
    ELF="$ROOT/examples/tinyusb/build/picobootx.elf"
    LD="$ROOT/examples/tinyusb/pico-sdkless-repo/examples/common/common.ld"
    BUILD=1
else
    echo "usage: ci/check-ramfunc-c.sh [elf linker-script]" >&2
    exit 1
fi
NAME="$(basename "$ELF")"

# objdump rather than readelf, because the section header carries the VMA and
# only objdump prints the LMA beside it - and the LMA is half of what is being
# asked.  Overridable, since the name differs between toolchains.
OBJDUMP="${OBJDUMP:-arm-none-eabi-objdump}"
command -v "$OBJDUMP" >/dev/null || {
    echo "$OBJDUMP is not on PATH - set OBJDUMP to an objdump that reads Arm ELF" >&2
    exit 1
}

# The three placement symbols are symbols rather than section boundaries, so
# they take nm.
NM="${NM:-arm-none-eabi-nm}"
command -v "$NM" >/dev/null || {
    echo "$NM is not on PATH - set NM to an nm that reads Arm ELF" >&2
    exit 1
}

if [ "$BUILD" -eq 1 ]; then
    echo "Building the tinyusb example"
    make -C "$ROOT" example >/dev/null
fi
[ -f "$ELF" ] || { echo "$ELF does not exist" >&2; exit 1; }
[ -f "$LD" ] || { echo "$LD does not exist" >&2; exit 1; }

# ORIGIN and LENGTH of one region, as two decimal numbers.  The shell reads 0x
# for itself, so only the K and M suffixes a linker script may write need
# handling here.
region() {
    local line origin len mult=1
    line="$(grep -E "^[[:space:]]*$1[[:space:]]*\(" "$LD")"
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
    echo "could not read FLASH and RAM out of $LD" >&2
    exit 1
}

# Idx Name  Size  VMA  LMA  File-off  Algn
SECTION="$("$OBJDUMP" -h "$ELF" | awk '$2 == ".ramfunc" { print $3, $4, $5; exit }')"
[ -n "$SECTION" ] || {
    echo "FAIL: $NAME has no .ramfunc section" >&2
    echo "      The critical routines were not linked in, or the script placed" >&2
    echo "      the section nowhere" >&2
    exit 1
}

read -r SIZE VMA LMA <<EOF
$SECTION
EOF

# Three hex numbers, or the row was not the one this expects.  An objdump that
# lays its columns out differently would otherwise reach the arithmetic below
# with a word where an address belongs, and report some other fault instead of
# saying it did not understand what it read.
hex() { [ -n "$1" ] && [ -z "${1//[0-9a-fA-F]/}" ]; }
hex "$SIZE" && hex "$VMA" && hex "$LMA" || {
    echo "FAIL: $OBJDUMP's section row for .ramfunc is not size, VMA and LMA:" >&2
    echo "      $SECTION" >&2
    echo "      A section with no load address of its own prints without an" >&2
    echo "      LMA.  A different layout means this script needs an objdump it" >&2
    echo "      understands - GNU's prints all three." >&2
    exit 1
}

# The three symbols INTEGRATION.md's reset handler copies between.
sym() { "$NM" "$ELF" | awk -v s="$1" '$3 == s { print $1; exit }'; }
START="$(sym __ramfunc_start)"
END="$(sym __ramfunc_end)"
LOAD="$(sym __ramfunc_load)"
[ -n "$START" ] && [ -n "$END" ] && [ -n "$LOAD" ] || {
    echo "FAIL: $NAME does not define all of __ramfunc_start, __ramfunc_end" >&2
    echo "      and __ramfunc_load, so nothing says where the startup copy" >&2
    echo "      runs from and to.  INTEGRATION.md's linker script fragment is" >&2
    echo "      what defines them.  An integrator using names of their own" >&2
    echo "      adapts this script to those names." >&2
    exit 1
}

MARK="$(sym pb_ramfunc_mark)"
[ -n "$MARK" ] || {
    echo "FAIL: $NAME does not define pb_ramfunc_mark, so the library has no" >&2
    echo "      way to tell at run time whether the startup copy ran" >&2
    exit 1
}

size=$((0x$SIZE)); vma=$((0x$VMA)); lma=$((0x$LMA))
start=$((0x$START)); end=$((0x$END)); load=$((0x$LOAD))
mark=$((0x$MARK))

printf '.ramfunc        size 0x%x  VMA 0x%08x  LMA 0x%08x\n' "$size" "$vma" "$lma"
printf '__ramfunc_start 0x%08x\n' "$start"
printf '__ramfunc_end   0x%08x\n' "$end"
printf '__ramfunc_load  0x%08x\n' "$load"
printf 'pb_ramfunc_mark 0x%08x\n' "$mark"
printf 'RAM             0x%08x + 0x%x\n' "$RAM_ORIGIN" "$RAM_LEN"
printf 'FLASH           0x%08x + 0x%x\n' "$FLASH_ORIGIN" "$FLASH_LEN"

bad=0
[ "$size" -gt 0 ] || { echo "FAIL: .ramfunc is empty" >&2; bad=1; }

if [ "$vma" -lt "$RAM_ORIGIN" ] || [ $((vma + size)) -gt $((RAM_ORIGIN + RAM_LEN)) ]; then
    echo "FAIL: .ramfunc runs from outside RAM, so an erase or a program would" >&2
    echo "      fetch it from a flash that has stopped answering" >&2
    bad=1
fi

if [ "$lma" -lt "$FLASH_ORIGIN" ] || [ $((lma + size)) -gt $((FLASH_ORIGIN + FLASH_LEN)) ]; then
    echo "FAIL: .ramfunc is not loaded from flash, so nothing carries it into RAM" >&2
    bad=1
fi

if [ "$start" -ne "$vma" ] || [ "$end" -ne $((vma + size)) ]; then
    echo "FAIL: the startup copy fills __ramfunc_start to __ramfunc_end, which" >&2
    printf '      is 0x%08x to 0x%08x, and .ramfunc runs from 0x%08x to\n' \
        "$start" "$end" "$vma" >&2
    printf '      0x%08x - so part of the routine is whatever RAM held\n' \
        $((vma + size)) >&2
    bad=1
fi

if [ "$mark" -lt "$vma" ] || [ "$mark" -ge $((vma + size)) ]; then
    echo "FAIL: pb_ramfunc_mark is outside .ramfunc, so the word the library" >&2
    echo "      reads back to tell whether the copy ran was not carried by it." >&2
    echo "      The marker sits in .ramfunc.mark - this script's header says" >&2
    echo "      why - so the script needs *(.ramfunc*) rather than *(.ramfunc)" >&2
    bad=1
fi

if [ "$load" -ne "$lma" ]; then
    echo "FAIL: the startup copy reads from __ramfunc_load, which is" >&2
    printf '      0x%08x, and .ramfunc is loaded from 0x%08x - so the\n' \
        "$load" "$lma" >&2
    echo "      routine is filled with whatever lies at the other address" >&2
    bad=1
fi

[ "$bad" -eq 0 ] || exit 1
echo "PASS: $NAME's .ramfunc runs from RAM, is loaded from flash, and the startup copy covers it"
