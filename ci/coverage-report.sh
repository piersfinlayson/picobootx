#!/usr/bin/env bash
# Turn coverage tracefiles into figures, a line list, or a pass/fail gate.
#
# Usage: ci/coverage-report.sh [mode] [tracefile ...]
#
#   (no mode)          per-file table, grouped by language, with totals
#   --uncovered [PATH] the lines nothing reached, narrowed to the measured
#                      files whose path contains PATH.  A PATH nothing matches
#                      is an error rather than an empty answer.
#   --check            fail if any file is below its floor, if a floor has no
#                      file behind it, or if a source reached no tracefile
#   --raise            raise the floors to today's figures
#
# Tracefiles default to the set `make cov` writes, which is the C library as
# each implementation's suites reached it and the Rust library as its own.
# Naming tracefiles explicitly reports on a subset, which is how you look at
# one language on its own.  --raise refuses them: it rewrites every floor, and
# a subset would rewrite floors it never measured.  --check accepts them and
# will fail, since a file the subset does not carry reads as one that has gone.
#
# Line coverage only.  Function and branch records are present in a tracefile
# and are ignored here: one number per file that anyone can reason about beats
# a richer one nobody reads, and the C's own gate in test/Makefile already
# requires every function as well as every line.  It does mean this cannot see
# inside a match arm, so an untested arm of a dispatch reads as covered.
#
# Merging happens here rather than in lcov, because for line coverage the rule
# is that a line is covered if any run covered it, which is a union.  Doing it
# here keeps this script working with whatever lcov the machine has, and lets
# it read the Rust tracefile too, which lcov never touched.
#
# The floors are a ratchet.  They exist so coverage cannot quietly go
# backwards, and so something new cannot be added with no test.  --uncovered is
# how you improve them: what is left after both suites, under both
# implementations, is either a test nobody has written or a path the harness
# cannot reach, and only reading the lines says which.
#
# This reports what the tracefiles say.  It does not re-run anything, and it
# cannot tell a tracefile written before an edit from one written after — `make
# cov` captures and checks in the one command, which is how a figure and the
# source it describes are kept together.
set -e

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BASELINE="$ROOT/ci/coverage-baseline.txt"
UNMEASURED="$ROOT/ci/coverage-unmeasured.txt"
OUT_DIR="$ROOT/test/build/coverage"

# The set of runs the floors are built from.  A floor raised from all of these
# cannot be met by fewer - fewer runs reach fewer lines - so --check refuses
# unless every one is present.  picobootx-c is the C library as the C
# implementation's suites reached it, picobootx-rust the C left over when the
# Rust library is under test, and rust the Rust library itself.
CAMPAIGN="picobootx-c.info picobootx-rust.info rust.info"

MODE="table"
FILTER=""
case "${1:-}" in
    --uncovered) MODE="uncovered"; shift
                 # Anything that is not a tracefile is the filter.  Decided by
                 # what it is not, rather than by a list of source suffixes: a
                 # directory, or a path typed wrongly, matched no suffix and was
                 # taken as a tracefile instead, and a tracefile that does not
                 # exist reads as a run in which nothing was uncovered.
                 case "${1:-}" in
                     "")     ;;
                     *.info) ;;
                     *)      FILTER="$1"; shift ;;
                 esac ;;
    --check)     MODE="check"; shift ;;
    --raise)     MODE="raise"; shift ;;
    --*)         echo "unknown option '$1'" >&2; exit 2 ;;
esac

# --raise writes every floor in the file, so it has to have measured every one.
# Handed one tracefile it would rewrite the whole baseline from that tracefile,
# and every floor the file does not carry would go.
if [ "$MODE" = raise ] && [ $# -gt 0 ]; then
    echo "--raise rewrites every floor, so it reads the whole set of runs and" >&2
    echo "takes no tracefile arguments.  Run 'make cov', then 'make cov-raise'." >&2
    exit 2
fi

if [ $# -gt 0 ]; then
    TRACEFILES="$*"
else
    missing=""
    TRACEFILES=""
    for t in $CAMPAIGN; do
        # -s, not -f: a tracefile of zero bytes is one the capture did not
        # finish writing, and it says as little as one that is not there.
        if [ -s "$OUT_DIR/$t" ]; then
            TRACEFILES="$TRACEFILES $OUT_DIR/$t"
        else
            missing="$missing  $t\n"
        fi
    done
    if [ -n "$missing" ]; then
        echo "Not every run the floors are built from has been captured - missing:" >&2
        printf "%b" "$missing" >&2
        echo "Run 'make cov', or name tracefiles explicitly to report on a subset." >&2
        exit 1
    fi
fi

dest=/dev/stdout
sources=/dev/null
tmp_dest=""
tmp_sources=""
trap 'rm -f "$tmp_dest" "$tmp_sources"' EXIT

if [ "$MODE" = raise ]; then
    tmp_dest="$(mktemp)"
    dest="$tmp_dest"
fi

# Every source the measured set is expected to name.  Which files reach
# llvm-cov and lcov is decided by hand-kept lists in test/Makefile, so a new
# crate, or a file in a directory none of those lists names, is measured by
# nothing - and nothing in a tracefile can say so, because the file is simply
# not in it.  So the check asks the tree rather than the tracefiles.
#
# rust/interop is out: it is a workspace of its own, driving picobootx from
# outside as a host would, and the suite never links it.  target directories
# hold what cargo fetched and built, which is nobody's source.
if [ "$MODE" = check ]; then
    tmp_sources="$(mktemp)"
    sources="$tmp_sources"
    (
        cd "$ROOT"
        ls src/*.c
        find rust -type d \( -name interop -o -name target \) -prune -o \
             -type f -name '*.rs' -path '*/src/*' -print
    ) | sort > "$sources"
fi

# shellcheck disable=SC2086
awk -v mode="$MODE" -v filter="$FILTER" -v baseline="$BASELINE" \
    -v sources="$sources" -v unmeasured="$UNMEASURED" -v listfile="ci/coverage-unmeasured.txt" '
# Which language a file belongs to, longest prefix first.  Two entries, so they
# are here rather than in a file of their own - but a path matching neither is
# reported as Ungrouped and fails the check, so a third one appearing cannot go
# unnoticed.
function name_of(path) {
    if (index(path, "src/") == 1)  return "C library"
    if (index(path, "rust/") == 1) return "Rust library"
    ungrouped[path] = 1
    return "Ungrouped"
}
function n_ungrouped(   k, n) { for (k in ungrouped) n++; return n + 0 }
function pct(h, t) { return t ? 100.0 * h / t : 0 }

# Order a list of paths the way the table groups them - by language, then by
# path.  A bubble sort, because the lists are a dozen entries long and every
# awk has this and not all of them have a sort.
function sort_list(a, n,   i, j, x, y, t) {
    for (i = 1; i <= n; i++)
        for (j = i + 1; j <= n; j++) {
            x = name_of(a[i]) SUBSEP a[i]; y = name_of(a[j]) SUBSEP a[j]
            if (y < x) { t = a[i]; a[i] = a[j]; a[j] = t }
        }
    return n
}
# Every file that was measured, and every file that has a floor.
function sort_union(a,   f, n) {
    n = 0
    for (f in files)    a[++n] = f
    for (f in floor_of) if (!(f in files)) a[++n] = f
    return sort_list(a, n)
}
function sort_floors(a,   f, n) {
    n = 0
    for (f in floor_of) a[++n] = f
    return sort_list(a, n)
}

BEGIN {
    while ((getline line < baseline) > 0) {
        if (line ~ /^ *#/ || line ~ /^ *$/) continue
        split(line, fld, /[ \t]+/); floor_of[fld[1]] = fld[2] + 0
    }
    while ((getline line < sources) > 0) {
        if (line == "") continue
        src[++nsrc] = line; on_disk[line] = 1
    }
    while ((getline line < unmeasured) > 0) {
        if (line ~ /^ *#/ || line ~ /^ *$/) continue
        split(line, fld, /[ \t]+/); ign[++nign] = fld[1]; ignored[fld[1]] = 1
    }
}

# Union the tracefiles: a line is covered if any run covered it.
/^SF:/  { sf = substr($0, 4); next }
/^DA:/  {
    split(substr($0, 4), d, ",")
    key = sf SUBSEP d[1]
    if (!(key in seen)) { seen[key] = 1; files[sf] = 1; total[sf]++ }
    if (d[2] + 0 > 0 && !(key in covered)) { covered[key] = 1; hit[sf]++ }
    next
}

END {
    if (mode == "uncovered") {
        # A filter nothing matches would otherwise print nothing, which reads
        # exactly like a filter that matched and found every line covered.
        nmatch = 0
        for (f in files) if (filter == "" || index(f, filter)) nmatch++
        if (nmatch == 0) {
            if (filter != "")
                printf "no measured file matches \"%s\"\n", filter
            else
                print "the tracefiles name no file"
            exit 1
        }
        for (k in seen) {
            split(k, kp, SUBSEP)
            if (k in covered) continue
            if (filter != "" && index(kp[1], filter) == 0) continue
            miss[kp[1]] = miss[kp[1]] " " kp[2]
        }
        nout = 0
        for (f in miss) { out[++nout] = f }
        for (i = 1; i <= nout; i++)
            for (j = i + 1; j <= nout; j++)
                if (out[j] < out[i]) { t = out[i]; out[i] = out[j]; out[j] = t }
        for (i = 1; i <= nout; i++) {
            f = out[i]
            n = split(miss[f], ln, " ")
            for (a = 1; a <= n; a++) for (b = a + 1; b <= n; b++)
                if (ln[b] + 0 < ln[a] + 0) { t = ln[a]; ln[a] = ln[b]; ln[b] = t }
            printf "%s  (%d uncovered of %d)\n", f, total[f] - hit[f], total[f]
            line = "   "
            for (a = 1; a <= n; a++) {
                if (ln[a] == "") continue
                if (length(line) > 70) { print line; line = "   " }
                line = line " " ln[a]
            }
            if (line != "   ") print line
        }
        if (nout == 0)
            printf "nothing uncovered in the %d file(s) matched\n", nmatch
        exit 0
    }

    nf = 0
    for (f in files) { flist[++nf] = f }
    sort_list(flist, nf)

    if (mode == "raise") {
        print "# Per-file coverage floors.  A file may not drop below its floor."
        print "# Raised by ci/coverage-report.sh --raise.  Never lowered by hand"
        print "# without saying why in the commit."
        print "#"
        print "# The C library sits at 100.0 because test/Makefile gates it there"
        print "# outright, on functions as well as lines.  A floor below 100.0 on"
        print "# one of those three files means the gate has been let go."
        # Every file that has a floor, plus every file that was measured.  A
        # floor whose file the runs did not measure is carried forward as it
        # stands rather than dropped: a file leaving the measured set is what
        # --check reports as GONE, and a --raise that quietly deleted the floor
        # would take the evidence with it.
        nr = sort_union(rlist)
        for (i = 1; i <= nr; i++) {
            f = rlist[i]
            if (f in files) {
                rate = pct(hit[f], total[f])
                fl = (f in floor_of && floor_of[f] > rate) ? floor_of[f] : rate
            } else {
                fl = floor_of[f]
            }
            printf "%-44s %5.1f\n", f, fl
        }
        exit 0
    }

    if (mode == "check") {
        bad = 0
        for (i = 1; i <= nf; i++) {
            f = flist[i]; rate = pct(hit[f], total[f])
            if (!(f in floor_of)) {
                printf "NEW    %-44s %5.1f%%  (no floor yet)\n", f, rate
                bad = 1; continue
            }
            if (rate + 0.05 < floor_of[f]) {
                printf "DROP   %-44s %5.1f%%  floor %.1f%%\n", f, rate, floor_of[f]
                bad = 1
            } else if (rate > floor_of[f] + 0.05) {
                printf "RAISE  %-44s %5.1f%%  floor %.1f%%\n", f, rate, floor_of[f]
                raisable++
            }
        }

        # The loop above walks what the tracefiles hold, so a file that has
        # stopped being measured is not in it and nothing above says a word.
        # That is what a lost --whole-archive, a module removed by a cfg, a
        # crate dropped from the measured set and a path filter that stopped
        # matching all look like - and each of them would otherwise leave the
        # gate reporting a pass over what is left.  So the floors are walked
        # too, and a floor with nothing behind it fails.
        ng = sort_floors(glist)
        for (i = 1; i <= ng; i++) {
            f = glist[i]
            if (f in files) continue
            printf "GONE   %-44s     -    floor %.1f%%  (measured by nothing)\n",
                   f, floor_of[f]
            bad = 1
        }

        # And a source that reaches no tracefile at all.  A floor cannot catch
        # this one: the file never had a floor to begin with, so it is not GONE,
        # and it is not NEW either, because nothing measured it.  One that does
        # have a floor is left to GONE above, which has already said it.
        for (i = 1; i <= nsrc; i++) {
            f = src[i]
            if (f in files || f in ignored || f in floor_of) continue
            printf "UNMEA  %-44s     -    (no coverage data, and not named in\n", f
            printf "       %s)\n", listfile
            bad = 1
        }
        for (i = 1; i <= nign; i++) {
            f = ign[i]
            if (!(f in on_disk))
                printf "STALE  %-44s (in %s, not in the tree)\n", f, listfile
            else if (f in files)
                printf "STALE  %-44s (in %s, and measured after all)\n", f, listfile
            else
                continue
            bad = 1
        }

        if (n_ungrouped()) {
            printf "\n%d file(s) belong to no language\n", n_ungrouped()
            for (u in ungrouped) print "   " u
            bad = 1
        }
        if (bad) { print "\ncoverage check FAILED"; exit 1 }
        if (raisable)
            printf "\ncoverage check passed - %d floor(s) can go up, run --raise\n", raisable
        else
            print "coverage check passed"
        exit 0
    }

    printf "%-44s %7s %7s %7s %7s\n", "File", "Lines", "Hit", "Rate", "Floor"
    printf "%-44s %7s %7s %7s %7s\n", "----", "-----", "---", "----", "-----"
    prev = ""
    for (i = 1; i <= nf; i++) {
        f = flist[i]; g = name_of(f)
        if (g != prev && prev != "") {
            printf "%-44s %7d %7d %6.1f%%\n\n", prev, gt, gh, pct(gh, gt)
            gt = 0; gh = 0
        }
        prev = g; gt += total[f]; gh += hit[f]
        at += total[f]; ah += hit[f]
        # A file with no floor is new, and --check is what fails on it.  Here it
        # just reads as having none.
        rate = pct(hit[f], total[f])
        if (f in floor_of) {
            fl = sprintf("%6.1f%%", floor_of[f])
            # Named, not left to the reader to spot by comparing two numbers.
            # BELOW is the failure the gate reports, and the headroom above a
            # floor is what --raise would take up.
            if (rate + 0.05 < floor_of[f])        mark = "  BELOW"
            else if (rate > floor_of[f] + 0.05)   mark = sprintf("  +%.1f", rate - floor_of[f])
            else                                  mark = ""
        } else {
            fl = "      -"
            mark = "  NEW"
        }
        printf "  %-42s %7d %7d %6.1f%% %s%s\n", f, total[f], hit[f], rate, fl, mark
    }
    if (prev != "") printf "%-44s %7d %7d %6.1f%%\n", prev, gt, gh, pct(gh, gt)
    printf "\n%-44s %7d %7d %6.1f%%\n", "ALL", at, ah, pct(ah, at)

    if (n_ungrouped()) {
        printf "\n%d file(s) belong to no language, so they are counted in ALL\n", n_ungrouped()
        printf "and to nothing else:\n"
        for (u in ungrouped) printf "   %s\n", u
        exit 1
    }
}
' $TRACEFILES > "$dest"

# --raise writes the baseline itself, rather than leaving it to a shell
# redirect - a redirect truncates the file before awk reads it, and a floor
# nobody wrote down is a floor that does not exist.
if [ "$MODE" = raise ]; then
    if [ -f "$BASELINE" ] && diff -q "$BASELINE" "$dest" >/dev/null 2>&1; then
        echo "No floor moved - $BASELINE is already current."
    else
        [ -f "$BASELINE" ] && diff "$BASELINE" "$dest" |
            sed -n 's/^> \(.*\)/  raised: \1/p'
        cp "$dest" "$BASELINE"
        echo "Wrote $BASELINE"
    fi
fi
