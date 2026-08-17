// Copyright (C) 2026 Piers Finlayson <piers@piers.rocks>
//
// MIT License

// The harness itself: the sequence log every other part records into, the
// assertion machinery, and the setup a scenario starts from.

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pbt.h"

// Generous: the longest scenario records a few hundred actions.
#define PBT_EVENT_MAX 4096u

// ---------------------------------------------------------------------------
// The log
// ---------------------------------------------------------------------------

static pbt_event_t s_events[PBT_EVENT_MAX];
static uint32_t    s_event_count;
static uint32_t    s_seq;

void pbt_log(const char *name, uint32_t a0, uint32_t a1, uint32_t a2,
             uint32_t a3) {
    if (s_event_count >= PBT_EVENT_MAX) {
        // Dropping events silently would make an ordering assertion answer from
        // a truncated record, which is worse than stopping.
        fprintf(stderr, "pbt: sequence log full at %u events\n", PBT_EVENT_MAX);
        abort();
    }
    pbt_event_t *ev = &s_events[s_event_count++];
    ev->seq  = ++s_seq;
    ev->name = name;
    ev->a0   = a0;
    ev->a1   = a1;
    ev->a2   = a2;
    ev->a3   = a3;
}

uint32_t pbt_event_count(void) { return s_event_count; }

// Drop everything recorded so far.  The sequence log belongs to one scenario,
// and whatever sets a scenario up empties it.
void pbt_log_reset(void) { s_event_count = 0; s_seq = 0; }

const pbt_event_t *pbt_event(uint32_t index) {
    return index < s_event_count ? &s_events[index] : NULL;
}

int pbt_count(const char *name) {
    int n = 0;
    for (uint32_t i = 0; i < s_event_count; i++) {
        if (strcmp(s_events[i].name, name) == 0) {
            n++;
        }
    }
    return n;
}

const pbt_event_t *pbt_nth(const char *name, int n) {
    int seen = 0;
    for (uint32_t i = 0; i < s_event_count; i++) {
        if (strcmp(s_events[i].name, name) == 0) {
            if (seen == n) {
                return &s_events[i];
            }
            seen++;
        }
    }
    return NULL;
}

int pbt_seq(const char *name) {
    const pbt_event_t *ev = pbt_nth(name, 0);
    return ev == NULL ? -1 : (int)ev->seq;
}

bool pbt_before(const char *first, const char *second) {
    int a = pbt_seq(first);
    int b = pbt_seq(second);
    // An absent action cannot be ordered against anything.  Answering true here
    // would let an ordering assertion pass for a sequence that never ran.
    return a >= 0 && b >= 0 && a < b;
}

void pbt_dump_log(void) {
    fprintf(stderr, "    sequence log (%u events):\n", s_event_count);
    for (uint32_t i = 0; i < s_event_count; i++) {
        const pbt_event_t *ev = &s_events[i];
        fprintf(stderr, "      %4u  %-32s %10u %10u %10u %10u\n", ev->seq,
                ev->name, ev->a0, ev->a1, ev->a2, ev->a3);
    }
}

// ---------------------------------------------------------------------------
// picobootx's own logging
//
// Built only when PICOBOOT_LOGGING is on.  picobootx declares these and leaves
// them to the integrator, so a host build has to supply them like any other.
// Its call sites do not terminate their lines, so this does.
// ---------------------------------------------------------------------------

#if defined(PICOBOOT_LOGGING) && (PICOBOOT_LOGGING == 1)

static void pbt_vlog(const char *level, const char *fmt, va_list ap) {
    fprintf(stderr, "      [%s] ", level);
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
}

void picoboot_debug(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    pbt_vlog("debug", fmt, ap);
    va_end(ap);
}

void picoboot_log(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    pbt_vlog("log", fmt, ap);
    va_end(ap);
}

void picoboot_error(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    pbt_vlog("error", fmt, ap);
    va_end(ap);
}

#endif // PICOBOOT_LOGGING

// ---------------------------------------------------------------------------
// Assertions
// ---------------------------------------------------------------------------

static unsigned s_scenario_failures;
static unsigned s_total_failures;

void pbt_fail(const char *file, int line, const char *fmt, ...) {
    s_scenario_failures++;
    s_total_failures++;

    // Report only the file's own name — the absolute path adds nothing and
    // differs between machines.
    const char *base = strrchr(file, '/');
    base = base != NULL ? base + 1 : file;

    fprintf(stderr, "    FAIL %s:%d: ", base, line);
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
}

bool pbt_failed(void) { return s_scenario_failures > 0; }

const char *pbt_status_name(int status) {
    switch (status) {
        case PB_STATUS_OK:                   return "OK";
        case PB_STATUS_UNKNOWN_CMD:          return "UNKNOWN_CMD";
        case PB_STATUS_INVALID_CMD_LENGTH:   return "INVALID_CMD_LENGTH";
        case PB_STATUS_INVALID_TRANSFER_LEN: return "INVALID_TRANSFER_LEN";
        case PB_STATUS_INVALID_ADDRESS:      return "INVALID_ADDRESS";
        case PB_STATUS_BAD_ALIGNMENT:        return "BAD_ALIGNMENT";
        case PB_STATUS_INTERLEAVED_WRITE:    return "INTERLEAVED_WRITE";
        case PB_STATUS_REBOOTING:            return "REBOOTING";
        case PB_STATUS_UNKNOWN_ERROR:        return "UNKNOWN_ERROR";
        case PB_STATUS_INVALID_STATE:        return "INVALID_STATE";
        case PB_STATUS_NOT_PERMITTED:        return "NOT_PERMITTED";
        case PB_STATUS_INVALID_ARG:          return "INVALID_ARG";
        case PB_STATUS_BUFFER_TOO_SMALL:     return "BUFFER_TOO_SMALL";
        case PB_STATUS_PRECONDITION_NOT_MET: return "PRECONDITION_NOT_MET";
        case PB_STATUS_MODIFIED_DATA:        return "MODIFIED_DATA";
        case PB_STATUS_INVALID_DATA:         return "INVALID_DATA";
        case PB_STATUS_NOT_FOUND:            return "NOT_FOUND";
        case PB_STATUS_UNSUPPORTED_MOD:      return "UNSUPPORTED_MOD";
        default:                             return "<not a status>";
    }
}

const char *pbt_state_name(pb_state_t state) {
    switch (state) {
        case PB_STATE_IDLE:
        case PB_STATE_DATA_OUT:
        case PB_STATE_DATA_IN:
        case PB_STATE_CUSTOM_IN:
        case PB_STATE_AWAIT_ZLP:
        case PB_STATE_AWAIT_ACK:
        case PB_STATE_STALLED:
            return pb_state_to_str[state];
        default:
            return "<not a state>";
    }
}

// ---------------------------------------------------------------------------
// Setting a scenario up
// ---------------------------------------------------------------------------

picoboot_ops_t        pbt_ops;
picoboot_custom_ops_t pbt_custom_ops;
bool                  pbt_use_custom;
bool                  pbt_use_flash_buf;

// The library's state block.  INTEGRATION.md tells an integrator to allocate
// PICOBOOT_STATE_SIZE bytes at four-byte alignment, and that constant is the
// device's, where a pointer is four bytes wide.  This process's pointers are
// wider, so the allocation is taken from sizeof and the constant is checked
// against the device layout by the assertion in picobootx_private.h.
// ---------------------------------------------------------------------------
// The runner
// ---------------------------------------------------------------------------

int main(int argc, char **argv) {
    // An argument selects the suites whose name contains it, for working on one
    // area without running the rest.
    const char *filter = argc > 1 ? argv[1] : NULL;

    unsigned scenarios_run    = 0;
    unsigned scenarios_failed = 0;

    printf("picobootx conformance suite, library version %s\n",
           PICOBOOTX_VERSION_STRING);

    for (unsigned i = 0; i < pbt_suite_count; i++) {
        const pbt_suite_t *suite = pbt_suites[i];
        if (filter != NULL && strstr(suite->name, filter) == NULL) {
            continue;
        }

        printf("\n%s\n", suite->name);

        for (unsigned j = 0; j < suite->count; j++) {
            const pbt_scenario_t *scenario = &suite->scenarios[j];

            s_scenario_failures = 0;
            scenario->fn();
            scenarios_run++;

            if (s_scenario_failures > 0) {
                scenarios_failed++;
                printf("  FAIL  %s\n", scenario->name);
                pbt_dump_log();
            } else {
                printf("  ok    %s\n", scenario->name);
            }
        }
    }

    printf("\n%u scenarios, %u failed, %u failed assertions\n", scenarios_run,
           scenarios_failed, s_total_failures);

    if (scenarios_run == 0) {
        fprintf(stderr, "no scenarios ran\n");
        return 2;
    }
    return scenarios_failed == 0 ? 0 : 1;
}
