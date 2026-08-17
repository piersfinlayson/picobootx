// Copyright (C) 2026 Piers Finlayson <piers@piers.rocks>
//
// MIT License

// The runner: walk the suites this binary was linked with, run every scenario,
// and report.  Both suites share it — which suites there are is decided by the
// pbt_suites table each one links, in pbt_suites.c and usbt_suites.c.
//
// The recording and assertion machinery it reports on is in pbt_core.c.

#include <stdio.h>
#include <string.h>

#include "pbt.h"

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

            pbt_fail_reset();
            scenario->fn();
            scenarios_run++;

            if (pbt_failed()) {
                scenarios_failed++;
                printf("  FAIL  %s\n", scenario->name);
                pbt_dump_log();
            } else {
                printf("  ok    %s\n", scenario->name);
            }
        }
    }

    printf("\n%u scenarios, %u failed, %u failed assertions\n", scenarios_run,
           scenarios_failed, pbt_fail_total());

    if (scenarios_run == 0) {
        fprintf(stderr, "no scenarios ran\n");
        return 2;
    }
    return scenarios_failed == 0 ? 0 : 1;
}
