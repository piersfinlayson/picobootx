// Copyright (C) 2026 Piers Finlayson <piers@piers.rocks>
//
// MIT License

// The core suite's scenario list.
//
// Separate from the runner so that the usb suite, which shares the runner and
// names a different set, does not have to carry these too.

#include "pbt.h"

const pbt_suite_t *const pbt_suites[] = {
    &pbt_suite_framing,
    &pbt_suite_stall,
    &pbt_suite_zlp,
    &pbt_suite_data_in,
    &pbt_suite_data_out,
    &pbt_suite_custom,
    &pbt_suite_transport,
    &pbt_suite_ops,
    &pbt_suite_bootrom,
    &pbt_suite_quirks,
};

const unsigned pbt_suite_count = sizeof(pbt_suites) / sizeof(pbt_suites[0]);
