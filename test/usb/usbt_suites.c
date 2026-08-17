// Copyright (C) 2026 Piers Finlayson <piers@piers.rocks>
//
// MIT License

// The usb suite's scenario list.  The runner is shared with the core suite —
// see pbt_suites.c, which names that one's.

#include "pbt.h"
#include "usbt.h"

const pbt_suite_t *const pbt_suites[] = {
    &usbt_suite_enumeration,
    &usbt_suite_vendor,
};

const unsigned pbt_suite_count = sizeof(pbt_suites) / sizeof(pbt_suites[0]);
