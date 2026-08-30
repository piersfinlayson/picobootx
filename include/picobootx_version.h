// Copyright (C) 2026 Piers Finlayson <piers@piers.rocks>
//
// MIT License

// picobootx's version, for integrators that need to compile against more than
// one release of it.
//
// This header has no dependencies of its own — not on a USB stack, not on the
// rest of picobootx — so it can be included on its own by build glue or by
// code that has to decide what to include next.

#if !defined(PICOBOOTX_VERSION_H)
#define PICOBOOTX_VERSION_H

#define PICOBOOTX_VERSION_MAJOR 0
#define PICOBOOTX_VERSION_MINOR 5
#define PICOBOOTX_VERSION_PATCH 1

#define PICOBOOTX_VERSION_STRING "0.5.1"

// Encodes a version as a single comparable integer, so an integrator can write
// #if PICOBOOTX_VERSION >= PICOBOOTX_VERSION_ENCODE(0, 2, 0)
#define PICOBOOTX_VERSION_ENCODE(major, minor, patch) \
    (((major) * 10000) + ((minor) * 100) + (patch))

#define PICOBOOTX_VERSION                    \
    PICOBOOTX_VERSION_ENCODE(                \
        PICOBOOTX_VERSION_MAJOR,             \
        PICOBOOTX_VERSION_MINOR,             \
        PICOBOOTX_VERSION_PATCH              \
    )

#endif // PICOBOOTX_VERSION_H
