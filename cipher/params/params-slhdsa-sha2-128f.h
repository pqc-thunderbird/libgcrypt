#ifndef SLHDSA_PARAMS_H
#define SLHDSA_PARAMS_H

/* Hash output length in bytes. */
#define SLHDSA_N 16
/* Height of the hypertree. */
#define SLHDSA_FULL_HEIGHT 66
/* Number of subtree layer. */
#define SLHDSA_D 22
/* FORS tree dimensions. */
#define SLHDSA_FORS_HEIGHT 6
#define SLHDSA_FORS_TREES 33
/* Winternitz parameter, */
#define SLHDSA_WOTS_W 16

/* The hash function is defined by linking a different hash.c file, as opposed
   to setting a #define constant. */

/* This is a SHA2-based parameter set, hence whether we use SHA-256
 * exclusively or we use both SHA-256 and SHA-512 is controlled by
 * the following #define */
#define SLHDSA_SHA512 0  /* Use SHA-256 for all hashes */

/* For clarity */
#define SLHDSA_ADDR_BYTES 32

/* WOTS parameters. */
#if SLHDSA_WOTS_W == 256
    #define SLHDSA_WOTS_LOGW 8
#elif SLHDSA_WOTS_W == 16
    #define SLHDSA_WOTS_LOGW 4
#else
    #error SLHDSA_WOTS_W assumed 16 or 256
#endif

#define SLHDSA_WOTS_LEN1 (8 * SLHDSA_N / SLHDSA_WOTS_LOGW)

/* SLHDSA_WOTS_LEN2 is floor(log(len_1 * (w - 1)) / log(w)) + 1; we precompute */
#if SLHDSA_WOTS_W == 256
    #if SLHDSA_N <= 1
        #define SLHDSA_WOTS_LEN2 1
    #elif SLHDSA_N <= 256
        #define SLHDSA_WOTS_LEN2 2
    #else
        #error Did not precompute SLHDSA_WOTS_LEN2 for n outside {2, .., 256}
    #endif
#elif SLHDSA_WOTS_W == 16
    #if SLHDSA_N <= 8
        #define SLHDSA_WOTS_LEN2 2
    #elif SLHDSA_N <= 136
        #define SLHDSA_WOTS_LEN2 3
    #elif SLHDSA_N <= 256
        #define SLHDSA_WOTS_LEN2 4
    #else
        #error Did not precompute SLHDSA_WOTS_LEN2 for n outside {2, .., 256}
    #endif
#endif

#define SLHDSA_WOTS_LEN (SLHDSA_WOTS_LEN1 + SLHDSA_WOTS_LEN2)
#define SLHDSA_WOTS_BYTES (SLHDSA_WOTS_LEN * SLHDSA_N)
#define SLHDSA_WOTS_PK_BYTES SLHDSA_WOTS_BYTES

/* Subtree size. */
#define SLHDSA_TREE_HEIGHT (SLHDSA_FULL_HEIGHT / SLHDSA_D)

#if SLHDSA_TREE_HEIGHT * SLHDSA_D != SLHDSA_FULL_HEIGHT
    #error SLHDSA_D should always divide SLHDSA_FULL_HEIGHT
#endif

/* FORS parameters. */
#define SLHDSA_FORS_MSG_BYTES ((SLHDSA_FORS_HEIGHT * SLHDSA_FORS_TREES + 7) / 8)
#define SLHDSA_FORS_BYTES ((SLHDSA_FORS_HEIGHT + 1) * SLHDSA_FORS_TREES * SLHDSA_N)
#define SLHDSA_FORS_PK_BYTES SLHDSA_N

/* Resulting SLHDSA sizes. */
#define SLHDSA_BYTES (SLHDSA_N + SLHDSA_FORS_BYTES + SLHDSA_D * SLHDSA_WOTS_BYTES +\
                   SLHDSA_FULL_HEIGHT * SLHDSA_N)
#define SLHDSA_PK_BYTES (2 * SLHDSA_N)
#define SLHDSA_SK_BYTES (2 * SLHDSA_N + SLHDSA_PK_BYTES)

#include "../slhdsa-sha2_offsets.h"

#endif
