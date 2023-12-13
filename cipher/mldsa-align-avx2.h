#ifndef ALIGN_H
#define ALIGN_H

#include <stdint.h>
#include <immintrin.h>

#define ALIGNED_INT32(GCRY_MLDSA_N)        \
    union {                     \
        s32 coeffs[GCRY_MLDSA_N];      \
        __m256i vec[(GCRY_MLDSA_N+7)/8];   \
    }

#endif
