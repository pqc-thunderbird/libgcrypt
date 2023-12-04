#ifndef ALIGN_H
#define ALIGN_H

#include <stdint.h>
#include <immintrin.h>

#define ALIGNED_UINT8(GCRY_MLDSA_N)        \
    union {                     \
        uint8_t coeffs[GCRY_MLDSA_N];      \
        __m256i vec[(GCRY_MLDSA_N+31)/32]; \
    }

#define ALIGNED_INT32(GCRY_MLDSA_N)        \
    union {                     \
        int32_t coeffs[GCRY_MLDSA_N];      \
        __m256i vec[(GCRY_MLDSA_N+7)/8];   \
    }

#endif
