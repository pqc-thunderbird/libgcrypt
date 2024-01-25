#ifndef _GCRY_IMMINTRIN_SUPPORT_H
#define _GCRY_IMMINTRIN_SUPPORT_H

#include "config.h"

/* USE_AVX2 indicates whether to compile with Intel AVX2 code. */
#undef USE_AVX2
#if defined(ENABLE_AVX2_SUPPORT) && defined(__x86_64__)                       \
    && defined(HAVE_IMMINTRIN_H)                                              \
    && (defined(HAVE_COMPATIBLE_GCC_AMD64_PLATFORM_AS)                        \
        || defined(HAVE_COMPATIBLE_GCC_WIN64_PLATFORM_AS))
#define USE_AVX2 1
#endif
#endif