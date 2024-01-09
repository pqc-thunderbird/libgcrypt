#ifndef _GCRY_MLDSA_AVX2_CONSTS_H
#define _GCRY_MLDSA_AVX2_CONSTS_H

#define _8XQ 0
#define _8XQINV 8
#define _8XDIV_QINV 16
#define _8XDIV 24
#define _ZETAS_QINV 32
#define _ZETAS 328

/* The C ABI on MacOS exports all symbols with a leading
 * underscore. This means that any symbols we refer to from
 * C files (functions) can't be found, and all symbols we
 * refer to from ASM also can't be found.
 *
 * This define helps us get around this
 */
#if defined(__WIN32__) || defined(__APPLE__)
#define decorate(s) _##s
#define _cdecl(s) decorate (s)
#define cdecl(s) _cdecl(s)
#else
#define cdecl(s) s
#endif

#ifndef __ASSEMBLER__

#include <immintrin.h>
typedef union
{
  s32 coeffs[624];
  __m256i vec[(624 + 7) / 8];
} qdata_t;

extern const qdata_t qdata;

#endif
#endif
