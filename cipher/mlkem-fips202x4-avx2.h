#ifndef _GCRY_mlkem_AVX2_FIPS202X4_H
#define _GCRY_mlkem_AVX2_FIPS202X4_H

#ifdef __ASSEMBLER__
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

#else
#include <stddef.h>
#include <stdint.h>
#include <immintrin.h>
#include "config.h"
#include "types.h"

typedef struct
{
  __m256i s[25];
} gcry_mlkem_keccakx4_state;

void _gcry_mlkem_avx2_f1600x4 (__m256i *s, const u64 *rc);

void _gcry_mlkem_avx2_shake128x4_absorb_once (
    gcry_mlkem_keccakx4_state *state, const byte *in0, const byte *in1, const byte *in2, const byte *in3, size_t inlen);

void _gcry_mlkem_avx2_shake128x4_squeezeblocks (
    byte *out0, byte *out1, byte *out2, byte *out3, size_t nblocks, gcry_mlkem_keccakx4_state *state);

void _gcry_mlkem_avx2_shake256x4_absorb_once (
    gcry_mlkem_keccakx4_state *state, const byte *in0, const byte *in1, const byte *in2, const byte *in3, size_t inlen);

void _gcry_mlkem_avx2_shake256x4_squeezeblocks (
    byte *out0, byte *out1, byte *out2, byte *out3, size_t nblocks, gcry_mlkem_keccakx4_state *state);

#endif
#endif