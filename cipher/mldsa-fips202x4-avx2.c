#include <stddef.h>
#include <stdint.h>
#include <immintrin.h>
#include <string.h>
#include "config.h"
#include "types.h"
#include "mldsa-fips202x4-avx2.h"
#include "mldsa-symmetric.h"

/* Keccak round constants */
#define NROUNDS 24
const u64 KeccakF_RoundConstants[NROUNDS]
    = {(u64)0x0000000000000001ULL, (u64)0x0000000000008082ULL, (u64)0x800000000000808aULL, (u64)0x8000000080008000ULL,
       (u64)0x000000000000808bULL, (u64)0x0000000080000001ULL, (u64)0x8000000080008081ULL, (u64)0x8000000000008009ULL,
       (u64)0x000000000000008aULL, (u64)0x0000000000000088ULL, (u64)0x0000000080008009ULL, (u64)0x000000008000000aULL,
       (u64)0x000000008000808bULL, (u64)0x800000000000008bULL, (u64)0x8000000000008089ULL, (u64)0x8000000000008003ULL,
       (u64)0x8000000000008002ULL, (u64)0x8000000000000080ULL, (u64)0x000000000000800aULL, (u64)0x800000008000000aULL,
       (u64)0x8000000080008081ULL, (u64)0x8000000000008080ULL, (u64)0x0000000080000001ULL, (u64)0x8000000080008008ULL};

static void keccakx4_absorb_once(__m256i s[25],
                                 unsigned int r,
                                 const byte *in0,
                                 const byte *in1,
                                 const byte *in2,
                                 const byte *in3,
                                 size_t inlen,
                                 byte p)
{
  size_t i;
  u64 pos = 0;
  __m256i t, idx;

  for (i = 0; i < 25; ++i)
    s[i] = _mm256_setzero_si256();

  idx = _mm256_set_epi64x((long long)in3, (long long)in2, (long long)in1, (long long)in0);
  while (inlen >= r)
    {
      for (i = 0; i < r / 8; ++i)
        {
          t    = _mm256_i64gather_epi64((long long *)pos, idx, 1);
          s[i] = _mm256_xor_si256(s[i], t);
          pos += 8;
        }
      inlen -= r;

      _gcry_mldsa_avx2_f1600x4(s, KeccakF_RoundConstants);
    }

  for (i = 0; i < inlen / 8; ++i)
    {
      t    = _mm256_i64gather_epi64((long long *)pos, idx, 1);
      s[i] = _mm256_xor_si256(s[i], t);
      pos += 8;
    }
  inlen -= 8 * i;

  if (inlen)
    {
      t    = _mm256_i64gather_epi64((long long *)pos, idx, 1);
      idx  = _mm256_set1_epi64x((1ULL << (8 * inlen)) - 1);
      t    = _mm256_and_si256(t, idx);
      s[i] = _mm256_xor_si256(s[i], t);
    }

  t            = _mm256_set1_epi64x((u64)p << 8 * inlen);
  s[i]         = _mm256_xor_si256(s[i], t);
  t            = _mm256_set1_epi64x(1ULL << 63);
  s[r / 8 - 1] = _mm256_xor_si256(s[r / 8 - 1], t);
}

static void keccakx4_squeezeblocks(
    byte *out0, byte *out1, byte *out2, byte *out3, size_t nblocks, unsigned int r, __m256i s[25])
{
  unsigned int i;
  __m128d t;

  while (nblocks > 0)
    {
      _gcry_mldsa_avx2_f1600x4(s, KeccakF_RoundConstants);
      for (i = 0; i < r / 8; ++i)
        {
          t = _mm_castsi128_pd(_mm256_castsi256_si128(s[i]));
          _mm_storel_pd((__attribute__((__may_alias__)) double *)&out0[8 * i], t);
          _mm_storeh_pd((__attribute__((__may_alias__)) double *)&out1[8 * i], t);
          t = _mm_castsi128_pd(_mm256_extracti128_si256(s[i], 1));
          _mm_storel_pd((__attribute__((__may_alias__)) double *)&out2[8 * i], t);
          _mm_storeh_pd((__attribute__((__may_alias__)) double *)&out3[8 * i], t);
        }

      out0 += r;
      out1 += r;
      out2 += r;
      out3 += r;
      --nblocks;
    }
}

void _gcry_mldsa_avx2_shake128x4_absorb_once(
    gcry_mldsa_keccakx4_state *state, const byte *in0, const byte *in1, const byte *in2, const byte *in3, size_t inlen)
{
  keccakx4_absorb_once(state->s, GCRY_SHAKE128_RATE, in0, in1, in2, in3, inlen, 0x1F);
}

void _gcry_mldsa_avx2_shake128x4_squeezeblocks(
    byte *out0, byte *out1, byte *out2, byte *out3, size_t nblocks, gcry_mldsa_keccakx4_state *state)
{
  keccakx4_squeezeblocks(out0, out1, out2, out3, nblocks, GCRY_SHAKE128_RATE, state->s);
}

void _gcry_mldsa_avx2_shake256x4_absorb_once(
    gcry_mldsa_keccakx4_state *state, const byte *in0, const byte *in1, const byte *in2, const byte *in3, size_t inlen)
{
  keccakx4_absorb_once(state->s, GCRY_SHAKE256_RATE, in0, in1, in2, in3, inlen, 0x1F);
}

void _gcry_mldsa_avx2_shake256x4_squeezeblocks(
    byte *out0, byte *out1, byte *out2, byte *out3, size_t nblocks, gcry_mldsa_keccakx4_state *state)
{
  keccakx4_squeezeblocks(out0, out1, out2, out3, nblocks, GCRY_SHAKE256_RATE, state->s);
}