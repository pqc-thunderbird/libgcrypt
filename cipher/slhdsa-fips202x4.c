/* slhdsa-fips202x4.c
 * Copyright (C) 2024 MTG AG
 * The code was created based on the reference implementation that is part of the ML-DSA NIST submission.
 *
 * This file is part of Libgcrypt.
 *
 * Libgcrypt is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * Libgcrypt is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include "slhdsa-fips202x4.h"
#include "slhdsa-utils.h"

#ifdef USE_AVX2
#include <immintrin.h>
#include <stdint.h>
#include <assert.h>

#define SHAKE128_RATE 168
#define SHAKE256_RATE 136
#define SHA3_256_RATE 136
#define SHA3_512_RATE 72

#define NROUNDS 24
#define ROL(a, offset) ((a << offset) ^ (a >> (64 - offset)))

static u64 load64 (const byte *x)
{
  unsigned long long r = 0, i;

  for (i = 0; i < 8; ++i)
    {
      r |= (unsigned long long)x[i] << 8 * i;
    }
  return r;
}

static void store64 (byte *x, u64 u)
{
  unsigned int i;

  for (i = 0; i < 8; ++i)
    {
      x[i] = u;
      u >>= 8;
    }
}

static void keccak_absorb4x (__m256i *s,
                             unsigned int r,
                             const byte *m0,
                             const byte *m1,
                             const byte *m2,
                             const byte *m3,
                             unsigned long long int mlen,
                             byte p)
{
  unsigned long long i;
  byte t0[200];
  byte t1[200];
  byte t2[200];
  byte t3[200];

  unsigned long long *ss = (unsigned long long *)s;


  while (mlen >= r)
    {
      for (i = 0; i < r / 8; ++i)
        {
          ss[4 * i + 0] ^= load64 (m0 + 8 * i);
          ss[4 * i + 1] ^= load64 (m1 + 8 * i);
          ss[4 * i + 2] ^= load64 (m2 + 8 * i);
          ss[4 * i + 3] ^= load64 (m3 + 8 * i);
        }

      _gcry_slhdsa_KeccakP1600times4_PermuteAll_24rounds (s);
      mlen -= r;
      m0 += r;
      m1 += r;
      m2 += r;
      m3 += r;
    }

  for (i = 0; i < r; ++i)
    {
      t0[i] = 0;
      t1[i] = 0;
      t2[i] = 0;
      t3[i] = 0;
    }
  for (i = 0; i < mlen; ++i)
    {
      t0[i] = m0[i];
      t1[i] = m1[i];
      t2[i] = m2[i];
      t3[i] = m3[i];
    }

  t0[i] = p;
  t1[i] = p;
  t2[i] = p;
  t3[i] = p;

  t0[r - 1] |= 128;
  t1[r - 1] |= 128;
  t2[r - 1] |= 128;
  t3[r - 1] |= 128;

  for (i = 0; i < r / 8; ++i)
    {
      ss[4 * i + 0] ^= load64 (t0 + 8 * i);
      ss[4 * i + 1] ^= load64 (t1 + 8 * i);
      ss[4 * i + 2] ^= load64 (t2 + 8 * i);
      ss[4 * i + 3] ^= load64 (t3 + 8 * i);
    }
}


static void keccak_squeezeblocks4x (
    byte *h0, byte *h1, byte *h2, byte *h3, unsigned long long int nblocks, __m256i *s, unsigned int r)
{
  unsigned int i;

  unsigned long long *ss = (unsigned long long *)s;

  while (nblocks > 0)
    {
      _gcry_slhdsa_KeccakP1600times4_PermuteAll_24rounds (s);
      for (i = 0; i < (r >> 3); i++)
        {
          store64 (h0 + 8 * i, ss[4 * i + 0]);
          store64 (h1 + 8 * i, ss[4 * i + 1]);
          store64 (h2 + 8 * i, ss[4 * i + 2]);
          store64 (h3 + 8 * i, ss[4 * i + 3]);
        }
      h0 += r;
      h1 += r;
      h2 += r;
      h3 += r;
      nblocks--;
    }
}

gcry_err_code_t _gcry_slhdsa_shake256x4 (byte *out0,
                                         byte *out1,
                                         byte *out2,
                                         byte *out3,
                                         unsigned long long outlen,
                                         byte *in0,
                                         byte *in1,
                                         byte *in2,
                                         byte *in3,
                                         unsigned long long inlen)
{
  gcry_err_code_t ec             = 0;
  gcry_slhdsa_buf_al state_alloc = {};
  __m256i *s                     = NULL;

  byte t0[SHAKE256_RATE];
  byte t1[SHAKE256_RATE];
  byte t2[SHAKE256_RATE];
  byte t3[SHAKE256_RATE];
  unsigned int i;

  /* we need 32-byte aligned state */
  ec = _gcry_mldsa_buf_al_create (&state_alloc, sizeof (__m256i[25]));
  if (ec)
    {
      goto leave;
    }
  s = (__m256i *)state_alloc.buf;

  /* zero state */
  for (i = 0; i < 25; i++)
    s[i] = _mm256_xor_si256 (s[i], s[i]);

  /* absorb 4 message of identical length in parallel */
  keccak_absorb4x (s, SHAKE256_RATE, in0, in1, in2, in3, inlen, 0x1F);

  /* Squeeze output */
  keccak_squeezeblocks4x (out0, out1, out2, out3, outlen / SHAKE256_RATE, s, SHAKE256_RATE);

  out0 += (outlen / SHAKE256_RATE) * SHAKE256_RATE;
  out1 += (outlen / SHAKE256_RATE) * SHAKE256_RATE;
  out2 += (outlen / SHAKE256_RATE) * SHAKE256_RATE;
  out3 += (outlen / SHAKE256_RATE) * SHAKE256_RATE;

  if (outlen % SHAKE256_RATE)
    {
      keccak_squeezeblocks4x (t0, t1, t2, t3, 1, s, SHAKE256_RATE);
      for (i = 0; i < outlen % SHAKE256_RATE; i++)
        {
          out0[i] = t0[i];
          out1[i] = t1[i];
          out2[i] = t2[i];
          out3[i] = t3[i];
        }
    }
leave:
  _gcry_mldsa_buf_al_destroy (&state_alloc);
  return ec;
}

typedef unsigned long long int UINT64;

/* on Mac OS-X and possibly others, ALIGN(x) is defined in param.h, and -Werror chokes on the redef. */
#ifdef ALIGN
#undef ALIGN
#endif

#if defined(__GNUC__)
#define ALIGN(x) __attribute__ ((aligned (x)))
#elif defined(_MSC_VER)
#define ALIGN(x) __declspec(align (x))
#elif defined(__ARMCC_VERSION)
#define ALIGN(x) __align (x)
#else
#define ALIGN(x)
#endif

#define KeccakP1600times4_statesAlignment 32

static ALIGN (KeccakP1600times4_statesAlignment) const UINT64 KeccakF1600RoundConstants[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL, 0x8000000080008000ULL, 0x000000000000808bULL,
    0x0000000080000001ULL, 0x8000000080008081ULL, 0x8000000000008009ULL, 0x000000000000008aULL, 0x0000000000000088ULL,
    0x0000000080008009ULL, 0x000000008000000aULL, 0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL,
    0x8000000000008003ULL, 0x8000000000008002ULL, 0x8000000000000080ULL, 0x000000000000800aULL, 0x800000008000000aULL,
    0x8000000080008081ULL, 0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL};


#define ANDnu256(a, b) _mm256_andnot_si256 (a, b)
#define CONST256(a) _mm256_load_si256 ((const __m256i *)&(a))
#define CONST256_64(a) (__m256i) _mm256_broadcast_sd ((const double *)(&a))
#define LOAD256(a) _mm256_load_si256 ((const __m256i *)&(a))
#define LOAD256u(a) _mm256_loadu_si256 ((const __m256i *)&(a))
#define LOAD4_64(a, b, c, d) _mm256_set_epi64x ((UINT64)(a), (UINT64)(b), (UINT64)(c), (UINT64)(d))
#define ROL64in256(d, a, o) d = _mm256_or_si256 (_mm256_slli_epi64 (a, o), _mm256_srli_epi64 (a, 64 - (o)))
#define ROL64in256_8(d, a) d = _mm256_shuffle_epi8 (a, CONST256 (rho8))
#define ROL64in256_56(d, a) d = _mm256_shuffle_epi8 (a, CONST256 (rho56))
static const UINT64 rho8[4]  = {0x0605040302010007, 0x0E0D0C0B0A09080F, 0x1615141312111017, 0x1E1D1C1B1A19181F};
static const UINT64 rho56[4] = {0x0007060504030201, 0x080F0E0D0C0B0A09, 0x1017161514131211, 0x181F1E1D1C1B1A19};
#define STORE256(a, b) _mm256_store_si256 ((__m256i *)&(a), b)
#define STORE256u(a, b) _mm256_storeu_si256 ((__m256i *)&(a), b)
#define STORE2_128(ah, al, v) _mm256_storeu2_m128d ((V128 *)&(ah), (V128 *)&(al), v)
#define XOR256(a, b) _mm256_xor_si256 (a, b)
#define XOReq256(a, b) a = _mm256_xor_si256 (a, b)
#define UNPACKL(a, b) _mm256_unpacklo_epi64 ((a), (b))
#define UNPACKH(a, b) _mm256_unpackhi_epi64 ((a), (b))
#define PERM128(a, b, c) (__m256i) _mm256_permute2f128_ps ((__m256)(a), (__m256)(b), c)
#define SHUFFLE64(a, b, c) (__m256i) _mm256_shuffle_pd ((__m256d)(a), (__m256d)(b), c)

#define copyFromState(X, state)                                                                                        \
  X##ba = LOAD256 (state[0]);                                                                                          \
  X##be = LOAD256 (state[1]);                                                                                          \
  X##bi = LOAD256 (state[2]);                                                                                          \
  X##bo = LOAD256 (state[3]);                                                                                          \
  X##bu = LOAD256 (state[4]);                                                                                          \
  X##ga = LOAD256 (state[5]);                                                                                          \
  X##ge = LOAD256 (state[6]);                                                                                          \
  X##gi = LOAD256 (state[7]);                                                                                          \
  X##go = LOAD256 (state[8]);                                                                                          \
  X##gu = LOAD256 (state[9]);                                                                                          \
  X##ka = LOAD256 (state[10]);                                                                                         \
  X##ke = LOAD256 (state[11]);                                                                                         \
  X##ki = LOAD256 (state[12]);                                                                                         \
  X##ko = LOAD256 (state[13]);                                                                                         \
  X##ku = LOAD256 (state[14]);                                                                                         \
  X##ma = LOAD256 (state[15]);                                                                                         \
  X##me = LOAD256 (state[16]);                                                                                         \
  X##mi = LOAD256 (state[17]);                                                                                         \
  X##mo = LOAD256 (state[18]);                                                                                         \
  X##mu = LOAD256 (state[19]);                                                                                         \
  X##sa = LOAD256 (state[20]);                                                                                         \
  X##se = LOAD256 (state[21]);                                                                                         \
  X##si = LOAD256 (state[22]);                                                                                         \
  X##so = LOAD256 (state[23]);                                                                                         \
  X##su = LOAD256 (state[24]);

#define copyToState(state, X)                                                                                          \
  STORE256 (state[0], X##ba);                                                                                          \
  STORE256 (state[1], X##be);                                                                                          \
  STORE256 (state[2], X##bi);                                                                                          \
  STORE256 (state[3], X##bo);                                                                                          \
  STORE256 (state[4], X##bu);                                                                                          \
  STORE256 (state[5], X##ga);                                                                                          \
  STORE256 (state[6], X##ge);                                                                                          \
  STORE256 (state[7], X##gi);                                                                                          \
  STORE256 (state[8], X##go);                                                                                          \
  STORE256 (state[9], X##gu);                                                                                          \
  STORE256 (state[10], X##ka);                                                                                         \
  STORE256 (state[11], X##ke);                                                                                         \
  STORE256 (state[12], X##ki);                                                                                         \
  STORE256 (state[13], X##ko);                                                                                         \
  STORE256 (state[14], X##ku);                                                                                         \
  STORE256 (state[15], X##ma);                                                                                         \
  STORE256 (state[16], X##me);                                                                                         \
  STORE256 (state[17], X##mi);                                                                                         \
  STORE256 (state[18], X##mo);                                                                                         \
  STORE256 (state[19], X##mu);                                                                                         \
  STORE256 (state[20], X##sa);                                                                                         \
  STORE256 (state[21], X##se);                                                                                         \
  STORE256 (state[22], X##si);                                                                                         \
  STORE256 (state[23], X##so);                                                                                         \
  STORE256 (state[24], X##su);

#define prepareTheta                                                                                                   \
  Ca = XOR256 (Aba, XOR256 (Aga, XOR256 (Aka, XOR256 (Ama, Asa))));                                                    \
  Ce = XOR256 (Abe, XOR256 (Age, XOR256 (Ake, XOR256 (Ame, Ase))));                                                    \
  Ci = XOR256 (Abi, XOR256 (Agi, XOR256 (Aki, XOR256 (Ami, Asi))));                                                    \
  Co = XOR256 (Abo, XOR256 (Ago, XOR256 (Ako, XOR256 (Amo, Aso))));                                                    \
  Cu = XOR256 (Abu, XOR256 (Agu, XOR256 (Aku, XOR256 (Amu, Asu))));


#define thetaRhoPiChiIotaPrepareTheta(i, A, E)                                                                         \
  ROL64in256 (Ce1, Ce, 1);                                                                                             \
  Da = XOR256 (Cu, Ce1);                                                                                               \
  ROL64in256 (Ci1, Ci, 1);                                                                                             \
  De = XOR256 (Ca, Ci1);                                                                                               \
  ROL64in256 (Co1, Co, 1);                                                                                             \
  Di = XOR256 (Ce, Co1);                                                                                               \
  ROL64in256 (Cu1, Cu, 1);                                                                                             \
  Do = XOR256 (Ci, Cu1);                                                                                               \
  ROL64in256 (Ca1, Ca, 1);                                                                                             \
  Du = XOR256 (Co, Ca1);                                                                                               \
                                                                                                                       \
  XOReq256 (A##ba, Da);                                                                                                \
  Bba = A##ba;                                                                                                         \
  XOReq256 (A##ge, De);                                                                                                \
  ROL64in256 (Bbe, A##ge, 44);                                                                                         \
  XOReq256 (A##ki, Di);                                                                                                \
  ROL64in256 (Bbi, A##ki, 43);                                                                                         \
  E##ba = XOR256 (Bba, ANDnu256 (Bbe, Bbi));                                                                           \
  XOReq256 (E##ba, CONST256_64 (KeccakF1600RoundConstants[i]));                                                        \
  Ca = E##ba;                                                                                                          \
  XOReq256 (A##mo, Do);                                                                                                \
  ROL64in256 (Bbo, A##mo, 21);                                                                                         \
  E##be = XOR256 (Bbe, ANDnu256 (Bbi, Bbo));                                                                           \
  Ce    = E##be;                                                                                                       \
  XOReq256 (A##su, Du);                                                                                                \
  ROL64in256 (Bbu, A##su, 14);                                                                                         \
  E##bi = XOR256 (Bbi, ANDnu256 (Bbo, Bbu));                                                                           \
  Ci    = E##bi;                                                                                                       \
  E##bo = XOR256 (Bbo, ANDnu256 (Bbu, Bba));                                                                           \
  Co    = E##bo;                                                                                                       \
  E##bu = XOR256 (Bbu, ANDnu256 (Bba, Bbe));                                                                           \
  Cu    = E##bu;                                                                                                       \
                                                                                                                       \
  XOReq256 (A##bo, Do);                                                                                                \
  ROL64in256 (Bga, A##bo, 28);                                                                                         \
  XOReq256 (A##gu, Du);                                                                                                \
  ROL64in256 (Bge, A##gu, 20);                                                                                         \
  XOReq256 (A##ka, Da);                                                                                                \
  ROL64in256 (Bgi, A##ka, 3);                                                                                          \
  E##ga = XOR256 (Bga, ANDnu256 (Bge, Bgi));                                                                           \
  XOReq256 (Ca, E##ga);                                                                                                \
  XOReq256 (A##me, De);                                                                                                \
  ROL64in256 (Bgo, A##me, 45);                                                                                         \
  E##ge = XOR256 (Bge, ANDnu256 (Bgi, Bgo));                                                                           \
  XOReq256 (Ce, E##ge);                                                                                                \
  XOReq256 (A##si, Di);                                                                                                \
  ROL64in256 (Bgu, A##si, 61);                                                                                         \
  E##gi = XOR256 (Bgi, ANDnu256 (Bgo, Bgu));                                                                           \
  XOReq256 (Ci, E##gi);                                                                                                \
  E##go = XOR256 (Bgo, ANDnu256 (Bgu, Bga));                                                                           \
  XOReq256 (Co, E##go);                                                                                                \
  E##gu = XOR256 (Bgu, ANDnu256 (Bga, Bge));                                                                           \
  XOReq256 (Cu, E##gu);                                                                                                \
                                                                                                                       \
  XOReq256 (A##be, De);                                                                                                \
  ROL64in256 (Bka, A##be, 1);                                                                                          \
  XOReq256 (A##gi, Di);                                                                                                \
  ROL64in256 (Bke, A##gi, 6);                                                                                          \
  XOReq256 (A##ko, Do);                                                                                                \
  ROL64in256 (Bki, A##ko, 25);                                                                                         \
  E##ka = XOR256 (Bka, ANDnu256 (Bke, Bki));                                                                           \
  XOReq256 (Ca, E##ka);                                                                                                \
  XOReq256 (A##mu, Du);                                                                                                \
  ROL64in256_8 (Bko, A##mu);                                                                                           \
  E##ke = XOR256 (Bke, ANDnu256 (Bki, Bko));                                                                           \
  XOReq256 (Ce, E##ke);                                                                                                \
  XOReq256 (A##sa, Da);                                                                                                \
  ROL64in256 (Bku, A##sa, 18);                                                                                         \
  E##ki = XOR256 (Bki, ANDnu256 (Bko, Bku));                                                                           \
  XOReq256 (Ci, E##ki);                                                                                                \
  E##ko = XOR256 (Bko, ANDnu256 (Bku, Bka));                                                                           \
  XOReq256 (Co, E##ko);                                                                                                \
  E##ku = XOR256 (Bku, ANDnu256 (Bka, Bke));                                                                           \
  XOReq256 (Cu, E##ku);                                                                                                \
                                                                                                                       \
  XOReq256 (A##bu, Du);                                                                                                \
  ROL64in256 (Bma, A##bu, 27);                                                                                         \
  XOReq256 (A##ga, Da);                                                                                                \
  ROL64in256 (Bme, A##ga, 36);                                                                                         \
  XOReq256 (A##ke, De);                                                                                                \
  ROL64in256 (Bmi, A##ke, 10);                                                                                         \
  E##ma = XOR256 (Bma, ANDnu256 (Bme, Bmi));                                                                           \
  XOReq256 (Ca, E##ma);                                                                                                \
  XOReq256 (A##mi, Di);                                                                                                \
  ROL64in256 (Bmo, A##mi, 15);                                                                                         \
  E##me = XOR256 (Bme, ANDnu256 (Bmi, Bmo));                                                                           \
  XOReq256 (Ce, E##me);                                                                                                \
  XOReq256 (A##so, Do);                                                                                                \
  ROL64in256_56 (Bmu, A##so);                                                                                          \
  E##mi = XOR256 (Bmi, ANDnu256 (Bmo, Bmu));                                                                           \
  XOReq256 (Ci, E##mi);                                                                                                \
  E##mo = XOR256 (Bmo, ANDnu256 (Bmu, Bma));                                                                           \
  XOReq256 (Co, E##mo);                                                                                                \
  E##mu = XOR256 (Bmu, ANDnu256 (Bma, Bme));                                                                           \
  XOReq256 (Cu, E##mu);                                                                                                \
                                                                                                                       \
  XOReq256 (A##bi, Di);                                                                                                \
  ROL64in256 (Bsa, A##bi, 62);                                                                                         \
  XOReq256 (A##go, Do);                                                                                                \
  ROL64in256 (Bse, A##go, 55);                                                                                         \
  XOReq256 (A##ku, Du);                                                                                                \
  ROL64in256 (Bsi, A##ku, 39);                                                                                         \
  E##sa = XOR256 (Bsa, ANDnu256 (Bse, Bsi));                                                                           \
  XOReq256 (Ca, E##sa);                                                                                                \
  XOReq256 (A##ma, Da);                                                                                                \
  ROL64in256 (Bso, A##ma, 41);                                                                                         \
  E##se = XOR256 (Bse, ANDnu256 (Bsi, Bso));                                                                           \
  XOReq256 (Ce, E##se);                                                                                                \
  XOReq256 (A##se, De);                                                                                                \
  ROL64in256 (Bsu, A##se, 2);                                                                                          \
  E##si = XOR256 (Bsi, ANDnu256 (Bso, Bsu));                                                                           \
  XOReq256 (Ci, E##si);                                                                                                \
  E##so = XOR256 (Bso, ANDnu256 (Bsu, Bsa));                                                                           \
  XOReq256 (Co, E##so);                                                                                                \
  E##su = XOR256 (Bsu, ANDnu256 (Bsa, Bse));                                                                           \
  XOReq256 (Cu, E##su);


#define thetaRhoPiChiIota(i, A, E)                                                                                     \
  ROL64in256 (Ce1, Ce, 1);                                                                                             \
  Da = XOR256 (Cu, Ce1);                                                                                               \
  ROL64in256 (Ci1, Ci, 1);                                                                                             \
  De = XOR256 (Ca, Ci1);                                                                                               \
  ROL64in256 (Co1, Co, 1);                                                                                             \
  Di = XOR256 (Ce, Co1);                                                                                               \
  ROL64in256 (Cu1, Cu, 1);                                                                                             \
  Do = XOR256 (Ci, Cu1);                                                                                               \
  ROL64in256 (Ca1, Ca, 1);                                                                                             \
  Du = XOR256 (Co, Ca1);                                                                                               \
                                                                                                                       \
  XOReq256 (A##ba, Da);                                                                                                \
  Bba = A##ba;                                                                                                         \
  XOReq256 (A##ge, De);                                                                                                \
  ROL64in256 (Bbe, A##ge, 44);                                                                                         \
  XOReq256 (A##ki, Di);                                                                                                \
  ROL64in256 (Bbi, A##ki, 43);                                                                                         \
  E##ba = XOR256 (Bba, ANDnu256 (Bbe, Bbi));                                                                           \
  XOReq256 (E##ba, CONST256_64 (KeccakF1600RoundConstants[i]));                                                        \
  XOReq256 (A##mo, Do);                                                                                                \
  ROL64in256 (Bbo, A##mo, 21);                                                                                         \
  E##be = XOR256 (Bbe, ANDnu256 (Bbi, Bbo));                                                                           \
  XOReq256 (A##su, Du);                                                                                                \
  ROL64in256 (Bbu, A##su, 14);                                                                                         \
  E##bi = XOR256 (Bbi, ANDnu256 (Bbo, Bbu));                                                                           \
  E##bo = XOR256 (Bbo, ANDnu256 (Bbu, Bba));                                                                           \
  E##bu = XOR256 (Bbu, ANDnu256 (Bba, Bbe));                                                                           \
                                                                                                                       \
  XOReq256 (A##bo, Do);                                                                                                \
  ROL64in256 (Bga, A##bo, 28);                                                                                         \
  XOReq256 (A##gu, Du);                                                                                                \
  ROL64in256 (Bge, A##gu, 20);                                                                                         \
  XOReq256 (A##ka, Da);                                                                                                \
  ROL64in256 (Bgi, A##ka, 3);                                                                                          \
  E##ga = XOR256 (Bga, ANDnu256 (Bge, Bgi));                                                                           \
  XOReq256 (A##me, De);                                                                                                \
  ROL64in256 (Bgo, A##me, 45);                                                                                         \
  E##ge = XOR256 (Bge, ANDnu256 (Bgi, Bgo));                                                                           \
  XOReq256 (A##si, Di);                                                                                                \
  ROL64in256 (Bgu, A##si, 61);                                                                                         \
  E##gi = XOR256 (Bgi, ANDnu256 (Bgo, Bgu));                                                                           \
  E##go = XOR256 (Bgo, ANDnu256 (Bgu, Bga));                                                                           \
  E##gu = XOR256 (Bgu, ANDnu256 (Bga, Bge));                                                                           \
                                                                                                                       \
  XOReq256 (A##be, De);                                                                                                \
  ROL64in256 (Bka, A##be, 1);                                                                                          \
  XOReq256 (A##gi, Di);                                                                                                \
  ROL64in256 (Bke, A##gi, 6);                                                                                          \
  XOReq256 (A##ko, Do);                                                                                                \
  ROL64in256 (Bki, A##ko, 25);                                                                                         \
  E##ka = XOR256 (Bka, ANDnu256 (Bke, Bki));                                                                           \
  XOReq256 (A##mu, Du);                                                                                                \
  ROL64in256_8 (Bko, A##mu);                                                                                           \
  E##ke = XOR256 (Bke, ANDnu256 (Bki, Bko));                                                                           \
  XOReq256 (A##sa, Da);                                                                                                \
  ROL64in256 (Bku, A##sa, 18);                                                                                         \
  E##ki = XOR256 (Bki, ANDnu256 (Bko, Bku));                                                                           \
  E##ko = XOR256 (Bko, ANDnu256 (Bku, Bka));                                                                           \
  E##ku = XOR256 (Bku, ANDnu256 (Bka, Bke));                                                                           \
                                                                                                                       \
  XOReq256 (A##bu, Du);                                                                                                \
  ROL64in256 (Bma, A##bu, 27);                                                                                         \
  XOReq256 (A##ga, Da);                                                                                                \
  ROL64in256 (Bme, A##ga, 36);                                                                                         \
  XOReq256 (A##ke, De);                                                                                                \
  ROL64in256 (Bmi, A##ke, 10);                                                                                         \
  E##ma = XOR256 (Bma, ANDnu256 (Bme, Bmi));                                                                           \
  XOReq256 (A##mi, Di);                                                                                                \
  ROL64in256 (Bmo, A##mi, 15);                                                                                         \
  E##me = XOR256 (Bme, ANDnu256 (Bmi, Bmo));                                                                           \
  XOReq256 (A##so, Do);                                                                                                \
  ROL64in256_56 (Bmu, A##so);                                                                                          \
  E##mi = XOR256 (Bmi, ANDnu256 (Bmo, Bmu));                                                                           \
  E##mo = XOR256 (Bmo, ANDnu256 (Bmu, Bma));                                                                           \
  E##mu = XOR256 (Bmu, ANDnu256 (Bma, Bme));                                                                           \
                                                                                                                       \
  XOReq256 (A##bi, Di);                                                                                                \
  ROL64in256 (Bsa, A##bi, 62);                                                                                         \
  XOReq256 (A##go, Do);                                                                                                \
  ROL64in256 (Bse, A##go, 55);                                                                                         \
  XOReq256 (A##ku, Du);                                                                                                \
  ROL64in256 (Bsi, A##ku, 39);                                                                                         \
  E##sa = XOR256 (Bsa, ANDnu256 (Bse, Bsi));                                                                           \
  XOReq256 (A##ma, Da);                                                                                                \
  ROL64in256 (Bso, A##ma, 41);                                                                                         \
  E##se = XOR256 (Bse, ANDnu256 (Bsi, Bso));                                                                           \
  XOReq256 (A##se, De);                                                                                                \
  ROL64in256 (Bsu, A##se, 2);                                                                                          \
  E##si = XOR256 (Bsi, ANDnu256 (Bso, Bsu));                                                                           \
  E##so = XOR256 (Bso, ANDnu256 (Bsu, Bsa));                                                                           \
  E##su = XOR256 (Bsu, ANDnu256 (Bsa, Bse));


#define rounds24                                                                                                       \
  prepareTheta thetaRhoPiChiIotaPrepareTheta (0, A, E) thetaRhoPiChiIotaPrepareTheta (1, E, A)                         \
      thetaRhoPiChiIotaPrepareTheta (2, A, E) thetaRhoPiChiIotaPrepareTheta (3, E, A) thetaRhoPiChiIotaPrepareTheta (  \
          4, A, E) thetaRhoPiChiIotaPrepareTheta (5, E, A) thetaRhoPiChiIotaPrepareTheta (6, A, E)                     \
          thetaRhoPiChiIotaPrepareTheta (7, E, A) thetaRhoPiChiIotaPrepareTheta (8, A, E)                              \
              thetaRhoPiChiIotaPrepareTheta (9, E, A) thetaRhoPiChiIotaPrepareTheta (10, A, E)                         \
                  thetaRhoPiChiIotaPrepareTheta (11, E, A) thetaRhoPiChiIotaPrepareTheta (12, A, E)                    \
                      thetaRhoPiChiIotaPrepareTheta (13, E, A) thetaRhoPiChiIotaPrepareTheta (14, A, E)                \
                          thetaRhoPiChiIotaPrepareTheta (15, E, A) thetaRhoPiChiIotaPrepareTheta (16, A, E)            \
                              thetaRhoPiChiIotaPrepareTheta (17, E, A) thetaRhoPiChiIotaPrepareTheta (18, A, E)        \
                                  thetaRhoPiChiIotaPrepareTheta (19, E, A) thetaRhoPiChiIotaPrepareTheta (20, A, E)    \
                                      thetaRhoPiChiIotaPrepareTheta (21, E, A)                                         \
                                          thetaRhoPiChiIotaPrepareTheta (22, A, E) thetaRhoPiChiIota (23, E, A)

void _gcry_slhdsa_KeccakP1600times4_PermuteAll_24rounds (__m256i *states)
{
  __m256i *statesAsLanes = states;
  __m256i Aba, Abe, Abi, Abo, Abu;
  __m256i Aga, Age, Agi, Ago, Agu;
  __m256i Aka, Ake, Aki, Ako, Aku;
  __m256i Ama, Ame, Ami, Amo, Amu;
  __m256i Asa, Ase, Asi, Aso, Asu;
  __m256i Bba, Bbe, Bbi, Bbo, Bbu;
  __m256i Bga, Bge, Bgi, Bgo, Bgu;
  __m256i Bka, Bke, Bki, Bko, Bku;
  __m256i Bma, Bme, Bmi, Bmo, Bmu;
  __m256i Bsa, Bse, Bsi, Bso, Bsu;
  __m256i Ca, Ce, Ci, Co, Cu;
  __m256i Ca1, Ce1, Ci1, Co1, Cu1;
  __m256i Da, De, Di, Do, Du;
  __m256i Eba, Ebe, Ebi, Ebo, Ebu;
  __m256i Ega, Ege, Egi, Ego, Egu;
  __m256i Eka, Eke, Eki, Eko, Eku;
  __m256i Ema, Eme, Emi, Emo, Emu;
  __m256i Esa, Ese, Esi, Eso, Esu;

  copyFromState (A, statesAsLanes) rounds24 copyToState (statesAsLanes, A)
}
#endif