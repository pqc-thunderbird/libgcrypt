/* slhdsa-thash.c
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

#include <config.h>

#include "types.h"
#include <string.h>

#include "slhdsa-address.h"
#include "slhdsa-thash.h"
#include "slhdsa-utils.h"

#include "avx2-immintrin-support.h"
#ifdef USE_AVX2
#include "slhdsa-sha512x4.h"
#include "slhdsa-sha256x8.h"
#include "slhdsa-fips202x4.h"
#endif

#include "g10lib.h"

gcry_err_code_t _gcry_slhdsa_thash (
    byte *out, const byte *in, unsigned int inblocks, const _gcry_slhdsa_param_t *ctx, u32 addr[8])
{
  gcry_err_code_t ec = 0;
  gcry_md_hd_t hd    = NULL;
  enum gcry_md_algos algo;

  /* initialize hash */
  if (ctx->is_sha2)
    {
      if (ctx->do_use_sha512 && (inblocks > 1))
        {
          algo = GCRY_MD_SHA512;
          ec   = _gcry_md_copy (&hd, ctx->state_seeded_512);
        }
      else
        {
          algo = GCRY_MD_SHA256;
          ec   = _gcry_md_copy (&hd, ctx->state_seeded);
        }
    }
  else
    {
      algo = GCRY_MD_SHAKE256;
      ec   = _gcry_md_open (&hd, GCRY_MD_SHAKE256, GCRY_MD_FLAG_SECURE);
      if (!ec)
        _gcry_md_write (hd, ctx->pub_seed, ctx->n);
    }
  if (ec)
    goto leave;

  _gcry_md_write (hd, (byte *)addr, ctx->addr_bytes);
  _gcry_md_write (hd, in, inblocks * ctx->n);

  if (ctx->is_sha2)
    {
      memcpy (out, _gcry_md_read (hd, algo), ctx->n);
    }
  else
    {
      ec = _gcry_md_extract (hd, algo, out, ctx->n);
      if (ec)
        goto leave;
    }

leave:
  _gcry_md_close (hd);
  return ec;
}

#ifdef USE_AVX2
static gcry_err_code_t thashx8_512 (byte *out0,
                                    byte *out1,
                                    byte *out2,
                                    byte *out3,
                                    byte *out4,
                                    byte *out5,
                                    byte *out6,
                                    byte *out7,
                                    const byte *in0,
                                    const byte *in1,
                                    const byte *in2,
                                    const byte *in3,
                                    const byte *in4,
                                    const byte *in5,
                                    const byte *in6,
                                    const byte *in7,
                                    unsigned int inblocks,
                                    const _gcry_slhdsa_param_t *ctx,
                                    u32 addrx8[8 * 8]);

/**
 * 8-way parallel version of thash; takes 8x as much input and output
 */
gcry_err_code_t _gcry_slhdsa_thash_avx2_sha2 (byte *out0,
                                              byte *out1,
                                              byte *out2,
                                              byte *out3,
                                              byte *out4,
                                              byte *out5,
                                              byte *out6,
                                              byte *out7,
                                              const byte *in0,
                                              const byte *in1,
                                              const byte *in2,
                                              const byte *in3,
                                              const byte *in4,
                                              const byte *in5,
                                              const byte *in6,
                                              const byte *in7,
                                              unsigned int inblocks,
                                              const _gcry_slhdsa_param_t *ctx,
                                              u32 addrx8[8 * 8])
{
  gcry_err_code_t ec = 0;
  byte *bufx8        = NULL;
  byte *outbufx8     = NULL;
  unsigned int i;

  bufx8 = xtrymalloc_secure (8 * (ctx->addr_bytes + inblocks * ctx->n));
  if (!bufx8)
    {
      ec = gpg_err_code_from_syserror();
      goto leave;
    }
  outbufx8 = xtrymalloc_secure (8 * SLHDSA_SHA256_OUTPUT_BYTES);
  if (!outbufx8)
    {
      ec = gpg_err_code_from_syserror();
      goto leave;
    }

  if (ctx->do_use_sha512)
    {
      if (inblocks > 1)
        {
          ec = thashx8_512 (out0,
                            out1,
                            out2,
                            out3,
                            out4,
                            out5,
                            out6,
                            out7,
                            in0,
                            in1,
                            in2,
                            in3,
                            in4,
                            in5,
                            in6,
                            in7,
                            inblocks,
                            ctx,
                            addrx8);
          goto leave;
        }
    }

  for (i = 0; i < 8; i++)
    {
      memcpy (bufx8 + i * (ctx->addr_bytes + inblocks * ctx->n), addrx8 + i * 8, ctx->addr_bytes);
    }

  memcpy (bufx8 + ctx->addr_bytes + 0 * (ctx->addr_bytes + inblocks * ctx->n), in0, inblocks * ctx->n);
  memcpy (bufx8 + ctx->addr_bytes + 1 * (ctx->addr_bytes + inblocks * ctx->n), in1, inblocks * ctx->n);
  memcpy (bufx8 + ctx->addr_bytes + 2 * (ctx->addr_bytes + inblocks * ctx->n), in2, inblocks * ctx->n);
  memcpy (bufx8 + ctx->addr_bytes + 3 * (ctx->addr_bytes + inblocks * ctx->n), in3, inblocks * ctx->n);
  memcpy (bufx8 + ctx->addr_bytes + 4 * (ctx->addr_bytes + inblocks * ctx->n), in4, inblocks * ctx->n);
  memcpy (bufx8 + ctx->addr_bytes + 5 * (ctx->addr_bytes + inblocks * ctx->n), in5, inblocks * ctx->n);
  memcpy (bufx8 + ctx->addr_bytes + 6 * (ctx->addr_bytes + inblocks * ctx->n), in6, inblocks * ctx->n);
  memcpy (bufx8 + ctx->addr_bytes + 7 * (ctx->addr_bytes + inblocks * ctx->n), in7, inblocks * ctx->n);

  _gcry_slhdsa_sha256x8_seeded (
      /* out */
      outbufx8 + 0 * SLHDSA_SHA256_OUTPUT_BYTES,
      outbufx8 + 1 * SLHDSA_SHA256_OUTPUT_BYTES,
      outbufx8 + 2 * SLHDSA_SHA256_OUTPUT_BYTES,
      outbufx8 + 3 * SLHDSA_SHA256_OUTPUT_BYTES,
      outbufx8 + 4 * SLHDSA_SHA256_OUTPUT_BYTES,
      outbufx8 + 5 * SLHDSA_SHA256_OUTPUT_BYTES,
      outbufx8 + 6 * SLHDSA_SHA256_OUTPUT_BYTES,
      outbufx8 + 7 * SLHDSA_SHA256_OUTPUT_BYTES,

      /* seed */
      ctx->state_seeded_avx2,
      512,

      /* in */
      bufx8 + 0 * (ctx->addr_bytes + inblocks * ctx->n),
      bufx8 + 1 * (ctx->addr_bytes + inblocks * ctx->n),
      bufx8 + 2 * (ctx->addr_bytes + inblocks * ctx->n),
      bufx8 + 3 * (ctx->addr_bytes + inblocks * ctx->n),
      bufx8 + 4 * (ctx->addr_bytes + inblocks * ctx->n),
      bufx8 + 5 * (ctx->addr_bytes + inblocks * ctx->n),
      bufx8 + 6 * (ctx->addr_bytes + inblocks * ctx->n),
      bufx8 + 7 * (ctx->addr_bytes + inblocks * ctx->n),
      ctx->addr_bytes + inblocks * ctx->n /* len */
  );

  memcpy (out0, outbufx8 + 0 * SLHDSA_SHA256_OUTPUT_BYTES, ctx->n);
  memcpy (out1, outbufx8 + 1 * SLHDSA_SHA256_OUTPUT_BYTES, ctx->n);
  memcpy (out2, outbufx8 + 2 * SLHDSA_SHA256_OUTPUT_BYTES, ctx->n);
  memcpy (out3, outbufx8 + 3 * SLHDSA_SHA256_OUTPUT_BYTES, ctx->n);
  memcpy (out4, outbufx8 + 4 * SLHDSA_SHA256_OUTPUT_BYTES, ctx->n);
  memcpy (out5, outbufx8 + 5 * SLHDSA_SHA256_OUTPUT_BYTES, ctx->n);
  memcpy (out6, outbufx8 + 6 * SLHDSA_SHA256_OUTPUT_BYTES, ctx->n);
  memcpy (out7, outbufx8 + 7 * SLHDSA_SHA256_OUTPUT_BYTES, ctx->n);

leave:
  xfree (bufx8);
  xfree (outbufx8);
  return ec;
}

/**
 * 2x4-way parallel version of thash; this is for the uses of thash that are
 * based on SHA-512
 */
gcry_err_code_t thashx8_512 (byte *out0,
                             byte *out1,
                             byte *out2,
                             byte *out3,
                             byte *out4,
                             byte *out5,
                             byte *out6,
                             byte *out7,
                             const byte *in0,
                             const byte *in1,
                             const byte *in2,
                             const byte *in3,
                             const byte *in4,
                             const byte *in5,
                             const byte *in6,
                             const byte *in7,
                             unsigned int inblocks,
                             const _gcry_slhdsa_param_t *ctx,
                             u32 addrx8[8 * 8])
{
  gcry_err_code_t ec = 0;
  byte *bufx8        = NULL;

  byte outbuf[4 * SLHDSA_SHA512_OUTPUT_BYTES];
  unsigned int i;

  bufx8 = xtrymalloc_secure (8 * (ctx->addr_bytes + inblocks * ctx->n));
  if (!bufx8)
    {
      ec = gpg_err_code_from_syserror();
      goto leave;
    }

  for (i = 0; i < 8; i++)
    {
      memcpy (bufx8 + i * (ctx->addr_bytes + inblocks * ctx->n), addrx8 + i * 8, ctx->addr_bytes);
    }

  memcpy (bufx8 + ctx->addr_bytes + 0 * (ctx->addr_bytes + inblocks * ctx->n), in0, inblocks * ctx->n);
  memcpy (bufx8 + ctx->addr_bytes + 1 * (ctx->addr_bytes + inblocks * ctx->n), in1, inblocks * ctx->n);
  memcpy (bufx8 + ctx->addr_bytes + 2 * (ctx->addr_bytes + inblocks * ctx->n), in2, inblocks * ctx->n);
  memcpy (bufx8 + ctx->addr_bytes + 3 * (ctx->addr_bytes + inblocks * ctx->n), in3, inblocks * ctx->n);
  memcpy (bufx8 + ctx->addr_bytes + 4 * (ctx->addr_bytes + inblocks * ctx->n), in4, inblocks * ctx->n);
  memcpy (bufx8 + ctx->addr_bytes + 5 * (ctx->addr_bytes + inblocks * ctx->n), in5, inblocks * ctx->n);
  memcpy (bufx8 + ctx->addr_bytes + 6 * (ctx->addr_bytes + inblocks * ctx->n), in6, inblocks * ctx->n);
  memcpy (bufx8 + ctx->addr_bytes + 7 * (ctx->addr_bytes + inblocks * ctx->n), in7, inblocks * ctx->n);

  ec = _gcry_slhdsa_sha512x4_seeded (outbuf + 0 * SLHDSA_SHA512_OUTPUT_BYTES,
                                     outbuf + 1 * SLHDSA_SHA512_OUTPUT_BYTES,
                                     outbuf + 2 * SLHDSA_SHA512_OUTPUT_BYTES,
                                     outbuf + 3 * SLHDSA_SHA512_OUTPUT_BYTES,
                                     ctx->state_seeded_512_avx2,                        /* seed */
                                     1024,                                              /* seed length */
                                     bufx8 + 0 * (ctx->addr_bytes + inblocks * ctx->n), /* in */
                                     bufx8 + 1 * (ctx->addr_bytes + inblocks * ctx->n),
                                     bufx8 + 2 * (ctx->addr_bytes + inblocks * ctx->n),
                                     bufx8 + 3 * (ctx->addr_bytes + inblocks * ctx->n),
                                     ctx->addr_bytes + inblocks * ctx->n /* len */
  );
  if (ec)
    goto leave;

  memcpy (out0, outbuf + 0 * SLHDSA_SHA512_OUTPUT_BYTES, ctx->n);
  memcpy (out1, outbuf + 1 * SLHDSA_SHA512_OUTPUT_BYTES, ctx->n);
  memcpy (out2, outbuf + 2 * SLHDSA_SHA512_OUTPUT_BYTES, ctx->n);
  memcpy (out3, outbuf + 3 * SLHDSA_SHA512_OUTPUT_BYTES, ctx->n);

  ec = _gcry_slhdsa_sha512x4_seeded (outbuf + 0 * SLHDSA_SHA512_OUTPUT_BYTES,
                                     outbuf + 1 * SLHDSA_SHA512_OUTPUT_BYTES,
                                     outbuf + 2 * SLHDSA_SHA512_OUTPUT_BYTES,
                                     outbuf + 3 * SLHDSA_SHA512_OUTPUT_BYTES,
                                     ctx->state_seeded_512_avx2,                        /* seed */
                                     1024,                                              /* seed length */
                                     bufx8 + 4 * (ctx->addr_bytes + inblocks * ctx->n), /* in */
                                     bufx8 + 5 * (ctx->addr_bytes + inblocks * ctx->n),
                                     bufx8 + 6 * (ctx->addr_bytes + inblocks * ctx->n),
                                     bufx8 + 7 * (ctx->addr_bytes + inblocks * ctx->n),
                                     ctx->addr_bytes + inblocks * ctx->n /* len */
  );
  if (ec)
    goto leave;

  memcpy (out4, outbuf + 0 * SLHDSA_SHA512_OUTPUT_BYTES, ctx->n);
  memcpy (out5, outbuf + 1 * SLHDSA_SHA512_OUTPUT_BYTES, ctx->n);
  memcpy (out6, outbuf + 2 * SLHDSA_SHA512_OUTPUT_BYTES, ctx->n);
  memcpy (out7, outbuf + 3 * SLHDSA_SHA512_OUTPUT_BYTES, ctx->n);

leave:
  xfree (bufx8);
  return ec;
}


/*
 * shake
 */


/**
 * 4-way parallel version of thash; takes 4x as much input and output
 */
gcry_err_code_t _gcry_slhdsa_thash_avx2_shake (byte *out0,
                                               byte *out1,
                                               byte *out2,
                                               byte *out3,
                                               const byte *in0,
                                               const byte *in1,
                                               const byte *in2,
                                               const byte *in3,
                                               unsigned int inblocks,
                                               const _gcry_slhdsa_param_t *ctx,
                                               u32 addrx4[4 * 8])
{
  gcry_err_code_t ec             = 0;
  byte *buf0                     = NULL;
  byte *buf1                     = NULL;
  byte *buf2                     = NULL;
  byte *buf3                     = NULL;
  gcry_slhdsa_buf_al state_alloc = {};


  if (inblocks == 1 || inblocks == 2)
    {
      /* As we write and read only a few quadwords, it is more efficient to
       * build and extract from the fourway SHAKE256 state by hand. */
      __m256i *state = NULL;

      /* we need 32-byte aligned state */
      ec = _gcry_slhdsa_buf_al_create (&state_alloc, sizeof (__m256i[25]));
      if (ec)
        {
          goto leave;
        }
      state = (__m256i *)state_alloc.buf;

      for (int i = 0; i < ctx->n / 8; i++)
        {
          state[i] = _mm256_set1_epi64x (((int64_t *)ctx->pub_seed)[i]);
        }
      for (int i = 0; i < 4; i++)
        {
          state[ctx->n / 8 + i] = _mm256_set_epi32 (addrx4[3 * 8 + 1 + 2 * i],
                                                    addrx4[3 * 8 + 2 * i],
                                                    addrx4[2 * 8 + 1 + 2 * i],
                                                    addrx4[2 * 8 + 2 * i],
                                                    addrx4[8 + 1 + 2 * i],
                                                    addrx4[8 + 2 * i],
                                                    addrx4[1 + 2 * i],
                                                    addrx4[2 * i]);
        }

      for (unsigned int i = 0; i < (ctx->n / 8) * inblocks; i++)
        {
          state[ctx->n / 8 + 4 + i]
              = _mm256_set_epi64x (((int64_t *)in3)[i], ((int64_t *)in2)[i], ((int64_t *)in1)[i], ((int64_t *)in0)[i]);
        }

      /* Domain separator and padding. */
      for (int i = (ctx->n / 8) * (1 + inblocks) + 4; i < 16; i++)
        {
          state[i] = _mm256_set1_epi64x (0);
        }
      state[16] = _mm256_set1_epi64x ((long long)(0x80ULL << 56));
      state[(ctx->n / 8) * (1 + inblocks) + 4]
          = _mm256_xor_si256 (state[(ctx->n / 8) * (1 + inblocks) + 4], _mm256_set1_epi64x (0x1f));
      for (int i = 17; i < 25; i++)
        {
          state[i] = _mm256_set1_epi64x (0);
        }

      _gcry_slhdsa_KeccakP1600times4_PermuteAll_24rounds (&state[0]);

      for (int i = 0; i < ctx->n / 8; i++)
        {
          ((int64_t *)out0)[i] = _mm256_extract_epi64 (state[i], 0);
          ((int64_t *)out1)[i] = _mm256_extract_epi64 (state[i], 1);
          ((int64_t *)out2)[i] = _mm256_extract_epi64 (state[i], 2);
          ((int64_t *)out3)[i] = _mm256_extract_epi64 (state[i], 3);
        }
    }
  else
    {
      buf0 = xtrymalloc_secure (ctx->n + ctx->addr_bytes + inblocks * ctx->n);
      if (ec)
        {
          ec = gpg_err_code_from_syserror();
          goto leave;
        }
      buf1 = xtrymalloc_secure (ctx->n + ctx->addr_bytes + inblocks * ctx->n);
      if (ec)
        {
          ec = gpg_err_code_from_syserror();
          goto leave;
        }
      buf2 = xtrymalloc_secure (ctx->n + ctx->addr_bytes + inblocks * ctx->n);
      if (ec)
        {
          ec = gpg_err_code_from_syserror();
          goto leave;
        }
      buf3 = xtrymalloc_secure (ctx->n + ctx->addr_bytes + inblocks * ctx->n);
      if (ec)
        {
          ec = gpg_err_code_from_syserror();
          goto leave;
        }

      memcpy (buf0, ctx->pub_seed, ctx->n);
      memcpy (buf1, ctx->pub_seed, ctx->n);
      memcpy (buf2, ctx->pub_seed, ctx->n);
      memcpy (buf3, ctx->pub_seed, ctx->n);
      memcpy (buf0 + ctx->n, addrx4 + 0 * 8, ctx->addr_bytes);
      memcpy (buf1 + ctx->n, addrx4 + 1 * 8, ctx->addr_bytes);
      memcpy (buf2 + ctx->n, addrx4 + 2 * 8, ctx->addr_bytes);
      memcpy (buf3 + ctx->n, addrx4 + 3 * 8, ctx->addr_bytes);
      memcpy (buf0 + ctx->n + ctx->addr_bytes, in0, inblocks * ctx->n);
      memcpy (buf1 + ctx->n + ctx->addr_bytes, in1, inblocks * ctx->n);
      memcpy (buf2 + ctx->n + ctx->addr_bytes, in2, inblocks * ctx->n);
      memcpy (buf3 + ctx->n + ctx->addr_bytes, in3, inblocks * ctx->n);

      ec = _gcry_slhdsa_shake256x4 (
          out0, out1, out2, out3, ctx->n, buf0, buf1, buf2, buf3, ctx->n + ctx->addr_bytes + inblocks * ctx->n);
      if (ec)
        goto leave;
    }

leave:
  xfree (buf0);
  xfree (buf1);
  xfree (buf2);
  xfree (buf3);
  _gcry_slhdsa_buf_al_destroy (&state_alloc);
  return ec;
}
#endif
