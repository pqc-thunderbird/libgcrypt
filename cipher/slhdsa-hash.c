#include <config.h>

#include "types.h"
#include <string.h>

#include "avx2-immintrin-support.h"
#include "slhdsa-address.h"
#include "slhdsa-utils.h"
#include "slhdsa-hash.h"

#include "g10lib.h"
#include "mgf.h"

#ifdef USE_AVX2
#include "slhdsa-sha256x8.h"
#include "slhdsa-sha512x4.h"
#include "slhdsa-fips202x4.h"
#endif

static gcry_err_code_t initialize_hash_function_sha2(_gcry_slhdsa_param_t *ctx);
static gcry_err_code_t gen_message_random_sha2(byte *R,
                                               const byte *sk_prf,
                                               const byte *optrand,
                                               const byte *m,
                                               unsigned long long mlen,
                                               const _gcry_slhdsa_param_t *ctx);
static gcry_err_code_t gen_message_random_shake(byte *R,
                                                const byte *sk_prf,
                                                const byte *optrand,
                                                const byte *m,
                                                unsigned long long mlen,
                                                const _gcry_slhdsa_param_t *ctx);
static gcry_err_code_t hash_message_sha2(byte *digest,
                                         u64 *tree,
                                         u32 *leaf_idx,
                                         const byte *R,
                                         const byte *pk,
                                         const byte *m,
                                         unsigned long long mlen,
                                         const _gcry_slhdsa_param_t *ctx);
static gcry_err_code_t hash_message_shake(byte *digest,
                                          u64 *tree,
                                          u32 *leaf_idx,
                                          const byte *R,
                                          const byte *pk,
                                          const byte *m,
                                          unsigned long long mlen,
                                          const _gcry_slhdsa_param_t *ctx);


gcry_err_code_t _gcry_slhdsa_initialize_hash_function(_gcry_slhdsa_param_t *ctx)
{
  /* absorb public seed */
  if (ctx->is_sha2)
    {
#ifdef USE_AVX2
      if (ctx->use_avx2)
        {
          /* also initialize the avx2 fields */
          initialize_hash_function_sha_avx2(ctx);
        }
#endif
      return initialize_hash_function_sha2(ctx);
    }
  return 0;
}

/**
 * Absorb the constant pub_seed using one round of the compression function
 * This initializes state_seeded and state_seeded_512, which can then be
 * reused in thash
 **/
void initialize_hash_function_sha_avx2(_gcry_slhdsa_param_t *ctx)
{
  byte block[SLHDSA_SHA512_BLOCK_BYTES];
  size_t i;

  for (i = 0; i < ctx->n; ++i)
    {
      block[i] = ctx->pub_seed[i];
    }
  for (i = ctx->n; i < SLHDSA_SHA512_BLOCK_BYTES; ++i)
    {
      block[i] = 0;
    }

  _gcry_slhdsa_sha256_inc_init(ctx->state_seeded_avx2);
  _gcry_slhdsa_sha256_inc_blocks(ctx->state_seeded_avx2, block, 1);
  if (ctx->do_use_sha512)
    {
      _gcry_slhdsa_sha512_inc_init(ctx->state_seeded_512_avx2);
      _gcry_slhdsa_sha512_inc_blocks(ctx->state_seeded_512_avx2, block, 1);
    }
}


/*
 * Computes PRF(pk_seed, sk_seed, addr).
 */
gcry_err_code_t _gcry_slhdsa_prf_addr(byte *out, const _gcry_slhdsa_param_t *ctx, const u32 addr[8])
{

  gcry_err_code_t ec = 0;
  gcry_md_hd_t hd    = NULL;
  enum gcry_md_algos algo;

  /* initialize hash */
  if (ctx->is_sha2)
    {
      algo = GCRY_MD_SHA256;
      ec   = _gcry_md_copy(&hd, ctx->state_seeded);
    }
  else
    {
      algo = GCRY_MD_SHAKE256;
      ec   = _gcry_md_open(&hd, GCRY_MD_SHAKE256, GCRY_MD_FLAG_SECURE);
      if (!ec)
        _gcry_md_write(hd, ctx->pub_seed, ctx->n);
    }
  if (ec)
    goto leave;

  _gcry_md_write(hd, (byte *)addr, ctx->addr_bytes);
  _gcry_md_write(hd, ctx->sk_seed, ctx->n);

  if (ctx->is_sha2)
    {
      memcpy(out, _gcry_md_read(hd, algo), ctx->n);
    }
  else
    {
      ec = _gcry_md_extract(hd, algo, out, ctx->n);
      if (ec)
        goto leave;
    }

leave:
  _gcry_md_close(hd);
  return ec;
}

#ifdef USE_AVX2
/*
 * 8-way parallel version of _gcry_slhdsa_prf_addr; takes 8x as much input and output
 */
gcry_err_code_t _gcry_slhdsa_prf_avx2_sha2(byte *out0,
                                           byte *out1,
                                           byte *out2,
                                           byte *out3,
                                           byte *out4,
                                           byte *out5,
                                           byte *out6,
                                           byte *out7,
                                           const _gcry_slhdsa_param_t *ctx,
                                           const u32 addrx8[8 * 8])
{
  gcry_err_code_t ec = 0;
  byte *bufx8        = NULL;

  byte outbufx8[8 * SLHDSA_SHA256_OUTPUT_BYTES];
  unsigned int j;

  bufx8 = xtrymalloc_secure(8 * (ctx->n + ctx->addr_bytes));
  if (!bufx8)
    {
      ec = gpg_err_code_from_syserror();
      goto leave;
    }


  for (j = 0; j < 8; j++)
    {
      memcpy(bufx8 + j * (ctx->n + ctx->addr_bytes), addrx8 + j * 8, ctx->addr_bytes);
      memcpy(bufx8 + j * (ctx->n + ctx->addr_bytes) + ctx->addr_bytes, ctx->sk_seed, ctx->n);
    }

  _gcry_slhdsa_sha256x8_seeded(
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
      bufx8 + 0 * (ctx->addr_bytes + ctx->n),
      bufx8 + 1 * (ctx->addr_bytes + ctx->n),
      bufx8 + 2 * (ctx->addr_bytes + ctx->n),
      bufx8 + 3 * (ctx->addr_bytes + ctx->n),
      bufx8 + 4 * (ctx->addr_bytes + ctx->n),
      bufx8 + 5 * (ctx->addr_bytes + ctx->n),
      bufx8 + 6 * (ctx->addr_bytes + ctx->n),
      bufx8 + 7 * (ctx->addr_bytes + ctx->n),
      ctx->addr_bytes + ctx->n /* len */
  );

  memcpy(out0, outbufx8 + 0 * SLHDSA_SHA256_OUTPUT_BYTES, ctx->n);
  memcpy(out1, outbufx8 + 1 * SLHDSA_SHA256_OUTPUT_BYTES, ctx->n);
  memcpy(out2, outbufx8 + 2 * SLHDSA_SHA256_OUTPUT_BYTES, ctx->n);
  memcpy(out3, outbufx8 + 3 * SLHDSA_SHA256_OUTPUT_BYTES, ctx->n);
  memcpy(out4, outbufx8 + 4 * SLHDSA_SHA256_OUTPUT_BYTES, ctx->n);
  memcpy(out5, outbufx8 + 5 * SLHDSA_SHA256_OUTPUT_BYTES, ctx->n);
  memcpy(out6, outbufx8 + 6 * SLHDSA_SHA256_OUTPUT_BYTES, ctx->n);
  memcpy(out7, outbufx8 + 7 * SLHDSA_SHA256_OUTPUT_BYTES, ctx->n);

leave:
  xfree(bufx8);
  return ec;
}

void _gcry_slhdsa_prf_avx2_shake(
    byte *out0, byte *out1, byte *out2, byte *out3, const _gcry_slhdsa_param_t *ctx, const u32 addrx4[4 * 8])
{
  /* As we write and read only a few quadwords, it is more efficient to
   * build and extract from the fourway SHAKE256 state by hand. */
  __m256i state[25];

  for (int i = 0; i < ctx->n / 8; i++)
    {
      state[i] = _mm256_set1_epi64x(((int64_t *)ctx->pub_seed)[i]);
    }
  for (int i = 0; i < 4; i++)
    {
      state[ctx->n / 8 + i] = _mm256_set_epi32(addrx4[3 * 8 + 1 + 2 * i],
                                               addrx4[3 * 8 + 2 * i],
                                               addrx4[2 * 8 + 1 + 2 * i],
                                               addrx4[2 * 8 + 2 * i],
                                               addrx4[8 + 1 + 2 * i],
                                               addrx4[8 + 2 * i],
                                               addrx4[1 + 2 * i],
                                               addrx4[2 * i]);
    }
  for (int i = 0; i < ctx->n / 8; i++)
    {
      state[ctx->n / 8 + i + 4] = _mm256_set1_epi64x(((int64_t *)ctx->sk_seed)[i]);
    }

  /* SHAKE domain separator and padding. */
  state[ctx->n / 4 + 4] = _mm256_set1_epi64x(0x1f);
  for (int i = ctx->n / 4 + 5; i < 16; i++)
    {
      state[i] = _mm256_set1_epi64x(0);
    }
  // shift unsigned and then cast to avoid UB
  state[16] = _mm256_set1_epi64x((long long)(0x80ULL << 56));

  for (int i = 17; i < 25; i++)
    {
      state[i] = _mm256_set1_epi64x(0);
    }

  _gcry_slhdsa_KeccakP1600times4_PermuteAll_24rounds(&state[0]);

  for (int i = 0; i < ctx->n / 8; i++)
    {
      ((int64_t *)out0)[i] = _mm256_extract_epi64(state[i], 0);
      ((int64_t *)out1)[i] = _mm256_extract_epi64(state[i], 1);
      ((int64_t *)out2)[i] = _mm256_extract_epi64(state[i], 2);
      ((int64_t *)out3)[i] = _mm256_extract_epi64(state[i], 3);
    }
}

#endif

gcry_err_code_t _gcry_slhdsa_gen_message_random(byte *R,
                                                const byte *sk_prf,
                                                const byte *optrand,
                                                const byte *m,
                                                unsigned long long mlen,
                                                const _gcry_slhdsa_param_t *ctx)
{
  if (ctx->is_sha2)
    {
      return gen_message_random_sha2(R, sk_prf, optrand, m, mlen, ctx);
    }
  else
    {
      return gen_message_random_shake(R, sk_prf, optrand, m, mlen, ctx);
    }
}

gcry_err_code_t _gcry_slhdsa_hash_message(byte *digest,
                                          u64 *tree,
                                          u32 *leaf_idx,
                                          const byte *R,
                                          const byte *pk,
                                          const byte *m,
                                          unsigned long long mlen,
                                          const _gcry_slhdsa_param_t *ctx)

{
  if (ctx->is_sha2)
    {
      return hash_message_sha2(digest, tree, leaf_idx, R, pk, m, mlen, ctx);
    }
  else
    {
      return hash_message_shake(digest, tree, leaf_idx, R, pk, m, mlen, ctx);
    }
}

gcry_err_code_t initialize_hash_function_sha2(_gcry_slhdsa_param_t *ctx)
{
  /**
   * Absorb the constant pub_seed using one round of the compression function
   * This initializes state_seeded and state_seeded_512, which can then be
   * reused in thash
   **/
  gcry_err_code_t ec = 0;
  byte block[SLHDSA_SHA512_BLOCK_BYTES];

  memset(block, 0, SLHDSA_SHA512_BLOCK_BYTES);
  memcpy(block, ctx->pub_seed, ctx->n);

  /* seed SHA256 state */
  ec = _gcry_md_open(&(ctx->state_seeded), GCRY_MD_SHA256, GCRY_MD_FLAG_SECURE);
  if (ec)
    return ec;
  _gcry_md_write(ctx->state_seeded, block, SLHDSA_SHA256_BLOCK_BYTES);

  /* seed SHA512 state */
  if (ctx->do_use_sha512)
    {
      ec = _gcry_md_open(&(ctx->state_seeded_512), GCRY_MD_SHA512, GCRY_MD_FLAG_SECURE);
      if (ec)
        return ec;
      _gcry_md_write(ctx->state_seeded_512, block, SLHDSA_SHA512_BLOCK_BYTES);
    }

  return ec;
}

/**
 * Computes the message-dependent randomness R, using a secret seed as a key
 * for HMAC, and an optional randomization value prefixed to the message.
 * This requires m to have at least shax_block_bytes + ctx->n space
 * available in front of the pointer, i.e. before the message to use for the
 * prefix. This is necessary to prevent having to move the message around (and
 * allocate memory for it).
 */
static gcry_err_code_t gen_message_random_sha2(byte *R,
                                               const byte *sk_prf,
                                               const byte *optrand,
                                               const byte *m,
                                               unsigned long long mlen,
                                               const _gcry_slhdsa_param_t *ctx)
{
  /* HMAC-SHA-X(SK.prf, OptRand||M) */

  gcry_err_code_t ec = 0;
  int hmac_shaX_algo;
  gcry_mac_hd_t hd = NULL;
  size_t outlen;
  byte *tmpmac = NULL;

  if (ctx->do_use_sha512)
    {
      hmac_shaX_algo = GCRY_MAC_HMAC_SHA512;
    }
  else
    {
      hmac_shaX_algo = GCRY_MAC_HMAC_SHA256;
    }

  ec = _gcry_mac_open(&hd, hmac_shaX_algo, GCRY_MAC_FLAG_SECURE, NULL);
  if (ec)
    goto leave;

  ec = _gcry_mac_setkey(hd, sk_prf, ctx->n);
  if (ec)
    goto leave;

  ec = _gcry_mac_write(hd, optrand, ctx->n);
  if (ec)
    goto leave;

  ec = _gcry_mac_write(hd, m, mlen);
  if (ec)
    goto leave;

  outlen = _gcry_mac_get_algo_maclen(hmac_shaX_algo);
  tmpmac = xtrymalloc(outlen);
  if (!tmpmac)
    {
      ec = gpg_err_code_from_syserror();
      goto leave;
    }

  ec = _gcry_mac_read(hd, tmpmac, &outlen);
  if (ec)
    goto leave;

  if (outlen < ctx->n)
    {
      ec = GPG_ERR_INV_STATE;
      goto leave;
    }
  memcpy(R, tmpmac, outlen);

leave:
  _gcry_mac_close(hd);
  xfree(tmpmac);
  return ec;
}

/**
 * Computes the message hash using R, the public key, and the message.
 * Outputs the message digest and the index of the leaf. The index is split in
 * the tree index and the leaf index, for convenient copying to an address.
 */
static gcry_err_code_t hash_message_sha2(byte *digest,
                                         u64 *tree,
                                         u32 *leaf_idx,
                                         const byte *R,
                                         const byte *pk,
                                         const byte *m,
                                         unsigned long long mlen,
                                         const _gcry_slhdsa_param_t *ctx)
{
  gcry_err_code_t ec       = 0;
  gcry_md_hd_t hd          = NULL;
  size_t SLHDSA_TREE_BITS  = (ctx->tree_height * (ctx->d - 1));
  size_t SLHDSA_TREE_BYTES = ((SLHDSA_TREE_BITS + 7) / 8);
  size_t SLHDSA_LEAF_BITS  = ctx->tree_height;
  size_t SLHDSA_LEAF_BYTES = ((SLHDSA_LEAF_BITS + 7) / 8);
  size_t SLHDSA_DGST_BYTES = (ctx->FORS_msg_bytes + SLHDSA_TREE_BYTES + SLHDSA_LEAF_BYTES);
  int hash_alg;
  byte shax_block_bytes;
  byte shax_output_bytes;
  size_t SLHDSA_INBLOCKS;
  byte *seed  = NULL;
  byte *inbuf = NULL;
  byte *buf   = NULL;
  byte *bufp;

  if (ctx->do_use_sha512)
    {
      hash_alg          = GCRY_MD_SHA512;
      shax_block_bytes  = SLHDSA_SHA512_BLOCK_BYTES;
      shax_output_bytes = SLHDSA_SHA512_OUTPUT_BYTES;
    }
  else
    {
      hash_alg          = GCRY_MD_SHA256;
      shax_block_bytes  = SLHDSA_SHA256_BLOCK_BYTES;
      shax_output_bytes = SLHDSA_SHA256_OUTPUT_BYTES;
    }
  SLHDSA_INBLOCKS = (((ctx->n + ctx->public_key_bytes + shax_block_bytes - 1) & -shax_block_bytes) / shax_block_bytes);

  seed = xtrymalloc_secure(2 * ctx->n + shax_output_bytes);
  if (!seed)
    {
      ec = gpg_err_code_from_syserror();
      goto leave;
    }
  inbuf = xtrymalloc_secure(SLHDSA_INBLOCKS * shax_block_bytes);
  if (!inbuf)
    {
      ec = gpg_err_code_from_syserror();
      goto leave;
    }
  buf = xtrymalloc_secure(SLHDSA_DGST_BYTES);
  if (!buf)
    {
      ec = gpg_err_code_from_syserror();
      goto leave;
    }

  bufp = buf;


  /* seed: SHA-X(R ‖ PK.seed ‖ PK.root ‖ M) */
  memcpy(inbuf, R, ctx->n);
  memcpy(inbuf + ctx->n, pk, ctx->public_key_bytes);

  ec = _gcry_md_open(&hd, hash_alg, GCRY_MD_FLAG_SECURE);
  if (ec)
    goto leave;

  /* If R + pk + message cannot fill up an entire block */
  if (ctx->n + ctx->public_key_bytes + mlen < SLHDSA_INBLOCKS * shax_block_bytes)
    {
      memcpy(inbuf + ctx->n + ctx->public_key_bytes, m, mlen);
      _gcry_md_write(hd, inbuf, ctx->n + ctx->public_key_bytes + mlen);
    }
  /* Otherwise first fill a block, so that finalize only uses the message */
  else
    {
      memcpy(inbuf + ctx->n + ctx->public_key_bytes,
             m,
             SLHDSA_INBLOCKS * shax_block_bytes - ctx->n - ctx->public_key_bytes);

      _gcry_md_write(hd, inbuf, SLHDSA_INBLOCKS * shax_block_bytes);
      m += SLHDSA_INBLOCKS * shax_block_bytes - ctx->n - ctx->public_key_bytes;
      mlen -= SLHDSA_INBLOCKS * shax_block_bytes - ctx->n - ctx->public_key_bytes;
      _gcry_md_write(hd, m, mlen);
    }
  memcpy(seed + 2 * ctx->n, _gcry_md_read(hd, hash_alg), shax_output_bytes);

  /* H_msg: MGF1-SHA-X(R ‖ PK.seed ‖ seed) */
  memcpy(seed, R, ctx->n);
  memcpy(seed + ctx->n, pk, ctx->n);

  ec = mgf1(bufp, SLHDSA_DGST_BYTES, seed, 2 * ctx->n + shax_output_bytes, hash_alg);
  if (ec)
    goto leave;


  memcpy(digest, bufp, ctx->FORS_msg_bytes);
  bufp += ctx->FORS_msg_bytes;

  *tree = _gcry_slhdsa_bytes_to_ull(bufp, SLHDSA_TREE_BYTES);
  *tree &= (~(u64)0) >> (64 - SLHDSA_TREE_BITS);
  bufp += SLHDSA_TREE_BYTES;

  *leaf_idx = (u32)_gcry_slhdsa_bytes_to_ull(bufp, SLHDSA_LEAF_BYTES);
  *leaf_idx &= (~(u32)0) >> (32 - SLHDSA_LEAF_BITS);

leave:
  _gcry_md_close(hd);
  xfree(seed);
  xfree(inbuf);
  xfree(buf);
  return ec;
}

/**
 * Computes the message-dependent randomness R, using a secret seed and an
 * optional randomization value as well as the message.
 */
static gcry_err_code_t gen_message_random_shake(byte *R,
                                                const byte *sk_prf,
                                                const byte *optrand,
                                                const byte *m,
                                                unsigned long long mlen,
                                                const _gcry_slhdsa_param_t *ctx)
{
  gcry_err_code_t ec = 0;
  gcry_md_hd_t hd    = NULL;

  ec = _gcry_md_open(&hd, GCRY_MD_SHAKE256, GCRY_MD_FLAG_SECURE);
  if (ec)
    goto leave;
  _gcry_md_write(hd, sk_prf, ctx->n);
  _gcry_md_write(hd, optrand, ctx->n);
  _gcry_md_write(hd, m, mlen);
  ec = _gcry_md_extract(hd, GCRY_MD_SHAKE256, R, ctx->n);

leave:
  _gcry_md_close(hd);
  return ec;
}

/**
 * Computes the message hash using R, the public key, and the message.
 * Outputs the message digest and the index of the leaf. The index is split in
 * the tree index and the leaf index, for convenient copying to an address.
 */
static gcry_err_code_t hash_message_shake(byte *digest,
                                          u64 *tree,
                                          u32 *leaf_idx,
                                          const byte *R,
                                          const byte *pk,
                                          const byte *m,
                                          unsigned long long mlen,
                                          const _gcry_slhdsa_param_t *ctx)
{
  gcry_err_code_t ec       = 0;
  gcry_md_hd_t hd          = NULL;
  size_t SLHDSA_TREE_BITS  = ctx->tree_height * (ctx->d - 1);
  size_t SLHDSA_TREE_BYTES = (SLHDSA_TREE_BITS + 7) / 8;
  size_t SLHDSA_LEAF_BITS  = ctx->tree_height;
  size_t SLHDSA_LEAF_BYTES = (SLHDSA_LEAF_BITS + 7) / 8;
  size_t SLHDSA_DGST_BYTES = ctx->FORS_msg_bytes + SLHDSA_TREE_BYTES + SLHDSA_LEAF_BYTES;

  byte *buf = NULL;
  byte *bufp;

  buf = xtrymalloc_secure(SLHDSA_DGST_BYTES);
  if (!buf)
    {
      ec = gpg_err_code_from_syserror();
      goto leave;
    }

  bufp = buf;

  ec = _gcry_md_open(&hd, GCRY_MD_SHAKE256, GCRY_MD_FLAG_SECURE);
  if (ec)
    goto leave;
  _gcry_md_write(hd, R, ctx->n);
  _gcry_md_write(hd, pk, ctx->public_key_bytes);
  _gcry_md_write(hd, m, mlen);
  ec = _gcry_md_extract(hd, GCRY_MD_SHAKE256, buf, SLHDSA_DGST_BYTES);
  if (ec)
    goto leave;

  memcpy(digest, bufp, ctx->FORS_msg_bytes);
  bufp += ctx->FORS_msg_bytes;

  *tree = _gcry_slhdsa_bytes_to_ull(bufp, SLHDSA_TREE_BYTES);
  *tree &= (~(u64)0) >> (64 - SLHDSA_TREE_BITS);
  bufp += SLHDSA_TREE_BYTES;

  *leaf_idx = (u32)_gcry_slhdsa_bytes_to_ull(bufp, SLHDSA_LEAF_BYTES);
  *leaf_idx &= (~(u32)0) >> (32 - SLHDSA_LEAF_BITS);

leave:
  _gcry_md_close(hd);
  xfree(buf);
  return ec;
}
