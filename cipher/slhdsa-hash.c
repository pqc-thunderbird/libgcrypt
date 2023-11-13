#include <config.h>

#include "types.h"
#include <string.h>

#include "slhdsa-address.h"
#include "slhdsa-utils.h"
#include "slhdsa-hash.h"
#include "slhdsa-sha2.h"

#include "g10lib.h"
#include "mgf.h"


static gcry_err_code_t initialize_hash_function_sha2(_gcry_slhdsa_param_t *ctx);
static gcry_err_code_t prf_addr_sha2(unsigned char *out, const _gcry_slhdsa_param_t *ctx, const u32 addr[8]);
static gcry_err_code_t prf_addr_shake(unsigned char *out, const _gcry_slhdsa_param_t *ctx, const u32 addr[8]);
static gcry_err_code_t gen_message_random_sha2(unsigned char *R,
                                               const unsigned char *sk_prf,
                                               const unsigned char *optrand,
                                               const unsigned char *m,
                                               unsigned long long mlen,
                                               const _gcry_slhdsa_param_t *ctx);
static gcry_err_code_t gen_message_random_shake(unsigned char *R,
                                                const unsigned char *sk_prf,
                                                const unsigned char *optrand,
                                                const unsigned char *m,
                                                unsigned long long mlen,
                                                const _gcry_slhdsa_param_t *ctx);
static gcry_err_code_t hash_message_sha2(unsigned char *digest,
                                         u64 *tree,
                                         u32 *leaf_idx,
                                         const unsigned char *R,
                                         const unsigned char *pk,
                                         const unsigned char *m,
                                         unsigned long long mlen,
                                         const _gcry_slhdsa_param_t *ctx);
static gcry_err_code_t hash_message_shake(unsigned char *digest,
                                          u64 *tree,
                                          u32 *leaf_idx,
                                          const unsigned char *R,
                                          const unsigned char *pk,
                                          const unsigned char *m,
                                          unsigned long long mlen,
                                          const _gcry_slhdsa_param_t *ctx);


gcry_err_code_t _gcry_slhdsa_initialize_hash_function(_gcry_slhdsa_param_t *ctx)
{
  /* absorb public seed */
  if (ctx->is_sha2)
    {
      return initialize_hash_function_sha2(ctx);
    }
}

gcry_err_code_t _gcry_slhdsa_prf_addr(unsigned char *out, const _gcry_slhdsa_param_t *ctx, const u32 addr[8])
{
  if (ctx->is_sha2)
    {
      return prf_addr_sha2(out, ctx, addr);
    }
  else
    {
      return prf_addr_shake(out, ctx, addr);
    }
}

gcry_err_code_t _gcry_slhdsa_gen_message_random(unsigned char *R,
                                                const unsigned char *sk_prf,
                                                const unsigned char *optrand,
                                                const unsigned char *m,
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

gcry_err_code_t _gcry_slhdsa_hash_message(unsigned char *digest,
                                          u64 *tree,
                                          u32 *leaf_idx,
                                          const unsigned char *R,
                                          const unsigned char *pk,
                                          const unsigned char *m,
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

/*
 * Computes PRF(pk_seed, sk_seed, addr).
 */
static gcry_err_code_t prf_addr_sha2(unsigned char *out, const _gcry_slhdsa_param_t *ctx, const u32 addr[8])
{
  gcry_err_code_t ec = 0;
  gcry_md_hd_t hd    = NULL;
  unsigned char sha256_pubseed_block[SLHDSA_SHA256_BLOCK_BYTES];

  memset(sha256_pubseed_block, 0, SLHDSA_SHA256_BLOCK_BYTES);
  memcpy(sha256_pubseed_block, ctx->pub_seed, ctx->n);

  ec = _gcry_md_open(&hd, GCRY_MD_SHA256, GCRY_MD_FLAG_SECURE);
  if (ec)
    goto leave;
  _gcry_md_write(hd, sha256_pubseed_block, SLHDSA_SHA256_BLOCK_BYTES);
  _gcry_md_write(hd, (byte *)addr, SLHDSA_SHA256_ADDR_BYTES);
  _gcry_md_write(hd, ctx->sk_seed, ctx->n);
  memcpy(out, _gcry_md_read(hd, GCRY_MD_SHA256), ctx->n);

leave:
  _gcry_md_close(hd);
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
static gcry_err_code_t gen_message_random_sha2(unsigned char *R,
                                               const unsigned char *sk_prf,
                                               const unsigned char *optrand,
                                               const unsigned char *m,
                                               unsigned long long mlen,
                                               const _gcry_slhdsa_param_t *ctx)
{
  /* HMAC-SHA-X(SK.prf, OptRand||M) */

  gcry_err_code_t ec = 0;
  int hmac_shaX_algo;
  gcry_mac_hd_t hd = NULL;
  size_t outlen;
  unsigned char *tmpmac = NULL;

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

  tmpmac = xtrymalloc(_gcry_mac_get_algo_maclen(hmac_shaX_algo));
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
static gcry_err_code_t hash_message_sha2(unsigned char *digest,
                                         u64 *tree,
                                         u32 *leaf_idx,
                                         const unsigned char *R,
                                         const unsigned char *pk,
                                         const unsigned char *m,
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
  unsigned char *seed  = NULL;
  unsigned char *inbuf = NULL;
  unsigned char *buf   = NULL;
  unsigned char *bufp;

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

/*
 * Computes PRF(pk_seed, sk_seed, addr)
 */
static gcry_err_code_t prf_addr_shake(unsigned char *out, const _gcry_slhdsa_param_t *ctx, const u32 addr[8])
{
  gcry_err_code_t ec = 0;
  unsigned char *buf = NULL;
  gcry_md_hd_t hd    = NULL;

  buf = xtrymalloc_secure(2 * ctx->n + ctx->addr_bytes);
  if (!buf)
    {
      ec = gpg_err_code_from_syserror();
      goto leave;
    }

  memcpy(buf, ctx->pub_seed, ctx->n);
  memcpy(buf + ctx->n, addr, ctx->addr_bytes);
  memcpy(buf + ctx->n + ctx->addr_bytes, ctx->sk_seed, ctx->n);

  ec = _gcry_md_open(&hd, GCRY_MD_SHAKE256, GCRY_MD_FLAG_SECURE);
  if (ec)
    goto leave;
  _gcry_md_write(hd, buf, 2 * ctx->n + ctx->addr_bytes);
  ec = _gcry_md_extract(hd, GCRY_MD_SHAKE256, out, ctx->n);
  if (ec)
    goto leave;

leave:
  _gcry_md_close(hd);
  xfree(buf);
  return ec;
}

/**
 * Computes the message-dependent randomness R, using a secret seed and an
 * optional randomization value as well as the message.
 */
static gcry_err_code_t gen_message_random_shake(unsigned char *R,
                                                const unsigned char *sk_prf,
                                                const unsigned char *optrand,
                                                const unsigned char *m,
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
static gcry_err_code_t hash_message_shake(unsigned char *digest,
                                          u64 *tree,
                                          u32 *leaf_idx,
                                          const unsigned char *R,
                                          const unsigned char *pk,
                                          const unsigned char *m,
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

  unsigned char *buf = NULL;
  unsigned char *bufp;

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
