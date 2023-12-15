#include "config.h"

#include <stdlib.h>
#include "types.h"
#include <string.h>

#include "avx2-immintrin-support.h"

#include "slhdsa-fors.h"
#include "slhdsa-utils.h"
#include "slhdsa-utilsx1.h"
#include "slhdsa-hash.h"
#include "slhdsa-thash.h"
#include "slhdsa-address.h"

#include "g10lib.h"

static gcry_err_code_t fors_gen_sk(unsigned char *sk, const _gcry_slhdsa_param_t *ctx, u32 fors_leaf_addr[8])
{
  return _gcry_slhdsa_prf_addr(sk, ctx, fors_leaf_addr);
}

#ifdef USE_AVX2
static void fors_gen_skx8(unsigned char *sk0,
                          unsigned char *sk1,
                          unsigned char *sk2,
                          unsigned char *sk3,
                          unsigned char *sk4,
                          unsigned char *sk5,
                          unsigned char *sk6,
                          unsigned char *sk7,
                          const _gcry_slhdsa_param_t *ctx,
                          uint32_t fors_leaf_addrx8[8 * 8])
{
  if (ctx->is_sha2)
    {
      _gcry_slhdsa_prf_addrx8_sha2(sk0, sk1, sk2, sk3, sk4, sk5, sk6, sk7, ctx, fors_leaf_addrx8);
    }
  else
    {
      // TODO
    }
}
#endif

static gcry_err_code_t fors_sk_to_leaf(unsigned char *leaf,
                                       const unsigned char *sk,
                                       const _gcry_slhdsa_param_t *ctx,
                                       u32 fors_leaf_addr[8])
{
  return _gcry_slhdsa_thash(leaf, sk, 1, ctx, fors_leaf_addr);
}

#ifdef USE_AVX2
static void fors_sk_to_leafx8(unsigned char *leaf0,
                              unsigned char *leaf1,
                              unsigned char *leaf2,
                              unsigned char *leaf3,
                              unsigned char *leaf4,
                              unsigned char *leaf5,
                              unsigned char *leaf6,
                              unsigned char *leaf7,
                              const unsigned char *sk0,
                              const unsigned char *sk1,
                              const unsigned char *sk2,
                              const unsigned char *sk3,
                              const unsigned char *sk4,
                              const unsigned char *sk5,
                              const unsigned char *sk6,
                              const unsigned char *sk7,
                              const _gcry_slhdsa_param_t *ctx,
                              uint32_t fors_leaf_addrx8[8 * 8])
{
  gcry_slhdsa_thash_sha2_avx2(leaf0,
                              leaf1,
                              leaf2,
                              leaf3,
                              leaf4,
                              leaf5,
                              leaf6,
                              leaf7,
                              sk0,
                              sk1,
                              sk2,
                              sk3,
                              sk4,
                              sk5,
                              sk6,
                              sk7,
                              1,
                              ctx,
                              fors_leaf_addrx8);
}
#endif

struct fors_gen_leaf_info
{
#ifdef USE_AVX2
  u32 leaf_addrx[8 * 8];
#else
  u32 leaf_addrx[8];
#endif
};

static gcry_err_code_t fors_gen_leafx1(unsigned char *leaf, const _gcry_slhdsa_param_t *ctx, u32 addr_idx, void *info)
{
  gcry_err_code_t ec                   = 0;
  struct fors_gen_leaf_info *fors_info = info;
  u32 *fors_leaf_addr                  = fors_info->leaf_addrx;

  /* Only set the parts that the caller doesn't set */
  _gcry_slhdsa_set_tree_index(ctx, fors_leaf_addr, addr_idx);
  _gcry_slhdsa_set_type(ctx, fors_leaf_addr, SLHDSA_ADDR_TYPE_FORSPRF);
  ec = fors_gen_sk(leaf, ctx, fors_leaf_addr);
  if (ec)
    goto leave;

  _gcry_slhdsa_set_type(ctx, fors_leaf_addr, SLHDSA_ADDR_TYPE_FORSTREE);
  ec = fors_sk_to_leaf(leaf, leaf, ctx, fors_leaf_addr);

leave:
  return ec;
}

#ifdef USE_AVX2
static gcry_err_code_t fors_gen_leafx8(unsigned char *leaf, const _gcry_slhdsa_param_t *ctx, u32 addr_idx, void *info)
{
  gcry_err_code_t ec                   = 0;
  struct fors_gen_leaf_info *fors_info = info;
  u32 *fors_leaf_addrx8                = fors_info->leaf_addrx;
  unsigned int j;

  /* Only set the parts that the caller doesn't set */
  for (j = 0; j < 8; j++)
    {
      _gcry_slhdsa_set_tree_index(ctx, fors_leaf_addrx8 + j * 8, addr_idx + j);
      _gcry_slhdsa_set_type(ctx, fors_leaf_addrx8 + j * 8, SLHDSA_ADDR_TYPE_FORSPRF);
    }

  fors_gen_skx8(leaf + 0 * ctx->n,
                leaf + 1 * ctx->n,
                leaf + 2 * ctx->n,
                leaf + 3 * ctx->n,
                leaf + 4 * ctx->n,
                leaf + 5 * ctx->n,
                leaf + 6 * ctx->n,
                leaf + 7 * ctx->n,
                ctx,
                fors_leaf_addrx8);

  for (j = 0; j < 8; j++)
    {
      _gcry_slhdsa_set_type(ctx, fors_leaf_addrx8 + j * 8, SLHDSA_ADDR_TYPE_FORSTREE);
    }

  fors_sk_to_leafx8(leaf + 0 * ctx->n,
                    leaf + 1 * ctx->n,
                    leaf + 2 * ctx->n,
                    leaf + 3 * ctx->n,
                    leaf + 4 * ctx->n,
                    leaf + 5 * ctx->n,
                    leaf + 6 * ctx->n,
                    leaf + 7 * ctx->n,
                    leaf + 0 * ctx->n,
                    leaf + 1 * ctx->n,
                    leaf + 2 * ctx->n,
                    leaf + 3 * ctx->n,
                    leaf + 4 * ctx->n,
                    leaf + 5 * ctx->n,
                    leaf + 6 * ctx->n,
                    leaf + 7 * ctx->n,
                    ctx,
                    fors_leaf_addrx8);

leave:
  return ec;
}
#endif

/**
 * Interprets m as ctx->FORS_height-bit unsigned integers.
 * Assumes m contains at least ctx->FORS_height * ctx->FORS_trees bits.
 * Assumes indices has space for ctx->FORS_trees integers.
 */
static void message_to_indices(const _gcry_slhdsa_param_t *ctx, u32 *indices, const unsigned char *m)
{
  unsigned int i, j;
  unsigned int offset = 0;

  for (i = 0; i < ctx->FORS_trees; i++)
    {
      indices[i] = 0;
      for (j = 0; j < ctx->FORS_height; j++)
        {
          indices[i] ^= ((m[offset >> 3] >> (offset & 0x7)) & 1u) << j;
          offset++;
        }
    }
}

/**
 * Signs a message m, deriving the secret key from sk_seed and the FTS address.
 * Assumes m contains at least ctx->FORS_height * ctx->FORS_trees bits.
 */
gcry_err_code_t _gcry_slhdsa_fors_sign(unsigned char *sig,
                                       unsigned char *pk,
                                       const unsigned char *m,
                                       const _gcry_slhdsa_param_t *ctx,
                                       const u32 fors_addr[8])
{
  gcry_err_code_t ec   = 0;
  u32 *indices         = NULL;
  unsigned char *roots = NULL;
#ifdef USE_AVX2
  u32 fors_tree_addr[8 * 8] = {0};
#else
  u32 fors_tree_addr[8] = {0};
#endif
  struct fors_gen_leaf_info fors_info = {0};
  u32 *fors_leaf_addr                 = fors_info.leaf_addrx;
  u32 fors_pk_addr[8]                 = {0};
  u32 idx_offset;
  unsigned int i;

  roots = xtrymalloc_secure(ctx->FORS_trees * ctx->n);
  if (!roots)
    {
      ec = gpg_err_code_from_syserror();
      goto leave;
    }
  indices = xtrymalloc_secure(sizeof(u32) * ctx->FORS_trees);
  if (!indices)
    {
      ec = gpg_err_code_from_syserror();
      goto leave;
    }

#ifdef USE_AVX2
  if (ctx->use_avx2)
    {
      for (i = 0; i < 8; i++)
        {
          _gcry_slhdsa_copy_keypair_addr(ctx, fors_tree_addr + 8 * i, fors_addr);
          _gcry_slhdsa_set_type(ctx, fors_tree_addr + 8 * i, SLHDSA_ADDR_TYPE_FORSTREE);
          _gcry_slhdsa_copy_keypair_addr(ctx, fors_leaf_addr + 8 * i, fors_addr);
        }
    }
  else
#endif
    {
      _gcry_slhdsa_copy_keypair_addr(ctx, fors_tree_addr, fors_addr);
      _gcry_slhdsa_copy_keypair_addr(ctx, fors_leaf_addr, fors_addr);
    }

  _gcry_slhdsa_copy_keypair_addr(ctx, fors_pk_addr, fors_addr);
  _gcry_slhdsa_set_type(ctx, fors_pk_addr, SLHDSA_ADDR_TYPE_FORSPK);

  message_to_indices(ctx, indices, m);

  for (i = 0; i < ctx->FORS_trees; i++)
    {
      idx_offset = i * (1 << ctx->FORS_height);

      _gcry_slhdsa_set_tree_height(ctx, fors_tree_addr, 0);
      _gcry_slhdsa_set_tree_index(ctx, fors_tree_addr, indices[i] + idx_offset);
      _gcry_slhdsa_set_type(ctx, fors_tree_addr, SLHDSA_ADDR_TYPE_FORSPRF);

      /* Include the secret key part that produces the selected leaf node. */
      ec = fors_gen_sk(sig, ctx, fors_tree_addr);
      if (ec)
        goto leave;
      _gcry_slhdsa_set_type(ctx, fors_tree_addr, SLHDSA_ADDR_TYPE_FORSTREE);
      sig += ctx->n;

      /* Compute the authentication path for this leaf node. */
#ifdef USE_AVX2
      if (ctx->use_avx2)
        {
          _gcry_slhdsa_treehashx8(roots + i * ctx->n,
                                  sig,
                                  ctx,
                                  indices[i],
                                  idx_offset,
                                  ctx->FORS_height,
                                  fors_gen_leafx8,
                                  fors_tree_addr,
                                  &fors_info);
        }
      else
#endif
        {
          _gcry_slhdsa_treehashx1(roots + i * ctx->n,
                                  sig,
                                  ctx,
                                  indices[i],
                                  idx_offset,
                                  ctx->FORS_height,
                                  fors_gen_leafx1,
                                  fors_tree_addr,
                                  &fors_info);
        }
      sig += ctx->n * ctx->FORS_height;
    }

  /* Hash horizontally across all tree roots to derive the public key. */
  ec = _gcry_slhdsa_thash(pk, roots, ctx->FORS_trees, ctx, fors_pk_addr);

leave:
  xfree(roots);
  xfree(indices);
  return ec;
}

/**
 * Derives the FORS public key from a signature.
 * This can be used for verification by comparing to a known public key, or to
 * subsequently verify a signature on the derived public key. The latter is the
 * typical use-case when used as an FTS below an OTS in a hypertree.
 * Assumes m contains at least ctx->FORS_height * ctx->FORS_trees bits.
 */
gcry_err_code_t _gcry_slhdsa_fors_pk_from_sig(unsigned char *pk,
                                              const unsigned char *sig,
                                              const unsigned char *m,
                                              const _gcry_slhdsa_param_t *ctx,
                                              const u32 fors_addr[8])
{
  gcry_err_code_t ec    = 0;
  u32 *indices          = NULL;
  unsigned char *roots  = NULL;
  unsigned char *leaf   = NULL;
  u32 fors_tree_addr[8] = {0};
  u32 fors_pk_addr[8]   = {0};
  u32 idx_offset;
  unsigned int i;

  indices = xtrymalloc_secure(sizeof(u32) * ctx->FORS_trees);
  if (!indices)
    {
      ec = gpg_err_code_from_syserror();
      goto leave;
    }
  roots = xtrymalloc_secure(ctx->FORS_trees * ctx->n);
  if (!roots)
    {
      ec = gpg_err_code_from_syserror();
      goto leave;
    }
  leaf = xtrymalloc_secure(ctx->n);
  if (!leaf)
    {
      ec = gpg_err_code_from_syserror();
      goto leave;
    }

  _gcry_slhdsa_copy_keypair_addr(ctx, fors_tree_addr, fors_addr);
  _gcry_slhdsa_copy_keypair_addr(ctx, fors_pk_addr, fors_addr);

  _gcry_slhdsa_set_type(ctx, fors_tree_addr, SLHDSA_ADDR_TYPE_FORSTREE);
  _gcry_slhdsa_set_type(ctx, fors_pk_addr, SLHDSA_ADDR_TYPE_FORSPK);

  message_to_indices(ctx, indices, m);

  for (i = 0; i < ctx->FORS_trees; i++)
    {
      idx_offset = i * (1 << ctx->FORS_height);

      _gcry_slhdsa_set_tree_height(ctx, fors_tree_addr, 0);
      _gcry_slhdsa_set_tree_index(ctx, fors_tree_addr, indices[i] + idx_offset);

      /* Derive the leaf from the included secret key part. */
      fors_sk_to_leaf(leaf, sig, ctx, fors_tree_addr);
      sig += ctx->n;

      /* Derive the corresponding root node of this tree. */
      ec = _gcry_slhdsa_compute_root(
          roots + i * ctx->n, leaf, indices[i], idx_offset, sig, ctx->FORS_height, ctx, fors_tree_addr);
      if (ec)
        goto leave;
      sig += ctx->n * ctx->FORS_height;
    }

  /* Hash horizontally across all tree roots to derive the public key. */
  ec = _gcry_slhdsa_thash(pk, roots, ctx->FORS_trees, ctx, fors_pk_addr);

leave:
  xfree(indices);
  xfree(roots);
  xfree(leaf);
  return ec;
}
