/* slhdsa-sign.c
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

#include <stddef.h>
#include <string.h>
#include "types.h"

#include "slhdsa-sign.h"
#include "slhdsa-wots.h"
#include "slhdsa-fors.h"
#include "slhdsa-hash.h"
#include "slhdsa-thash.h"
#include "slhdsa-address.h"
#include "slhdsa-utils.h"
#include "slhdsa-merkle.h"

#include "g10lib.h"

/*
 * Generates an SLHDSA key pair given a seed of length
 * Format sk: [SK_SEED || SK_PRF || PUB_SEED || root]
 * Format pk: [PUB_SEED || root]
 */
gcry_err_code_t _gcry_slhdsa_seed_keypair (_gcry_slhdsa_param_t *ctx, byte *pk, byte *sk, const byte *seed)
{
  gcry_err_code_t ec = 0;

  /* Initialize SK_SEED, SK_PRF and PUB_SEED from seed. */
  memcpy (sk, seed, ctx->seed_bytes);
  memcpy (pk, sk + 2 * ctx->n, ctx->n);
  memcpy (ctx->pub_seed, pk, ctx->n);
  memcpy (ctx->sk_seed, sk, ctx->n);

  /* This hook allows the hash function instantiation to do whatever
     preparation or computation it needs, based on the public seed. */
  ec = _gcry_slhdsa_initialize_hash_function (ctx);
  if (ec)
    goto leave;

  /* Compute root node of the top-most subtree. */
  ec = _gcry_slhdsa_merkle_gen_root (sk + 3 * ctx->n, ctx);
  if (ec)
    goto leave;

  memcpy (pk + ctx->n, sk + 3 * ctx->n, ctx->n);

leave:
  return ec;
}

/*
 * Generates an SLHDSA key pair.
 * Format sk: [SK_SEED || SK_PRF || PUB_SEED || root]
 * Format pk: [PUB_SEED || root]
 */
gcry_err_code_t _gcry_slhdsa_keypair (_gcry_slhdsa_param_t *ctx, byte *pk, byte *sk)
{
  gcry_err_code_t ec = 0;
  byte *seed         = NULL;

  seed = xtrymalloc_secure (ctx->seed_bytes);
  if (!seed)
    {
      ec = gpg_err_code_from_syserror();
      goto leave;
    }

  _gcry_randomize (seed, ctx->seed_bytes, GCRY_VERY_STRONG_RANDOM);
  ec = _gcry_slhdsa_seed_keypair (ctx, pk, sk, seed);

leave:
  xfree (seed);
  return ec;
}

/**
 * Returns an array containing a detached signature.
 */
gcry_err_code_t _gcry_slhdsa_signature (
    _gcry_slhdsa_param_t *ctx, byte *sig, size_t *siglen, const byte *m, size_t mlen, const byte *sk)
{
  gcry_err_code_t ec = 0;

  const byte *sk_prf = sk + ctx->n;
  const byte *pk     = sk + 2 * ctx->n;

  u32 i;
  u64 tree;
  u32 idx_leaf;
  u32 wots_addr[8] = {0};
  u32 tree_addr[8] = {0};

  byte *optrand = NULL;
  byte *mhash   = NULL;
  byte *root    = NULL;

  optrand = xtrymalloc_secure (ctx->n);
  if (!optrand)
    {
      ec = gpg_err_code_from_syserror();
      goto leave;
    }
  mhash = xtrymalloc_secure (ctx->FORS_msg_bytes);
  if (!mhash)
    {
      ec = gpg_err_code_from_syserror();
      goto leave;
    }
  root = xtrymalloc_secure (ctx->n);
  if (!root)
    {
      ec = gpg_err_code_from_syserror();
      goto leave;
    }

  memcpy (ctx->sk_seed, sk, ctx->n);
  memcpy (ctx->pub_seed, pk, ctx->n);

  /* This hook allows the hash function instantiation to do whatever
     preparation or computation it needs, based on the public seed. */
  ec = _gcry_slhdsa_initialize_hash_function (ctx);
  if (ec)
    goto leave;

  _gcry_slhdsa_set_type (ctx, wots_addr, SLHDSA_ADDR_TYPE_WOTS);
  _gcry_slhdsa_set_type (ctx, tree_addr, SLHDSA_ADDR_TYPE_HASHTREE);

  /* Optionally, signing can be made non-deterministic using optrand.
     This can help counter side-channel attacks that would benefit from
     getting a large number of traces when the signer uses the same nodes. */
  _gcry_randomize (optrand, ctx->n, GCRY_VERY_STRONG_RANDOM);
  /* Compute the digest randomization value. */
  ec = _gcry_slhdsa_gen_message_random (sig, sk_prf, optrand, m, mlen, ctx);
  if (ec)
    goto leave;

  /* Derive the message digest and leaf index from R, PK and M. */
  ec = _gcry_slhdsa_hash_message (mhash, &tree, &idx_leaf, sig, pk, m, mlen, ctx);
  if (ec)
    goto leave;
  sig += ctx->n;

  _gcry_slhdsa_set_tree_addr (ctx, wots_addr, tree);
  _gcry_slhdsa_set_keypair_addr (ctx, wots_addr, idx_leaf);

  /* Sign the message hash using FORS. */
  ec = _gcry_slhdsa_fors_sign (sig, root, mhash, ctx, wots_addr);
  if (ec)
    goto leave;
  sig += ctx->FORS_bytes;

  for (i = 0; i < ctx->d; i++)
    {
      _gcry_slhdsa_set_layer_addr (ctx, tree_addr, i);
      _gcry_slhdsa_set_tree_addr (ctx, tree_addr, tree);

      _gcry_slhdsa_copy_subtree_addr (ctx, wots_addr, tree_addr);
      _gcry_slhdsa_set_keypair_addr (ctx, wots_addr, idx_leaf);

#ifdef USE_AVX2
      if (ctx->use_avx2)
        {
          if (ctx->is_sha2)
            {
              ec = _gcry_slhdsa_merkle_sign_avx_sha2 (sig, root, ctx, wots_addr, tree_addr, idx_leaf);
            }
          else
            {
              ec = _gcry_slhdsa_merkle_sign_avx_shake (sig, root, ctx, wots_addr, tree_addr, idx_leaf);
            }
        }
      else
#endif
        {
          ec = _gcry_slhdsa_merkle_sign (sig, root, ctx, wots_addr, tree_addr, idx_leaf);
        }
      if (ec)
        goto leave;

      sig += ctx->WOTS_bytes + ctx->tree_height * ctx->n;

      /* Update the indices for the next layer. */
      idx_leaf = (tree & ((1 << ctx->tree_height) - 1));
      tree     = tree >> ctx->tree_height;
    }

  *siglen = ctx->signature_bytes;

leave:
  xfree (optrand);
  xfree (mhash);
  xfree (root);
  return ec;
}

/**
 * Verifies a detached signature and message under a given public key.
 */
gcry_err_code_t _gcry_slhdsa_verify (
    _gcry_slhdsa_param_t *ctx, const byte *sig, size_t siglen, const byte *m, size_t mlen, const byte *pk)
{
  gcry_err_code_t ec   = 0;
  const byte *pub_root = pk + ctx->n;
  byte *mhash          = NULL;
  byte *wots_pk        = NULL;
  byte *root           = NULL;
  byte *leaf           = NULL;
  unsigned int i;
  u64 tree;
  u32 idx_leaf;
  u32 wots_addr[8]    = {0};
  u32 tree_addr[8]    = {0};
  u32 wots_pk_addr[8] = {0};

  if (siglen != ctx->signature_bytes)
    {
      ec = GPG_ERR_BAD_SIGNATURE;
      goto leave;
    }

  mhash = xtrymalloc (ctx->FORS_msg_bytes);
  if (!mhash)
    {
      ec = gpg_err_code_from_syserror();
      goto leave;
    }
  wots_pk = xtrymalloc (ctx->WOTS_bytes);
  if (!wots_pk)
    {
      ec = gpg_err_code_from_syserror();
      goto leave;
    }
  root = xtrymalloc (ctx->n);
  if (!root)
    {
      ec = gpg_err_code_from_syserror();
      goto leave;
    }
  leaf = xtrymalloc (ctx->n);
  if (!leaf)
    {
      ec = gpg_err_code_from_syserror();
      goto leave;
    }

  memcpy (ctx->pub_seed, pk, ctx->n);

  /* This hook allows the hash function instantiation to do whatever
     preparation or computation it needs, based on the public seed. */
  ec = _gcry_slhdsa_initialize_hash_function (ctx);
  if (ec)
    goto leave;

  _gcry_slhdsa_set_type (ctx, wots_addr, SLHDSA_ADDR_TYPE_WOTS);
  _gcry_slhdsa_set_type (ctx, tree_addr, SLHDSA_ADDR_TYPE_HASHTREE);
  _gcry_slhdsa_set_type (ctx, wots_pk_addr, SLHDSA_ADDR_TYPE_WOTSPK);

  /* Derive the message digest and leaf index from R || PK || M. */
  /* The additional ctx->n is a result of the hash domain separator. */
  ec = _gcry_slhdsa_hash_message (mhash, &tree, &idx_leaf, sig, pk, m, mlen, ctx);
  if (ec)
    goto leave;
  sig += ctx->n;

  /* Layer correctly defaults to 0, so no need to _gcry_slhdsa_set_layer_addr */
  _gcry_slhdsa_set_tree_addr (ctx, wots_addr, tree);
  _gcry_slhdsa_set_keypair_addr (ctx, wots_addr, idx_leaf);

  ec = _gcry_slhdsa_fors_pk_from_sig (root, sig, mhash, ctx, wots_addr);
  if (ec)
    goto leave;
  sig += ctx->FORS_bytes;

  /* For each subtree.. */
  for (i = 0; i < ctx->d; i++)
    {
      _gcry_slhdsa_set_layer_addr (ctx, tree_addr, i);
      _gcry_slhdsa_set_tree_addr (ctx, tree_addr, tree);

      _gcry_slhdsa_copy_subtree_addr (ctx, wots_addr, tree_addr);
      _gcry_slhdsa_set_keypair_addr (ctx, wots_addr, idx_leaf);

      _gcry_slhdsa_copy_keypair_addr (ctx, wots_pk_addr, wots_addr);

      /* The WOTS public key is only correct if the signature was correct. */
      /* Initially, root is the FORS pk, but on subsequent iterations it is
         the root of the subtree below the currently processed subtree. */
#ifdef USE_AVX2
      if (ctx->use_avx2)
        {
          ec = _gcry_slhdsa_wots_pk_from_sig_avx2 (wots_pk, sig, root, ctx, wots_addr);
        }
      else
#endif
        {
          ec = _gcry_slhdsa_wots_pk_from_sig (wots_pk, sig, root, ctx, wots_addr);
        }
      if (ec)
        goto leave;
      sig += ctx->WOTS_bytes;

      /* Compute the leaf node using the WOTS public key. */
      ec = _gcry_slhdsa_thash (leaf, wots_pk, ctx->WOTS_len, ctx, wots_pk_addr);
      if (ec)
        goto leave;

      /* Compute the root node of this subtree. */
      ec = _gcry_slhdsa_compute_root (root, leaf, idx_leaf, 0, sig, ctx->tree_height, ctx, tree_addr);
      if (ec)
        goto leave;
      sig += ctx->tree_height * ctx->n;

      /* Update the indices for the next layer. */
      idx_leaf = (tree & ((1 << ctx->tree_height) - 1));
      tree     = tree >> ctx->tree_height;
    }

  /* Check if the root node equals the root node in the public key. */
  if (memcmp (root, pub_root, ctx->n))
    {
      ec = GPG_ERR_BAD_SIGNATURE;
      goto leave;
    }

leave:
  xfree (mhash);
  xfree (wots_pk);
  xfree (root);
  xfree (leaf);
  return ec;
}