#include "config.h"

#include "types.h"
#include <string.h>

#include "slhdsa-utils.h"
#include "slhdsa-utilsx1.h"
#include "slhdsa-hash.h"
#include "slhdsa-thash.h"
#include "slhdsa-wots.h"
#include "slhdsa-wotsx1.h"
#include "slhdsa-address.h"

#include "g10lib.h"

/**
 * Computes the chaining function.
 * out and in have to be n-byte arrays.
 *
 * Interprets in as start-th value of the chain.
 * addr has to contain the address of the chain.
 */
static gcry_err_code_t gen_chain(unsigned char *out,
                                 const unsigned char *in,
                                 unsigned int start,
                                 unsigned int steps,
                                 const _gcry_slhdsa_param_t *ctx,
                                 u32 addr[8])
{
  gcry_err_code_t ec = 0;
  u32 i;

  /* Initialize out with the value at position 'start'. */
  memcpy(out, in, ctx->n);

  /* Iterate 'steps' calls to the hash function. */
  for (i = start; i < (start + steps) && i < ctx->WOTS_w; i++)
    {
      _gcry_slhdsa_set_hash_addr(ctx, addr, i);
      ec = _gcry_slhdsa_thash(out, out, 1, ctx, addr);
      if (ec)
        goto leave;
    }

leave:
  return ec;
}

#ifdef USE_AVX2
/**
 * Computes up the chains
 */
static gcry_err_code_t gen_chains(unsigned char *out,
                                  const unsigned char *in,
                                  unsigned int *start,
                                  unsigned int *steps,
                                  const _gcry_slhdsa_param_t *ctx,
                                  uint32_t addr[8])
{
  gcry_err_code_t ec = 0;
  uint32_t i, j, k, idx, watching;
  int done;
  // unsigned char empty[ctx->n];
  unsigned char *bufs[8];
  byte *empty = NULL;
  uint32_t addrs[8 * 8];

  int l;
  // uint16_t counts[ctx->WOTS_w] = { 0 };
  // uint16_t idxs[ctx->WOTS_len];
  byte *counts = NULL;
  byte *idxs   = NULL;
  uint16_t total, newTotal;

  counts = xtrymalloc_secure(ctx->WOTS_w * sizeof(uint16_t));
  if (!counts)
    {
      ec = gpg_err_code_from_syserror();
      goto leave;
    }
  idxs = xtrymalloc_secure(ctx->WOTS_len * sizeof(uint16_t));
  if (!idxs)
    {
      ec = gpg_err_code_from_syserror();
      goto leave;
    }
  empty = xtrycalloc_secure(1, ctx->n);
  if (!empty)
    {
      ec = gpg_err_code_from_syserror();
      goto leave;
    }

  /* set addrs = {addr, addr, ..., addr} */
  for (j = 0; j < 8; j++)
    {
      memcpy(addrs + j * 8, addr, sizeof(uint32_t) * 8);
    }

  /* Initialize out with the value at position 'start'. */
  memcpy(out, in, ctx->WOTS_len * ctx->n);

  /* Sort the chains in reverse order by steps using counting sort. */
  for (i = 0; i < ctx->WOTS_len; i++)
    {
      counts[steps[i]]++;
    }
  total = 0;
  for (l = ctx->WOTS_w - 1; l >= 0; l--)
    {
      newTotal  = counts[l] + total;
      counts[l] = total;
      total     = newTotal;
    }
  for (i = 0; i < ctx->WOTS_len; i++)
    {
      idxs[counts[steps[i]]] = i;
      counts[steps[i]]++;
    }

  /* We got our work cut out for us: do it! */
  for (i = 0; i < ctx->WOTS_len; i += 8)
    {
      for (j = 0; j < 8 && i + j < ctx->WOTS_len; j++)
        {
          idx = idxs[i + j];
          _gcry_slhdsa_set_chain_addr(ctx, addrs + j * 8, idx);
          bufs[j] = out + ctx->n * idx;
        }

      /* As the chains are sorted in reverse order, we know that the first
       * chain is the longest and the last one is the shortest.  We keep
       * an eye on whether the last chain is done and then on the one before,
       * et cetera. */
      watching = 7;
      done     = 0;
      while (i + watching >= ctx->WOTS_len)
        {
          bufs[watching] = &empty[0];
          watching--;
        }

      for (k = 0;; k++)
        {
          while (k == steps[idxs[i + watching]])
            {
              bufs[watching] = &empty[0];
              if (watching == 0)
                {
                  done = 1;
                  break;
                }
              watching--;
            }
          if (done)
            {
              break;
            }
          for (j = 0; j < watching + 1; j++)
            {
              _gcry_slhdsa_set_hash_addr(ctx, addrs + j * 8, k + start[idxs[i + j]]);
            }

          gcry_slhdsa_thash_sha2_avx2(bufs[0],
                                      bufs[1],
                                      bufs[2],
                                      bufs[3],
                                      bufs[4],
                                      bufs[5],
                                      bufs[6],
                                      bufs[7],
                                      bufs[0],
                                      bufs[1],
                                      bufs[2],
                                      bufs[3],
                                      bufs[4],
                                      bufs[5],
                                      bufs[6],
                                      bufs[7],
                                      1,
                                      ctx,
                                      addrs);
        }
    }
leave:
  xfree(counts);
  xfree(idxs);
  xfree(empty);
  return ec;
}
#endif

/**
 * base_w algorithm as described in draft.
 * Interprets an array of bytes as integers in base w.
 * This only works when log_w is a divisor of 8.
 */
static void base_w(const _gcry_slhdsa_param_t *ctx, unsigned int *output, const int out_len, const unsigned char *input)
{
  int in  = 0;
  int out = 0;
  unsigned char total;
  int bits = 0;
  int consumed;

  for (consumed = 0; consumed < out_len; consumed++)
    {
      if (bits == 0)
        {
          total = input[in];
          in++;
          bits += 8;
        }
      bits -= ctx->WOTS_logw;
      output[out] = (total >> bits) & (ctx->WOTS_w - 1);
      out++;
    }
}

/* Computes the WOTS+ checksum over a message (in base_w). */
static gcry_err_code_t wots_checksum(const _gcry_slhdsa_param_t *ctx,
                                     unsigned int *csum_base_w,
                                     const unsigned int *msg_base_w)
{
  gcry_err_code_t ec        = 0;
  unsigned int csum         = 0;
  size_t csum_bytes_len     = (ctx->WOTS_len2 * ctx->WOTS_logw + 7) / 8;
  unsigned char *csum_bytes = NULL;
  unsigned int i;

  csum_bytes = xtrymalloc_secure(csum_bytes_len);
  if (!csum_bytes)
    {
      ec = gpg_err_code_from_syserror();
      goto leave;
    }

  /* Compute checksum. */
  for (i = 0; i < ctx->WOTS_len1; i++)
    {
      csum += ctx->WOTS_w - 1 - msg_base_w[i];
    }

  /* Convert checksum to base_w. */
  /* Make sure expected empty zero bits are the least significant bits. */
  csum = csum << ((8 - ((ctx->WOTS_len2 * ctx->WOTS_logw) % 8)) % 8);
  _gcry_slhdsa_ull_to_bytes(csum_bytes, csum_bytes_len, csum);
  base_w(ctx, csum_base_w, ctx->WOTS_len2, csum_bytes);

leave:
  xfree(csum_bytes);
  return ec;
}

/* Takes a message and derives the matching chain lengths. */
gcry_err_code_t _gcry_slhdsa_chain_lengths(const _gcry_slhdsa_param_t *ctx,
                                           unsigned int *lengths,
                                           const unsigned char *msg)
{
  base_w(ctx, lengths, ctx->WOTS_len1, msg);
  return wots_checksum(ctx, lengths + ctx->WOTS_len1, lengths);
}

/**
 * Takes a WOTS signature and an n-byte message, computes a WOTS public key.
 *
 * Writes the computed public key to 'pk'.
 */
gcry_err_code_t _gcry_slhdsa_wots_pk_from_sig(
    unsigned char *pk, const unsigned char *sig, const unsigned char *msg, const _gcry_slhdsa_param_t *ctx, u32 addr[8])
{
  gcry_err_code_t ec    = 0;
  unsigned int *lengths = NULL;
  u32 i;

  lengths = xtrymalloc_secure(sizeof(unsigned int) * ctx->WOTS_len);
  if (!lengths)
    {
      ec = gpg_err_code_from_syserror();
      goto leave;
    }

  ec = _gcry_slhdsa_chain_lengths(ctx, lengths, msg);
  if (ec)
    goto leave;

  for (i = 0; i < ctx->WOTS_len; i++)
    {
      _gcry_slhdsa_set_chain_addr(ctx, addr, i);
      ec = gen_chain(pk + i * ctx->n, sig + i * ctx->n, lengths[i], ctx->WOTS_w - 1 - lengths[i], ctx, addr);
      if (ec)
        goto leave;
    }

leave:
  xfree(lengths);
  return ec;
}

#ifdef USE_AVX2
/**
 * Takes a WOTS signature and an n-byte message, computes a WOTS public key.
 *
 * Writes the computed public key to 'pk'.
 */
gcry_err_code_t _gcry_slhdsa_wots_pk_from_sig_avx2(
    unsigned char *pk, const unsigned char *sig, const unsigned char *msg, const _gcry_slhdsa_param_t *ctx, u32 addr[8])
{
  gcry_err_code_t ec  = 0;
  unsigned int *start = NULL;
  unsigned int *steps = NULL;
  u32 i;

  start = xtrymalloc_secure(sizeof(unsigned int) * ctx->WOTS_len);
  if (!start)
    {
      ec = gpg_err_code_from_syserror();
      goto leave;
    }
  steps = xtrymalloc_secure(sizeof(unsigned int) * ctx->WOTS_len);
  if (!steps)
    {
      ec = gpg_err_code_from_syserror();
      goto leave;
    }

  ec = _gcry_slhdsa_chain_lengths(ctx, start, msg);
  if (ec)
    goto leave;

  for (i = 0; i < ctx->WOTS_len; i++)
    {
      steps[i] = ctx->WOTS_w - 1 - start[i];
    }
  ec = gen_chains(pk, sig, start, steps, ctx, addr);
  if (ec)
    goto leave;

leave:
  xfree(start);
  xfree(steps);
  return ec;
}
#endif

// TODO: gen_leafx1 here

#ifdef USE_AVX2
/*
 * This generates 8 sequential WOTS public keys
 * It also generates the WOTS signature if leaf_info indicates
 * that we're signing with one of these WOTS keys
 */
gcry_err_code_t wots_gen_leafx8(unsigned char *dest, const _gcry_slhdsa_param_t *ctx, uint32_t leaf_idx, void *v_info)
{
  gcry_err_code_t ec                       = 0;
  struct _grcy_slhdsa_leaf_info_x8_t *info = v_info;
  uint32_t *leaf_addr                      = info->leaf_addr;
  uint32_t *pk_addr                        = info->pk_addr;
  unsigned int i, j, k;
  unsigned char *pk_buffer = NULL;
  unsigned wots_offset     = ctx->WOTS_bytes;
  unsigned char *buffer;
  uint32_t wots_k_mask;
  unsigned wots_sign_index;

  pk_buffer = xtrymalloc_secure(8 * ctx->WOTS_bytes);
  if (!pk_buffer)
    {
      ec = gpg_err_code_from_syserror();
      goto leave;
    }

  if (((leaf_idx ^ info->wots_sign_leaf) & ~7) == 0)
    {
      /* We're traversing the leaf that's signing; generate the WOTS */
      /* signature */
      wots_k_mask     = 0;
      wots_sign_index = info->wots_sign_leaf & 7; /* Which of of the 8 */
                                                  /* slots do the signatures come from */
    }
  else
    {
      /* Nope, we're just generating pk's; turn off the signature logic */
      wots_k_mask     = ~0;
      wots_sign_index = 0;
    }

  for (j = 0; j < 8; j++)
    {
      _gcry_slhdsa_set_keypair_addr(ctx, leaf_addr + j * 8, leaf_idx + j);
      _gcry_slhdsa_set_keypair_addr(ctx, pk_addr + j * 8, leaf_idx + j);
    }

  for (i = 0, buffer = pk_buffer; i < ctx->WOTS_len; i++, buffer += ctx->n)
    {
      uint32_t wots_k = info->wots_steps[i] | wots_k_mask; /* Set wots_k */
      /* to the step if we're generating a signature, ~0 if we're not */

      /* Start with the secret seed */
      for (j = 0; j < 8; j++)
        {
          _gcry_slhdsa_set_chain_addr(ctx, leaf_addr + j * 8, i);
          _gcry_slhdsa_set_hash_addr(ctx, leaf_addr + j * 8, 0);
          _gcry_slhdsa_set_type(ctx, leaf_addr + j * 8, SLHDSA_ADDR_TYPE_WOTSPRF);
        }
      if (ctx->is_sha2)
        {
          _gcry_slhdsa_prf_addrx8_sha2(buffer + 0 * wots_offset,
                                       buffer + 1 * wots_offset,
                                       buffer + 2 * wots_offset,
                                       buffer + 3 * wots_offset,
                                       buffer + 4 * wots_offset,
                                       buffer + 5 * wots_offset,
                                       buffer + 6 * wots_offset,
                                       buffer + 7 * wots_offset,
                                       ctx,
                                       leaf_addr);
        }
      else
        {
          // TODO
        }

      for (j = 0; j < 8; j++)
        {
          _gcry_slhdsa_set_type(ctx, leaf_addr + j * 8, SLHDSA_ADDR_TYPE_WOTS);
        }

      /* Iterate down the WOTS chain */
      for (k = 0;; k++)
        {
          /* Check if one of the values we have needs to be saved as a */
          /* part of the WOTS signature */
          if (k == wots_k)
            {
              memcpy(info->wots_sig + i * ctx->n, buffer + wots_sign_index * wots_offset, ctx->n);
            }

          /* Check if we hit the top of the chain */
          if (k == ctx->WOTS_w - 1)
            break;

          /* Iterate one step on all 8 chains */
          for (j = 0; j < 8; j++)
            {
              _gcry_slhdsa_set_hash_addr(ctx, leaf_addr + j * 8, k);
            }
          gcry_slhdsa_thash_sha2_avx2(buffer + 0 * wots_offset,
                                      buffer + 1 * wots_offset,
                                      buffer + 2 * wots_offset,
                                      buffer + 3 * wots_offset,
                                      buffer + 4 * wots_offset,
                                      buffer + 5 * wots_offset,
                                      buffer + 6 * wots_offset,
                                      buffer + 7 * wots_offset,
                                      buffer + 0 * wots_offset,
                                      buffer + 1 * wots_offset,
                                      buffer + 2 * wots_offset,
                                      buffer + 3 * wots_offset,
                                      buffer + 4 * wots_offset,
                                      buffer + 5 * wots_offset,
                                      buffer + 6 * wots_offset,
                                      buffer + 7 * wots_offset,
                                      1,
                                      ctx,
                                      leaf_addr);
        }
    }

  /* Do the final thash to generate the public keys */
  gcry_slhdsa_thash_sha2_avx2(dest + 0 * ctx->n,
                              dest + 1 * ctx->n,
                              dest + 2 * ctx->n,
                              dest + 3 * ctx->n,
                              dest + 4 * ctx->n,
                              dest + 5 * ctx->n,
                              dest + 6 * ctx->n,
                              dest + 7 * ctx->n,
                              pk_buffer + 0 * wots_offset,
                              pk_buffer + 1 * wots_offset,
                              pk_buffer + 2 * wots_offset,
                              pk_buffer + 3 * wots_offset,
                              pk_buffer + 4 * wots_offset,
                              pk_buffer + 5 * wots_offset,
                              pk_buffer + 6 * wots_offset,
                              pk_buffer + 7 * wots_offset,
                              ctx->WOTS_len,
                              ctx,
                              pk_addr);

leave:
  xfree(pk_buffer);
  return ec;
}
#endif
