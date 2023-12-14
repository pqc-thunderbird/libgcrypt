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