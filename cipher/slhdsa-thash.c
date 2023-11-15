#include <config.h>

#include "types.h"
#include <string.h>

#include "slhdsa-address.h"
#include "slhdsa-thash.h"
#include "slhdsa-utils.h"

#include "g10lib.h"

gcry_err_code_t _gcry_slhdsa_thash(
    unsigned char *out, const unsigned char *in, unsigned int inblocks, const _gcry_slhdsa_param_t *ctx, u32 addr[8])
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
          ec   = _gcry_md_copy(&hd, ctx->state_seeded_512);
        }
      else
        {
          algo = GCRY_MD_SHA256;
          ec   = _gcry_md_copy(&hd, ctx->state_seeded);
        }
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
  _gcry_md_write(hd, in, inblocks * ctx->n);

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