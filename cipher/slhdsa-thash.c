#include <config.h>

#include "types.h"
#include <string.h>

#include "slhdsa-thash.h"
#include "slhdsa-address.h"
#include "slhdsa-utils.h"

#include "slhdsa-sha2.h"

#include "g10lib.h"


/**
 * Takes an array of inblocks concatenated arrays of ctx->n bytes.
 */
static gcry_err_code_t
thash_shake_simple(unsigned char *out, const unsigned char *in, unsigned int inblocks,
           const _gcry_slhdsa_param_t *ctx, u32 addr[8])
{
    gcry_err_code_t ec = 0;
    gcry_md_hd_t hd = NULL;
    byte *buf = NULL;

    buf = xtrymalloc_secure(ctx->n + ctx->addr_bytes + inblocks*ctx->n);
    if (!buf)
    {
      ec = gpg_err_code_from_syserror();
      goto leave;
    }

    memcpy(buf, ctx->pub_seed, ctx->n);
    memcpy(buf + ctx->n, addr, ctx->addr_bytes);
    memcpy(buf + ctx->n + ctx->addr_bytes, in, inblocks * ctx->n);

    ec = _gcry_md_open (&hd, GCRY_MD_SHAKE256, GCRY_MD_FLAG_SECURE);
    if (ec)
        goto leave;
    _gcry_md_write(hd, buf, ctx->n + ctx->addr_bytes + inblocks*ctx->n);
    ec = _gcry_md_extract(hd, GCRY_MD_SHAKE256, out, ctx->n);
    if (ec)
        goto leave;

leave:
    _gcry_md_close(hd);
    xfree(buf);
	return ec;
}

static gcry_err_code_t thash_512_simple(unsigned char *out, const unsigned char *in, unsigned int inblocks,
           const _gcry_slhdsa_param_t *ctx, u32 addr[8]);

/**
 * Takes an array of inblocks concatenated arrays of ctx->n bytes.
 */
static gcry_err_code_t
thash_sha2_simple(unsigned char *out, const unsigned char *in, unsigned int inblocks,
           const _gcry_slhdsa_param_t *ctx, u32 addr[8])
{
    gcry_err_code_t ec;
    gcry_md_hd_t hd = NULL;
    unsigned char sha256_pubseed_block[SLHDSA_SHA256_BLOCK_BYTES];

    if(ctx->do_use_sha512)
    {
        if (inblocks > 1) {
            return thash_512_simple(out, in, inblocks, ctx, addr);
        }
    }

    memset(sha256_pubseed_block, 0, SLHDSA_SHA256_BLOCK_BYTES);
    memcpy(sha256_pubseed_block, ctx->pub_seed, ctx->n);

    ec = _gcry_md_open (&hd, GCRY_MD_SHA256, GCRY_MD_FLAG_SECURE);
    if (ec)
        goto leave;
    _gcry_md_write(hd, sha256_pubseed_block, SLHDSA_SHA256_BLOCK_BYTES);
    _gcry_md_write(hd, (byte*)addr, SLHDSA_SHA256_ADDR_BYTES);
    _gcry_md_write(hd, in, inblocks * ctx->n);
    memcpy(out, _gcry_md_read(hd, GCRY_MD_SHA256), ctx->n);

leave:
    _gcry_md_close(hd);
    return ec;
}

static gcry_err_code_t thash_512_simple(unsigned char *out, const unsigned char *in, unsigned int inblocks,
           const _gcry_slhdsa_param_t *ctx, u32 addr[8])
{
    gcry_err_code_t ec;
    gcry_md_hd_t hd = NULL;
    unsigned char sha512_pubseed_block[SLHDSA_SHA512_BLOCK_BYTES];

    memset(sha512_pubseed_block, 0, SLHDSA_SHA512_BLOCK_BYTES);
    memcpy(sha512_pubseed_block, ctx->pub_seed, ctx->n);

    ec = _gcry_md_open (&hd, GCRY_MD_SHA512, GCRY_MD_FLAG_SECURE);
    if (ec)
        goto leave;
    _gcry_md_write(hd, sha512_pubseed_block, SLHDSA_SHA512_BLOCK_BYTES);
    _gcry_md_write(hd, (byte*)addr, SLHDSA_SHA256_ADDR_BYTES);
    _gcry_md_write(hd, in, inblocks * ctx->n);
    memcpy(out, _gcry_md_read(hd, GCRY_MD_SHA512), ctx->n);

leave:
    _gcry_md_close(hd);
    return ec;
}

gcry_err_code_t _gcry_slhdsa_thash(unsigned char *out, const unsigned char *in, unsigned int inblocks,
           const _gcry_slhdsa_param_t *ctx, u32 addr[8])
{
    if(ctx->is_sha2)
    {
        return thash_sha2_simple(out, in, inblocks, ctx, addr);
    }
    return thash_shake_simple(out, in, inblocks, ctx, addr);
}