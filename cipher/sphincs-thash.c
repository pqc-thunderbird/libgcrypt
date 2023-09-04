#include <stdint.h>
#include <string.h>

#include "sphincs-thash.h"
#include "sphincs-address.h"
#include "sphincs-utils.h"

#include "sphincs-fips202.h"
#include "sphincs-sha2.h"






/**
 * Takes an array of inblocks concatenated arrays of ctx->n bytes.
 */
void thash_shake_simple(unsigned char *out, const unsigned char *in, unsigned int inblocks,
           const spx_ctx *ctx, uint32_t addr[8])
{
    SPX_VLA(uint8_t, buf, ctx->n + ctx->addr_bytes + inblocks*ctx->n);

    memcpy(buf, ctx->pub_seed, ctx->n);
    memcpy(buf + ctx->n, addr, ctx->addr_bytes);
    memcpy(buf + ctx->n + ctx->addr_bytes, in, inblocks * ctx->n);

    shake256(out, ctx->n, buf, ctx->n + ctx->addr_bytes + inblocks*ctx->n);
}




/**
 * Takes an array of inblocks concatenated arrays of ctx->n bytes.
 */
void thash_shake_robust(unsigned char *out, const unsigned char *in, unsigned int inblocks,
           const spx_ctx *ctx, uint32_t addr[8])
{
    SPX_VLA(uint8_t, buf, ctx->n + ctx->addr_bytes + inblocks*ctx->n);
    SPX_VLA(uint8_t, bitmask, inblocks * ctx->n);
    unsigned int i;

    memcpy(buf, ctx->pub_seed, ctx->n);
    memcpy(buf + ctx->n, addr, ctx->addr_bytes);

    shake256(bitmask, inblocks * ctx->n, buf, ctx->n + ctx->addr_bytes);

    for (i = 0; i < inblocks * ctx->n; i++) {
        buf[ctx->n + ctx->addr_bytes + i] = in[i] ^ bitmask[i];
    }

    shake256(out, ctx->n, buf, ctx->n + ctx->addr_bytes + inblocks*ctx->n);
}









static void thash_512_simple(unsigned char *out, const unsigned char *in, unsigned int inblocks,
           const spx_ctx *ctx, uint32_t addr[8]);

/**
 * Takes an array of inblocks concatenated arrays of ctx->n bytes.
 */
void thash_sha2_simple(unsigned char *out, const unsigned char *in, unsigned int inblocks,
           const spx_ctx *ctx, uint32_t addr[8])
{
    if(ctx->do_use_sha512)
    {
        if (inblocks > 1) {
        thash_512_simple(out, in, inblocks, ctx, addr);
            return;
        }
    }

    unsigned char outbuf[SPX_SHA256_OUTPUT_BYTES];
    uint8_t sha2_state[40];
    SPX_VLA(uint8_t, buf, SPX_SHA256_ADDR_BYTES + inblocks*ctx->n);

    /* Retrieve precomputed state containing pub_seed */
    memcpy(sha2_state, ctx->state_seeded, 40 * sizeof(uint8_t));

    memcpy(buf, addr, SPX_SHA256_ADDR_BYTES);
    memcpy(buf + SPX_SHA256_ADDR_BYTES, in, inblocks * ctx->n);

    sha256_inc_finalize(outbuf, sha2_state, buf, SPX_SHA256_ADDR_BYTES + inblocks*ctx->n);
    memcpy(out, outbuf, ctx->n);
}

static void thash_512_simple(unsigned char *out, const unsigned char *in, unsigned int inblocks,
           const spx_ctx *ctx, uint32_t addr[8])
{
    unsigned char outbuf[SPX_SHA512_OUTPUT_BYTES];
    uint8_t sha2_state[72];
    SPX_VLA(uint8_t, buf, SPX_SHA256_ADDR_BYTES + inblocks*ctx->n);

    /* Retrieve precomputed state containing pub_seed */
    memcpy(sha2_state, ctx->state_seeded_512, 72 * sizeof(uint8_t));

    memcpy(buf, addr, SPX_SHA256_ADDR_BYTES);
    memcpy(buf + SPX_SHA256_ADDR_BYTES, in, inblocks * ctx->n);

    sha512_inc_finalize(outbuf, sha2_state, buf, SPX_SHA256_ADDR_BYTES + inblocks*ctx->n);
    memcpy(out, outbuf, ctx->n);
}






static void thash_512_robust(unsigned char *out, const unsigned char *in, unsigned int inblocks,
           const spx_ctx *ctx, uint32_t addr[8]);

/**
 * Takes an array of inblocks concatenated arrays of ctx->n bytes.
 */
void thash_sha2_robust(unsigned char *out, const unsigned char *in, unsigned int inblocks,
           const spx_ctx *ctx, uint32_t addr[8])
{
    if(ctx->do_use_sha512)
    {
        if (inblocks > 1) {
        thash_512_robust(out, in, inblocks, ctx, addr);
            return;
        }
    }
    unsigned char outbuf[SPX_SHA256_OUTPUT_BYTES];
    SPX_VLA(uint8_t, bitmask, inblocks * ctx->n);
    SPX_VLA(uint8_t, buf, ctx->n + SPX_SHA256_OUTPUT_BYTES + inblocks*ctx->n);
    uint8_t sha2_state[40];
    unsigned int i;

    memcpy(buf, ctx->pub_seed, ctx->n);
    memcpy(buf + ctx->n, addr, SPX_SHA256_ADDR_BYTES);
    mgf1_256(bitmask, inblocks * ctx->n, buf, ctx->n + SPX_SHA256_ADDR_BYTES);

    /* Retrieve precomputed state containing pub_seed */
    memcpy(sha2_state, ctx->state_seeded, 40 * sizeof(uint8_t));

    for (i = 0; i < inblocks * ctx->n; i++) {
        buf[ctx->n + SPX_SHA256_ADDR_BYTES + i] = in[i] ^ bitmask[i];
    }

    sha256_inc_finalize(outbuf, sha2_state, buf + ctx->n,
                        SPX_SHA256_ADDR_BYTES + inblocks*ctx->n);
    memcpy(out, outbuf, ctx->n);
}

static void thash_512_robust(unsigned char *out, const unsigned char *in, unsigned int inblocks,
           const spx_ctx *ctx, uint32_t addr[8])
{
    unsigned char outbuf[SPX_SHA512_OUTPUT_BYTES];
    SPX_VLA(uint8_t, bitmask, inblocks * ctx->n);
    SPX_VLA(uint8_t, buf, ctx->n + SPX_SHA256_ADDR_BYTES + inblocks*ctx->n);
    uint8_t sha2_state[72];
    unsigned int i;

    memcpy(buf, ctx->pub_seed, ctx->n);
    memcpy(buf + ctx->n, addr, SPX_SHA256_ADDR_BYTES);
    mgf1_512(bitmask, inblocks * ctx->n, buf, ctx->n + SPX_SHA256_ADDR_BYTES);

    /* Retrieve precomputed state containing pub_seed */
    memcpy(sha2_state, ctx->state_seeded_512, 72 * sizeof(uint8_t));

    for (i = 0; i < inblocks * ctx->n; i++) {
        buf[ctx->n + SPX_SHA256_ADDR_BYTES + i] = in[i] ^ bitmask[i];
    }

    sha512_inc_finalize(outbuf, sha2_state, buf + ctx->n,
                        SPX_SHA256_ADDR_BYTES + inblocks*ctx->n);
    memcpy(out, outbuf, ctx->n);
}


void thash(unsigned char *out, const unsigned char *in, unsigned int inblocks,
           const spx_ctx *ctx, uint32_t addr[8])
{
    /* TODO dispatch correctly later on */
    thash_sha2_simple(out, in, inblocks, ctx, addr);
}