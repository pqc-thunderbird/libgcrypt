#include <config.h>

#include <stdint.h>
#include <string.h>

#include "sphincs-address.h"
#include "sphincs-utils.h"
#include "sphincs-params.h"
#include "sphincs-hash.h"
#include "sphincs-sha2.h"
#include "sphincs-fips202.h"
#include "g10lib.h"


static void initialize_hash_function_sha2(spx_ctx *ctx);
static void initialize_hash_function_shake(spx_ctx *ctx);
static void prf_addr_sha2(unsigned char *out, const spx_ctx *ctx,
              const uint32_t addr[8]);
static void prf_addr_shake(unsigned char *out, const spx_ctx *ctx,
              const uint32_t addr[8]);
static void gen_message_random_sha2(unsigned char *R, const unsigned char *sk_prf,
        const unsigned char *optrand,
        const unsigned char *m, unsigned long long mlen,
        const spx_ctx *ctx);
static void gen_message_random_shake(unsigned char *R, const unsigned char *sk_prf,
        const unsigned char *optrand,
        const unsigned char *m, unsigned long long mlen,
        const spx_ctx *ctx);
static void hash_message_sha2(unsigned char *digest, uint64_t *tree, uint32_t *leaf_idx,
                  const unsigned char *R, const unsigned char *pk,
                  const unsigned char *m, unsigned long long mlen,
                  const spx_ctx *ctx);
static void hash_message_shake(unsigned char *digest, uint64_t *tree, uint32_t *leaf_idx,
                  const unsigned char *R, const unsigned char *pk,
                  const unsigned char *m, unsigned long long mlen,
                  const spx_ctx *ctx);


void initialize_hash_function(spx_ctx *ctx)
{
    if(ctx->is_sha2)
    {
        initialize_hash_function_sha2(ctx);
    }
    else
    {
        initialize_hash_function_shake(ctx);
    }
}

void prf_addr(unsigned char *out, const spx_ctx *ctx,
              const uint32_t addr[8])
{
    if(ctx->is_sha2)
    {
        prf_addr_sha2(out, ctx, addr);
    }
    else
    {
        prf_addr_shake(out, ctx, addr);
    }
}

void gen_message_random(unsigned char *R, const unsigned char *sk_prf,
                        const unsigned char *optrand,
                        const unsigned char *m, unsigned long long mlen,
                        const spx_ctx *ctx)
{
    if(ctx->is_sha2)
    {
        gen_message_random_sha2(R, sk_prf, optrand, m, mlen, ctx);
    }
    else
    {
        gen_message_random_shake(R, sk_prf, optrand, m, mlen, ctx);
    }
}

void hash_message(unsigned char *digest, uint64_t *tree, uint32_t *leaf_idx,
                  const unsigned char *R, const unsigned char *pk,
                  const unsigned char *m, unsigned long long mlen,
                  const spx_ctx *ctx)

{
    if(ctx->is_sha2)
    {
        hash_message_sha2(digest, tree, leaf_idx, R, pk, m, mlen, ctx);
    }
    else
    {
        hash_message_shake(digest, tree, leaf_idx, R, pk, m, mlen, ctx);
    }
}
typedef struct {
    uint8_t shax_output_bytes;
    uint8_t shax_block_bytes;
    void (*shaX_inc_init)(uint8_t*);
    void (*shaX_inc_blocks)(uint8_t*, const uint8_t*, size_t);
    void (*shaX_inc_finalize)(uint8_t*, uint8_t*, const uint8_t*, size_t);
    void (*shaX)(uint8_t*, const uint8_t*, size_t);
    void (*mgf1_X)(unsigned char*, unsigned long, const unsigned char*, unsigned long);
} shaX_cfg;

static void shaX_cfg_init(shaX_cfg *ctx, uint8_t n)
{
    if(n >= 24)
    {
        ctx->shax_output_bytes = SPX_SHA512_OUTPUT_BYTES;
        ctx->shax_block_bytes = SPX_SHA512_BLOCK_BYTES;
        ctx->shaX_inc_init = &sha512_inc_init;
        ctx->shaX_inc_blocks = &sha512_inc_blocks;
        ctx->shaX_inc_finalize = &sha512_inc_finalize;
        ctx->shaX = &sha512;
        ctx->mgf1_X = &mgf1_512;
    }
    else {
        ctx->shax_output_bytes = SPX_SHA256_OUTPUT_BYTES;
        ctx->shax_block_bytes = SPX_SHA256_BLOCK_BYTES;
        ctx->shaX_inc_init = &sha256_inc_init;
        ctx->shaX_inc_blocks = &sha256_inc_blocks;
        ctx->shaX_inc_finalize = &sha256_inc_finalize;
        ctx->shaX = &sha256;
        ctx->mgf1_X = &mgf1_256;
    }
}


/* For SHA, there is no immediate reason to initialize at the start,
   so this function is an empty operation. */
void initialize_hash_function_sha2(spx_ctx *ctx)
{
    seed_state(ctx);
}

/*
 * Computes PRF(pk_seed, sk_seed, addr).
 */
static void prf_addr_sha2(unsigned char *out, const spx_ctx *ctx,
              const uint32_t addr[8])
{
    uint8_t sha2_state[40];
    unsigned char buf[SPX_SHA256_ADDR_BYTES + ctx->n];
    unsigned char outbuf[SPX_SHA256_OUTPUT_BYTES];

    /* Retrieve precomputed state containing pub_seed */
    memcpy(sha2_state, ctx->state_seeded, 40 * sizeof(uint8_t));

    /* Remainder: ADDR^c ‖ SK.seed */
    memcpy(buf, addr, SPX_SHA256_ADDR_BYTES);
    memcpy(buf + SPX_SHA256_ADDR_BYTES, ctx->sk_seed, ctx->n);

    sha256_inc_finalize(outbuf, sha2_state, buf, SPX_SHA256_ADDR_BYTES + ctx->n);

    memcpy(out, outbuf, ctx->n);
}

/**
 * Computes the message-dependent randomness R, using a secret seed as a key
 * for HMAC, and an optional randomization value prefixed to the message.
 * This requires m to have at least shax_ctx.shax_block_bytes + ctx->n space
 * available in front of the pointer, i.e. before the message to use for the
 * prefix. This is necessary to prevent having to move the message around (and
 * allocate memory for it).
 */
static void gen_message_random_sha2(unsigned char *R, const unsigned char *sk_prf,
                        const unsigned char *optrand,
                        const unsigned char *m, unsigned long long mlen,
                        const spx_ctx *ctx)
{
    (void)ctx;
    shaX_cfg shax_ctx;
    shaX_cfg_init(&shax_ctx, ctx->n);

    unsigned char buf[shax_ctx.shax_block_bytes + shax_ctx.shax_output_bytes];
    uint8_t state[8 + shax_ctx.shax_output_bytes];
    int i;

/* TODO: asssert? */
// #if ctx->n > shax_ctx.shax_block_bytes
//     #error "Currently only supports ctx->n of at most shax_ctx.shax_block_bytes"
// #endif

    /* This implements HMAC-SHA */
    for (i = 0; i < ctx->n; i++) {
        buf[i] = 0x36 ^ sk_prf[i];
    }
    memset(buf + ctx->n, 0x36, shax_ctx.shax_block_bytes - ctx->n);

    shax_ctx.shaX_inc_init(state);
    shax_ctx.shaX_inc_blocks(state, buf, 1);

    memcpy(buf, optrand, ctx->n);

    /* If optrand + message cannot fill up an entire block */
    if (ctx->n + mlen < shax_ctx.shax_block_bytes) {
        memcpy(buf + ctx->n, m, mlen);
        shax_ctx.shaX_inc_finalize(buf + shax_ctx.shax_block_bytes, state,
                            buf, mlen + ctx->n);
    }
    /* Otherwise first fill a block, so that finalize only uses the message */
    else {
        memcpy(buf + ctx->n, m, shax_ctx.shax_block_bytes - ctx->n);
        shax_ctx.shaX_inc_blocks(state, buf, 1);

        m += shax_ctx.shax_block_bytes - ctx->n;
        mlen -= shax_ctx.shax_block_bytes - ctx->n;
        shax_ctx.shaX_inc_finalize(buf + shax_ctx.shax_block_bytes, state, m, mlen);
    }

    for (i = 0; i < ctx->n; i++) {
        buf[i] = 0x5c ^ sk_prf[i];
    }
    memset(buf + ctx->n, 0x5c, shax_ctx.shax_block_bytes - ctx->n);

    shax_ctx.shaX(buf, buf, shax_ctx.shax_block_bytes + shax_ctx.shax_output_bytes);
    memcpy(R, buf, ctx->n);
}

/**
 * Computes the message hash using R, the public key, and the message.
 * Outputs the message digest and the index of the leaf. The index is split in
 * the tree index and the leaf index, for convenient copying to an address.
 */
static void hash_message_sha2(unsigned char *digest, uint64_t *tree, uint32_t *leaf_idx,
                  const unsigned char *R, const unsigned char *pk,
                  const unsigned char *m, unsigned long long mlen,
                  const spx_ctx *ctx)
{
    (void)ctx;
    shaX_cfg shax_ctx;
    shaX_cfg_init(&shax_ctx, ctx->n);
//#define SPX_TREE_BITS (ctx->tree_height * (ctx->d - 1))
//#define SPX_TREE_BYTES ((SPX_TREE_BITS + 7) / 8)
//#define SPX_LEAF_BITS ctx->tree_height
//#define SPX_LEAF_BYTES ((SPX_LEAF_BITS + 7) / 8)
//#define SPX_DGST_BYTES (ctx->FORS_msg_bytes + SPX_TREE_BYTES + SPX_LEAF_BYTES)
    size_t SPX_TREE_BITS = (ctx->tree_height * (ctx->d - 1));
    size_t SPX_TREE_BYTES = ((SPX_TREE_BITS + 7) / 8);
    size_t SPX_LEAF_BITS = ctx->tree_height;
    size_t SPX_LEAF_BYTES = ((SPX_LEAF_BITS + 7) / 8);
    size_t SPX_DGST_BYTES = (ctx->FORS_msg_bytes + SPX_TREE_BYTES + SPX_LEAF_BYTES);

    unsigned char seed[2*ctx->n + shax_ctx.shax_output_bytes];

    /* Round to nearest multiple of shax_ctx.shax_block_bytes */
// TODO: assert?
//#if (shax_ctx.shax_block_bytes & (shax_ctx.shax_block_bytes-1)) != 0
//    #error "Assumes that shax_ctx.shax_block_bytes is a power of 2"
//#endif
#define SPX_INBLOCKS (((ctx->n + ctx->public_key_bytes + shax_ctx.shax_block_bytes - 1) & \
                        -shax_ctx.shax_block_bytes) / shax_ctx.shax_block_bytes)
    unsigned char inbuf[SPX_INBLOCKS * shax_ctx.shax_block_bytes];

    unsigned char buf[SPX_DGST_BYTES];
    unsigned char *bufp = buf;
    uint8_t state[8 + shax_ctx.shax_output_bytes];

    shax_ctx.shaX_inc_init(state);

    // seed: SHA-X(R ‖ PK.seed ‖ PK.root ‖ M)
    memcpy(inbuf, R, ctx->n);
    memcpy(inbuf + ctx->n, pk, ctx->public_key_bytes);

    /* If R + pk + message cannot fill up an entire block */
    if (ctx->n + ctx->public_key_bytes + mlen < SPX_INBLOCKS * shax_ctx.shax_block_bytes) {
        memcpy(inbuf + ctx->n + ctx->public_key_bytes, m, mlen);
        shax_ctx.shaX_inc_finalize(seed + 2*ctx->n, state, inbuf, ctx->n + ctx->public_key_bytes + mlen);
    }
    /* Otherwise first fill a block, so that finalize only uses the message */
    else {
        memcpy(inbuf + ctx->n + ctx->public_key_bytes, m,
               SPX_INBLOCKS * shax_ctx.shax_block_bytes - ctx->n - ctx->public_key_bytes);
        shax_ctx.shaX_inc_blocks(state, inbuf, SPX_INBLOCKS);

        m += SPX_INBLOCKS * shax_ctx.shax_block_bytes - ctx->n - ctx->public_key_bytes;
        mlen -= SPX_INBLOCKS * shax_ctx.shax_block_bytes - ctx->n - ctx->public_key_bytes;
        shax_ctx.shaX_inc_finalize(seed + 2*ctx->n, state, m, mlen);
    }

    // H_msg: MGF1-SHA-X(R ‖ PK.seed ‖ seed)
    memcpy(seed, R, ctx->n);
    memcpy(seed + ctx->n, pk, ctx->n);

    /* By doing this in two steps, we prevent hashing the message twice;
       otherwise each iteration in MGF1 would hash the message again. */
    shax_ctx.mgf1_X(bufp, SPX_DGST_BYTES, seed, 2*ctx->n + shax_ctx.shax_output_bytes);

    memcpy(digest, bufp, ctx->FORS_msg_bytes);
    bufp += ctx->FORS_msg_bytes;

#if SPX_TREE_BITS > 64
    #error For given height and depth, 64 bits cannot represent all subtrees
#endif

    *tree = bytes_to_ull(bufp, SPX_TREE_BYTES);
    *tree &= (~(uint64_t)0) >> (64 - SPX_TREE_BITS);
    bufp += SPX_TREE_BYTES;

    *leaf_idx = (uint32_t)bytes_to_ull(bufp, SPX_LEAF_BYTES);
    *leaf_idx &= (~(uint32_t)0) >> (32 - SPX_LEAF_BITS);
}



/* For SHAKE256, there is no immediate reason to initialize at the start,
   so this function is an empty operation. */
static void initialize_hash_function_shake(spx_ctx* ctx)
{
    (void)ctx; /* Suppress an 'unused parameter' warning. */
}

/*
 * Computes PRF(pk_seed, sk_seed, addr)
 */
static void prf_addr_shake(unsigned char *out, const spx_ctx *ctx,
              const uint32_t addr[8])
{
    unsigned char buf[2*ctx->n + ctx->addr_bytes];

    memcpy(buf, ctx->pub_seed, ctx->n);
    memcpy(buf + ctx->n, addr, ctx->addr_bytes);
    memcpy(buf + ctx->n + ctx->addr_bytes, ctx->sk_seed, ctx->n);

    //shake256(out, ctx->n, buf, 2*ctx->n + ctx->addr_bytes);

    gcry_md_hd_t hd;
    _gcry_md_open (&hd, GCRY_MD_SHAKE256, GCRY_MD_FLAG_SECURE);
    _gcry_md_write(hd, buf, 2*ctx->n + ctx->addr_bytes);
    _gcry_md_extract(hd, GCRY_MD_SHAKE256, out, ctx->n);
    _gcry_md_close(hd);
}

/**
 * Computes the message-dependent randomness R, using a secret seed and an
 * optional randomization value as well as the message.
 */
static void gen_message_random_shake(unsigned char *R, const unsigned char *sk_prf,
                        const unsigned char *optrand,
                        const unsigned char *m, unsigned long long mlen,
                        const spx_ctx *ctx)
{
    (void)ctx;

/*
    uint64_t s_inc[26];

    shake256_inc_init(s_inc);
    shake256_inc_absorb(s_inc, sk_prf, ctx->n);
    shake256_inc_absorb(s_inc, optrand, ctx->n);
    shake256_inc_absorb(s_inc, m, mlen);
    shake256_inc_finalize(s_inc);
    shake256_inc_squeeze(R, ctx->n, s_inc);
*/

    gcry_md_hd_t hd;

   _gcry_md_open (&hd, GCRY_MD_SHAKE256, GCRY_MD_FLAG_SECURE);
   _gcry_md_write(hd, sk_prf, ctx->n);
   _gcry_md_write(hd, optrand, ctx->n);
   _gcry_md_write(hd, m, mlen);
   _gcry_md_extract(hd, GCRY_MD_SHAKE256, R, ctx->n);
   _gcry_md_close(hd);
}

/**
 * Computes the message hash using R, the public key, and the message.
 * Outputs the message digest and the index of the leaf. The index is split in
 * the tree index and the leaf index, for convenient copying to an address.
 */
static void hash_message_shake(unsigned char *digest, uint64_t *tree, uint32_t *leaf_idx,
                  const unsigned char *R, const unsigned char *pk,
                  const unsigned char *m, unsigned long long mlen,
                  const spx_ctx *ctx)
{
    (void)ctx;
#define SPX_TREE_BITS (ctx->tree_height * (ctx->d - 1))
#define SPX_TREE_BYTES ((SPX_TREE_BITS + 7) / 8)
#define SPX_LEAF_BITS ctx->tree_height
#define SPX_LEAF_BYTES ((SPX_LEAF_BITS + 7) / 8)
#define SPX_DGST_BYTES (ctx->FORS_msg_bytes + SPX_TREE_BYTES + SPX_LEAF_BYTES)

    unsigned char buf[SPX_DGST_BYTES];
    unsigned char *bufp = buf;

    gcry_md_hd_t hd;
   _gcry_md_open (&hd, GCRY_MD_SHAKE256, GCRY_MD_FLAG_SECURE);
   _gcry_md_write(hd, R, ctx->n);
   _gcry_md_write(hd, pk, ctx->public_key_bytes);
   _gcry_md_write(hd, m, mlen);
   _gcry_md_extract(hd, GCRY_MD_SHAKE256, buf, SPX_DGST_BYTES);
   _gcry_md_close(hd);

    memcpy(digest, bufp, ctx->FORS_msg_bytes);
    bufp += ctx->FORS_msg_bytes;

/* TODO: assert? */
// #if SPX_TREE_BITS > 64
//     #error For given height and depth, 64 bits cannot represent all subtrees
// #endif

    *tree = bytes_to_ull(bufp, SPX_TREE_BYTES);
    *tree &= (~(uint64_t)0) >> (64 - SPX_TREE_BITS);
    bufp += SPX_TREE_BYTES;

    *leaf_idx = (uint32_t)bytes_to_ull(bufp, SPX_LEAF_BYTES);
    *leaf_idx &= (~(uint32_t)0) >> (32 - SPX_LEAF_BITS);
}
