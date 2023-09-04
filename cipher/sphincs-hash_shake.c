#include <stdint.h>
#include <string.h>

#include "sphincs-address.h"
#include "sphincs-utils.h"
#include "sphincs-params.h"
#include "sphincs-hash.h"
#include "sphincs-fips202.h"

/* For SHAKE256, there is no immediate reason to initialize at the start,
   so this function is an empty operation. */
void initialize_hash_function(spx_ctx* ctx)
{
    (void)ctx; /* Suppress an 'unused parameter' warning. */
}

/*
 * Computes PRF(pk_seed, sk_seed, addr)
 */
void prf_addr(unsigned char *out, const spx_ctx *ctx,
              const uint32_t addr[8])
{
    unsigned char buf[2*ctx->n + ctx->addr_bytes];

    memcpy(buf, ctx->pub_seed, ctx->n);
    memcpy(buf + ctx->n, addr, ctx->addr_bytes);
    memcpy(buf + ctx->n + ctx->addr_bytes, ctx->sk_seed, ctx->n);

    shake256(out, ctx->n, buf, 2*ctx->n + ctx->addr_bytes);
}

/**
 * Computes the message-dependent randomness R, using a secret seed and an
 * optional randomization value as well as the message.
 */
void gen_message_random(unsigned char *R, const unsigned char *sk_prf,
                        const unsigned char *optrand,
                        const unsigned char *m, unsigned long long mlen,
                        const spx_ctx *ctx)
{
    (void)ctx;
    uint64_t s_inc[26];

    shake256_inc_init(s_inc);
    shake256_inc_absorb(s_inc, sk_prf, ctx->n);
    shake256_inc_absorb(s_inc, optrand, ctx->n);
    shake256_inc_absorb(s_inc, m, mlen);
    shake256_inc_finalize(s_inc);
    shake256_inc_squeeze(R, ctx->n, s_inc);
}

/**
 * Computes the message hash using R, the public key, and the message.
 * Outputs the message digest and the index of the leaf. The index is split in
 * the tree index and the leaf index, for convenient copying to an address.
 */
void hash_message(unsigned char *digest, uint64_t *tree, uint32_t *leaf_idx,
                  const unsigned char *R, const unsigned char *pk,
                  const unsigned char *m, unsigned long long mlen,
                  const spx_ctx *ctx)
{
    (void)ctx;
#define SPX_TREE_BITS (ctx->tree_height * (SPX_D - 1))
#define SPX_TREE_BYTES ((SPX_TREE_BITS + 7) / 8)
#define SPX_LEAF_BITS ctx->tree_height
#define SPX_LEAF_BYTES ((SPX_LEAF_BITS + 7) / 8)
#define SPX_DGST_BYTES (ctx->FORS_msg_bytes + SPX_TREE_BYTES + SPX_LEAF_BYTES)

    unsigned char buf[SPX_DGST_BYTES];
    unsigned char *bufp = buf;
    uint64_t s_inc[26];

    shake256_inc_init(s_inc);
    shake256_inc_absorb(s_inc, R, ctx->n);
    shake256_inc_absorb(s_inc, pk, ctx->public_key_bytes);
    shake256_inc_absorb(s_inc, m, mlen);
    shake256_inc_finalize(s_inc);
    shake256_inc_squeeze(buf, SPX_DGST_BYTES, s_inc);

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
