#include <config.h>

#include <stdint.h>
#include <string.h>

#include "sphincs-address.h"
#include "sphincs-utils.h"
#include "sphincs-params.h"
#include "sphincs-hash.h"
#include "sphincs-sha2.h"

#include "g10lib.h"
#include "mgf.h"



static void initialize_hash_function_sha2(_gcry_sphincsplus_param_t *ctx);
static void initialize_hash_function_shake(_gcry_sphincsplus_param_t *ctx);
static void prf_addr_sha2(unsigned char *out, const _gcry_sphincsplus_param_t *ctx,
              const uint32_t addr[8]);
static void prf_addr_shake(unsigned char *out, const _gcry_sphincsplus_param_t *ctx,
              const uint32_t addr[8]);
static gcry_err_code_t gen_message_random_sha2(unsigned char *R, const unsigned char *sk_prf,
        const unsigned char *optrand,
        const unsigned char *m, unsigned long long mlen,
        const _gcry_sphincsplus_param_t *ctx);
static void gen_message_random_shake(unsigned char *R, const unsigned char *sk_prf,
        const unsigned char *optrand,
        const unsigned char *m, unsigned long long mlen,
        const _gcry_sphincsplus_param_t *ctx);
static void hash_message_sha2(unsigned char *digest, uint64_t *tree, uint32_t *leaf_idx,
                  const unsigned char *R, const unsigned char *pk,
                  const unsigned char *m, unsigned long long mlen,
                  const _gcry_sphincsplus_param_t *ctx);
static void hash_message_shake(unsigned char *digest, uint64_t *tree, uint32_t *leaf_idx,
                  const unsigned char *R, const unsigned char *pk,
                  const unsigned char *m, unsigned long long mlen,
                  const _gcry_sphincsplus_param_t *ctx);


void _gcry_sphincsplus_initialize_hash_function(_gcry_sphincsplus_param_t *ctx)
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

void _gcry_sphincsplus_prf_addr(unsigned char *out, const _gcry_sphincsplus_param_t *ctx,
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

void _gcry_sphincsplus_gen_message_random(unsigned char *R, const unsigned char *sk_prf,
                        const unsigned char *optrand,
                        const unsigned char *m, unsigned long long mlen,
                        const _gcry_sphincsplus_param_t *ctx)
{
    if(ctx->is_sha2)
    {
        /* TODO: propagate error from call */
        gen_message_random_sha2(R, sk_prf, optrand, m, mlen, ctx);
    }
    else
    {
        gen_message_random_shake(R, sk_prf, optrand, m, mlen, ctx);
    }
}

void _gcry_sphincsplus_hash_message(unsigned char *digest, uint64_t *tree, uint32_t *leaf_idx,
                  const unsigned char *R, const unsigned char *pk,
                  const unsigned char *m, unsigned long long mlen,
                  const _gcry_sphincsplus_param_t *ctx)

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

/* For SHA, there is no immediate reason to initialize at the start,
   so this function is an empty operation. */
void initialize_hash_function_sha2(_gcry_sphincsplus_param_t *ctx)
{
    /* TODO: implement this speed optimization */
    //seed_state(ctx);
}

/*
 * Computes PRF(pk_seed, sk_seed, addr).
 */
static void prf_addr_sha2(unsigned char *out, const _gcry_sphincsplus_param_t *ctx,
              const uint32_t addr[8])
{
    unsigned char sha256_pubseed_block[SPX_SHA256_BLOCK_BYTES];
    memset(sha256_pubseed_block, 0, SPX_SHA256_BLOCK_BYTES);
    memcpy(sha256_pubseed_block, ctx->pub_seed, ctx->n);
    gcry_md_hd_t hd;
    /* TODO: md_open can give error code... */
    _gcry_md_open (&hd, GCRY_MD_SHA256, GCRY_MD_FLAG_SECURE);
    _gcry_md_write(hd, sha256_pubseed_block, SPX_SHA256_BLOCK_BYTES);
    _gcry_md_write(hd, (uint8_t*)addr, SPX_SHA256_ADDR_BYTES);
    _gcry_md_write(hd, ctx->sk_seed, ctx->n);
    memcpy(out, _gcry_md_read(hd, GCRY_MD_SHA256), ctx->n);
    _gcry_md_close(hd);

}

/**
 * Computes the message-dependent randomness R, using a secret seed as a key
 * for HMAC, and an optional randomization value prefixed to the message.
 * This requires m to have at least shax_block_bytes + ctx->n space
 * available in front of the pointer, i.e. before the message to use for the
 * prefix. This is necessary to prevent having to move the message around (and
 * allocate memory for it).
 */
static gcry_err_code_t gen_message_random_sha2(unsigned char *R, const unsigned char *sk_prf,
                        const unsigned char *optrand,
                        const unsigned char *m, unsigned long long mlen,
                        const _gcry_sphincsplus_param_t *ctx)
{
    /* HMAC-SHA-X(SK.prf, OptRand||M) */

    int hmac_shaX_algo;
    gcry_mac_hd_t hd = NULL;
    gcry_err_code_t ec;
    size_t outlen;

    if(ctx->do_use_sha512)
    {
        hmac_shaX_algo = GCRY_MAC_HMAC_SHA512;
    }
    else
    {
        hmac_shaX_algo = GCRY_MAC_HMAC_SHA256;
    }

    ec = _gcry_mac_open (&hd, hmac_shaX_algo, GCRY_MAC_FLAG_SECURE, NULL);
    if(ec)
    {
        goto leave;
    }

    ec = _gcry_mac_setkey (hd, sk_prf, ctx->n);
    if(ec)
    {
        goto leave;
    }

    ec = _gcry_mac_write (hd, optrand, ctx->n);
    if(ec)
    {
        goto leave;
    }

    ec = _gcry_mac_write (hd, m, mlen);
    if(ec)
    {
        goto leave;
    }

    ec = _gcry_mac_read (hd, R, &outlen);
    if(ec)
    {
        goto leave;
    }

    if(outlen != ctx->n)
    {
        ec = GPG_ERR_INV_STATE;
    }

leave:
    _gcry_mac_close(hd);
    return ec;
}

/**
 * Computes the message hash using R, the public key, and the message.
 * Outputs the message digest and the index of the leaf. The index is split in
 * the tree index and the leaf index, for convenient copying to an address.
 */
static void hash_message_sha2(unsigned char *digest, uint64_t *tree, uint32_t *leaf_idx,
                  const unsigned char *R, const unsigned char *pk,
                  const unsigned char *m, unsigned long long mlen,
                  const _gcry_sphincsplus_param_t *ctx)
{
    size_t SPX_TREE_BITS = (ctx->tree_height * (ctx->d - 1));
    size_t SPX_TREE_BYTES = ((SPX_TREE_BITS + 7) / 8);
    size_t SPX_LEAF_BITS = ctx->tree_height;
    size_t SPX_LEAF_BYTES = ((SPX_LEAF_BITS + 7) / 8);
    size_t SPX_DGST_BYTES = (ctx->FORS_msg_bytes + SPX_TREE_BYTES + SPX_LEAF_BYTES);
    int hash_alg;
    uint8_t shax_block_bytes;
    uint8_t shax_output_bytes;

    if(ctx->do_use_sha512)
    {
        hash_alg = GCRY_MD_SHA512;
        shax_block_bytes = SPX_SHA512_BLOCK_BYTES;
        shax_output_bytes = SPX_SHA512_OUTPUT_BYTES;
    }
    else {
        hash_alg = GCRY_MD_SHA256;
        shax_block_bytes = SPX_SHA256_BLOCK_BYTES;
        shax_output_bytes = SPX_SHA256_OUTPUT_BYTES;
    }

    unsigned char seed[2*ctx->n + shax_output_bytes];

    size_t SPX_INBLOCKS = (((ctx->n + ctx->public_key_bytes + shax_block_bytes - 1) &
                        -shax_block_bytes) / shax_block_bytes);

    unsigned char inbuf[SPX_INBLOCKS * shax_block_bytes];

    unsigned char buf[SPX_DGST_BYTES];
    unsigned char *bufp = buf;


    // seed: SHA-X(R ‖ PK.seed ‖ PK.root ‖ M)
    memcpy(inbuf, R, ctx->n);
    memcpy(inbuf + ctx->n, pk, ctx->public_key_bytes);

     gcry_md_hd_t hd;
    /* TODO: md_open can give error code... */
    _gcry_md_open (&hd, hash_alg, GCRY_MD_FLAG_SECURE);

    /* If R + pk + message cannot fill up an entire block */
    if (ctx->n + ctx->public_key_bytes + mlen < SPX_INBLOCKS * shax_block_bytes) {
        memcpy(inbuf + ctx->n + ctx->public_key_bytes, m, mlen);
        _gcry_md_write(hd, inbuf, ctx->n + ctx->public_key_bytes + mlen);
    }
    /* Otherwise first fill a block, so that finalize only uses the message */
    else {
        memcpy(inbuf + ctx->n + ctx->public_key_bytes, m,
               SPX_INBLOCKS * shax_block_bytes - ctx->n - ctx->public_key_bytes);

        _gcry_md_write(hd, inbuf, SPX_INBLOCKS*shax_block_bytes);
        m += SPX_INBLOCKS * shax_block_bytes - ctx->n - ctx->public_key_bytes;
        mlen -= SPX_INBLOCKS * shax_block_bytes - ctx->n - ctx->public_key_bytes;
        _gcry_md_write(hd, m, mlen);

    }
    memcpy(seed + 2*ctx->n, _gcry_md_read(hd, hash_alg), shax_output_bytes);
    _gcry_md_close(hd);


    // H_msg: MGF1-SHA-X(R ‖ PK.seed ‖ seed)
    memcpy(seed, R, ctx->n);
    memcpy(seed + ctx->n, pk, ctx->n);

    // TODO check err
    mgf1(bufp, SPX_DGST_BYTES, seed, 2*ctx->n + shax_output_bytes, hash_alg);


    memcpy(digest, bufp, ctx->FORS_msg_bytes);
    bufp += ctx->FORS_msg_bytes;

    *tree = _gcry_sphincsplus_bytes_to_ull(bufp, SPX_TREE_BYTES);
    *tree &= (~(uint64_t)0) >> (64 - SPX_TREE_BITS);
    bufp += SPX_TREE_BYTES;

    *leaf_idx = (uint32_t)_gcry_sphincsplus_bytes_to_ull(bufp, SPX_LEAF_BYTES);
    *leaf_idx &= (~(uint32_t)0) >> (32 - SPX_LEAF_BITS);
}



/* For SHAKE256, there is no immediate reason to initialize at the start,
   so this function is an empty operation. */
static void initialize_hash_function_shake(_gcry_sphincsplus_param_t* ctx)
{
    (void)ctx; /* Suppress an 'unused parameter' warning. */
}

/*
 * Computes PRF(pk_seed, sk_seed, addr)
 */
static void prf_addr_shake(unsigned char *out, const _gcry_sphincsplus_param_t *ctx,
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
                        const _gcry_sphincsplus_param_t *ctx)
{
    gcry_md_hd_t hd;

    /* TODO: check and return err */
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
                  const _gcry_sphincsplus_param_t *ctx)
{
    size_t SPX_TREE_BITS = ctx->tree_height * (ctx->d - 1);
    size_t SPX_TREE_BYTES = (SPX_TREE_BITS + 7) / 8;
    size_t SPX_LEAF_BITS = ctx->tree_height;
    size_t SPX_LEAF_BYTES = (SPX_LEAF_BITS + 7) / 8;
    size_t SPX_DGST_BYTES = ctx->FORS_msg_bytes + SPX_TREE_BYTES + SPX_LEAF_BYTES;

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

    *tree = _gcry_sphincsplus_bytes_to_ull(bufp, SPX_TREE_BYTES);
    *tree &= (~(uint64_t)0) >> (64 - SPX_TREE_BITS);
    bufp += SPX_TREE_BYTES;

    *leaf_idx = (uint32_t)_gcry_sphincsplus_bytes_to_ull(bufp, SPX_LEAF_BYTES);
    *leaf_idx &= (~(uint32_t)0) >> (32 - SPX_LEAF_BITS);
}
