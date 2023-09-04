#include <config.h>

#include <stddef.h>
#include <string.h>
#include <stdint.h>

#include "sphincs-api.h"
#include "sphincs-wots.h"
#include "sphincs-fors.h"
#include "sphincs-hash.h"
#include "sphincs-thash.h"
#include "sphincs-address.h"
#include "sphincs-utils.h"
#include "sphincs-merkle.h"

#include "g10lib.h"

/*
 * Generates an SPX key pair given a seed of length
 * Format sk: [SK_SEED || SK_PRF || PUB_SEED || root]
 * Format pk: [PUB_SEED || root]
 */
int crypto_sign_seed_keypair(const spx_ctx *ctx, unsigned char *pk, unsigned char *sk,
                             const unsigned char *seed)
{
    /* Initialize SK_SEED, SK_PRF and PUB_SEED from seed. */
    memcpy(sk, seed, ctx->seed_bytes);

    memcpy(pk, sk + 2*ctx->n, ctx->n);

    memcpy(ctx->pub_seed, pk, ctx->n);
    memcpy(ctx->sk_seed, sk, ctx->n);

    /* This hook allows the hash function instantiation to do whatever
       preparation or computation it needs, based on the public seed. */
    initialize_hash_function(ctx);

    /* Compute root node of the top-most subtree. */
    merkle_gen_root(sk + 3*ctx->n, ctx);

    memcpy(pk + ctx->n, sk + 3*ctx->n, ctx->n);

    return 0;
}

/*
 * Generates an SPX key pair.
 * Format sk: [SK_SEED || SK_PRF || PUB_SEED || root]
 * Format pk: [PUB_SEED || root]
 */
int crypto_sign_keypair(const spx_ctx *ctx, unsigned char *pk, unsigned char *sk)
{
  unsigned char seed[ctx->seed_bytes];
  _gcry_randomize(seed, ctx->seed_bytes, GCRY_VERY_STRONG_RANDOM);
  crypto_sign_seed_keypair(ctx, pk, sk, seed);

  return 0;
}

/**
 * Returns an array containing a detached signature.
 */
int crypto_sign_signature(const spx_ctx *ctx, uint8_t *sig, size_t *siglen,
                          const uint8_t *m, size_t mlen, const uint8_t *sk)
{
    const unsigned char *sk_prf = sk + ctx->n;
    const unsigned char *pk = sk + 2*ctx->n;

    unsigned char optrand[ctx->n];
    unsigned char mhash[ctx->FORS_msg_bytes];
    unsigned char root[ctx->n];
    uint32_t i;
    uint64_t tree;
    uint32_t idx_leaf;
    uint32_t wots_addr[8] = {0};
    uint32_t tree_addr[8] = {0};

    memcpy(ctx->sk_seed, sk, ctx->n);
    memcpy(ctx->pub_seed, pk, ctx->n);

    /* This hook allows the hash function instantiation to do whatever
       preparation or computation it needs, based on the public seed. */
    initialize_hash_function(ctx);

    set_type(ctx, wots_addr, SPX_ADDR_TYPE_WOTS);
    set_type(ctx, tree_addr, SPX_ADDR_TYPE_HASHTREE);

    /* Optionally, signing can be made non-deterministic using optrand.
       This can help counter side-channel attacks that would benefit from
       getting a large number of traces when the signer uses the same nodes. */
    _gcry_randomize(optrand, ctx->n, GCRY_VERY_STRONG_RANDOM);
    /* Compute the digest randomization value. */
    gen_message_random(sig, sk_prf, optrand, m, mlen, ctx);

    /* Derive the message digest and leaf index from R, PK and M. */
    hash_message(mhash, &tree, &idx_leaf, sig, pk, m, mlen, ctx);
    sig += ctx->n;

    set_tree_addr(ctx, wots_addr, tree);
    set_keypair_addr(ctx, wots_addr, idx_leaf);

    /* Sign the message hash using FORS. */
    fors_sign(sig, root, mhash, ctx, wots_addr);
    sig += ctx->FORS_bytes;

    for (i = 0; i < ctx->d; i++) {
        set_layer_addr(ctx, tree_addr, i);
        set_tree_addr(ctx, tree_addr, tree);

        copy_subtree_addr(ctx, wots_addr, tree_addr);
        set_keypair_addr(ctx, wots_addr, idx_leaf);

        merkle_sign(sig, root, ctx, wots_addr, tree_addr, idx_leaf);
        sig += ctx->WOTS_bytes + ctx->tree_height * ctx->n;

        /* Update the indices for the next layer. */
        idx_leaf = (tree & ((1 << ctx->tree_height)-1));
        tree = tree >> ctx->tree_height;
    }

    *siglen = ctx->signature_bytes;

    return 0;
}

/**
 * Verifies a detached signature and message under a given public key.
 */
int crypto_sign_verify(const spx_ctx *ctx, const uint8_t *sig, size_t siglen,
                       const uint8_t *m, size_t mlen, const uint8_t *pk)
{
    const unsigned char *pub_root = pk + ctx->n;
    unsigned char mhash[ctx->FORS_msg_bytes];
    unsigned char wots_pk[ctx->WOTS_bytes];
    unsigned char root[ctx->n];
    unsigned char leaf[ctx->n];
    unsigned int i;
    uint64_t tree;
    uint32_t idx_leaf;
    uint32_t wots_addr[8] = {0};
    uint32_t tree_addr[8] = {0};
    uint32_t wots_pk_addr[8] = {0};

    if (siglen != ctx->signature_bytes) {
        return -1;
    }

    memcpy(ctx->pub_seed, pk, ctx->n);

    /* This hook allows the hash function instantiation to do whatever
       preparation or computation it needs, based on the public seed. */
    initialize_hash_function(ctx);

    set_type(ctx, wots_addr, SPX_ADDR_TYPE_WOTS);
    set_type(ctx, tree_addr, SPX_ADDR_TYPE_HASHTREE);
    set_type(ctx, wots_pk_addr, SPX_ADDR_TYPE_WOTSPK);

    /* Derive the message digest and leaf index from R || PK || M. */
    /* The additional ctx->n is a result of the hash domain separator. */
    hash_message(mhash, &tree, &idx_leaf, sig, pk, m, mlen, ctx);
    sig += ctx->n;

    /* Layer correctly defaults to 0, so no need to set_layer_addr */
    set_tree_addr(ctx, wots_addr, tree);
    set_keypair_addr(ctx, wots_addr, idx_leaf);

    fors_pk_from_sig(root, sig, mhash, ctx, wots_addr);
    sig += ctx->FORS_bytes;

    /* For each subtree.. */
    for (i = 0; i < ctx->d; i++) {
        set_layer_addr(ctx, tree_addr, i);
        set_tree_addr(ctx, tree_addr, tree);

        copy_subtree_addr(ctx, wots_addr, tree_addr);
        set_keypair_addr(ctx, wots_addr, idx_leaf);

        copy_keypair_addr(ctx, wots_pk_addr, wots_addr);

        /* The WOTS public key is only correct if the signature was correct. */
        /* Initially, root is the FORS pk, but on subsequent iterations it is
           the root of the subtree below the currently processed subtree. */
        wots_pk_from_sig(wots_pk, sig, root, ctx, wots_addr);
        sig += ctx->WOTS_bytes;

        /* Compute the leaf node using the WOTS public key. */
        thash(leaf, wots_pk, ctx->WOTS_len, ctx, wots_pk_addr);

        /* Compute the root node of this subtree. */
        compute_root(root, leaf, idx_leaf, 0, sig, ctx->tree_height,
                     ctx, tree_addr);
        sig += ctx->tree_height * ctx->n;

        /* Update the indices for the next layer. */
        idx_leaf = (tree & ((1 << ctx->tree_height)-1));
        tree = tree >> ctx->tree_height;
    }

    /* Check if the root node equals the root node in the public key. */
    if (memcmp(root, pub_root, ctx->n)) {
        return -1;
    }

    return 0;
}