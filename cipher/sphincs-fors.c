#include "config.h"

#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "sphincs-fors.h"
#include "sphincs-utils.h"
#include "sphincs-utilsx1.h"
#include "sphincs-hash.h"
#include "sphincs-thash.h"
#include "sphincs-address.h"

#include "g10lib.h"

static void fors_gen_sk(unsigned char *sk, const _gcry_sphincsplus_param_t *ctx,
                        uint32_t fors_leaf_addr[8])
{
    _gcry_sphincsplus_prf_addr(sk, ctx, fors_leaf_addr);
}

static void fors_sk_to_leaf(unsigned char *leaf, const unsigned char *sk,
                            const _gcry_sphincsplus_param_t *ctx,
                            uint32_t fors_leaf_addr[8])
{
    _gcry_sphincsplus_thash(leaf, sk, 1, ctx, fors_leaf_addr);
}

struct fors_gen_leaf_info {
    uint32_t leaf_addrx[8];
};

static gcry_err_code_t fors_gen_leafx1(unsigned char *leaf,
                            const _gcry_sphincsplus_param_t *ctx,
                            uint32_t addr_idx, void *info)
{
    struct fors_gen_leaf_info *fors_info = info;
    uint32_t *fors_leaf_addr = fors_info->leaf_addrx;

    /* Only set the parts that the caller doesn't set */
    _gcry_sphincsplus_set_tree_index(ctx, fors_leaf_addr, addr_idx);
    _gcry_sphincsplus_set_type(ctx, fors_leaf_addr, SPX_ADDR_TYPE_FORSPRF);
    fors_gen_sk(leaf, ctx, fors_leaf_addr);

    _gcry_sphincsplus_set_type(ctx, fors_leaf_addr, SPX_ADDR_TYPE_FORSTREE);
    fors_sk_to_leaf(leaf, leaf,
                    ctx, fors_leaf_addr);

    return 0; /* TODO check return codes in calls */
}

/**
 * Interprets m as ctx->FORS_height-bit unsigned integers.
 * Assumes m contains at least ctx->FORS_height * ctx->FORS_trees bits.
 * Assumes indices has space for ctx->FORS_trees integers.
 */
static void message_to_indices(const _gcry_sphincsplus_param_t *ctx, uint32_t *indices, const unsigned char *m)
{
    unsigned int i, j;
    unsigned int offset = 0;

    for (i = 0; i < ctx->FORS_trees; i++) {
        indices[i] = 0;
        for (j = 0; j < ctx->FORS_height; j++) {
            indices[i] ^= ((m[offset >> 3] >> (offset & 0x7)) & 1u) << j;
            offset++;
        }
    }
}

/**
 * Signs a message m, deriving the secret key from sk_seed and the FTS address.
 * Assumes m contains at least ctx->FORS_height * ctx->FORS_trees bits.
 */
gcry_err_code_t _gcry_sphincsplus_fors_sign(unsigned char *sig, unsigned char *pk,
               const unsigned char *m,
               const _gcry_sphincsplus_param_t *ctx,
               const uint32_t fors_addr[8])
{
    gcry_err_code_t ec = 0;
    // uint32_t indices[ctx->FORS_trees];
    uint32_t *indices = NULL;
    // unsigned char roots[ctx->FORS_trees * ctx->n];
    unsigned char *roots = NULL;
    uint32_t fors_tree_addr[8] = {0};
    struct fors_gen_leaf_info fors_info = {0};
    uint32_t *fors_leaf_addr = fors_info.leaf_addrx;
    uint32_t fors_pk_addr[8] = {0};
    uint32_t idx_offset;
    unsigned int i;

    roots = xtrymalloc_secure(ctx->FORS_trees * ctx->n);
    if (!roots)
    {
      ec = gpg_err_code_from_syserror();
      goto leave;
    }
    indices = xtrymalloc_secure(sizeof(uint32_t) * ctx->FORS_trees);
    if (!indices)
    {
      ec = gpg_err_code_from_syserror();
      goto leave;
    }

    _gcry_sphincsplus_copy_keypair_addr(ctx, fors_tree_addr, fors_addr);
    _gcry_sphincsplus_copy_keypair_addr(ctx, fors_leaf_addr, fors_addr);

    _gcry_sphincsplus_copy_keypair_addr(ctx, fors_pk_addr, fors_addr);
    _gcry_sphincsplus_set_type(ctx, fors_pk_addr, SPX_ADDR_TYPE_FORSPK);

    message_to_indices(ctx, indices, m);

    for (i = 0; i < ctx->FORS_trees; i++) {
        idx_offset = i * (1 << ctx->FORS_height);

        _gcry_sphincsplus_set_tree_height(ctx, fors_tree_addr, 0);
        _gcry_sphincsplus_set_tree_index(ctx, fors_tree_addr, indices[i] + idx_offset);
        _gcry_sphincsplus_set_type(ctx, fors_tree_addr, SPX_ADDR_TYPE_FORSPRF);

        /* Include the secret key part that produces the selected leaf node. */
        fors_gen_sk(sig, ctx, fors_tree_addr);
        _gcry_sphincsplus_set_type(ctx, fors_tree_addr, SPX_ADDR_TYPE_FORSTREE);
        sig += ctx->n;

        /* Compute the authentication path for this leaf node. */
        treehashx1(roots + i*ctx->n, sig, ctx,
                 indices[i], idx_offset, ctx->FORS_height, fors_gen_leafx1,
                 fors_tree_addr, &fors_info);

        sig += ctx->n * ctx->FORS_height;
    }

    /* Hash horizontally across all tree roots to derive the public key. */
    _gcry_sphincsplus_thash(pk, roots, ctx->FORS_trees, ctx, fors_pk_addr);

leave:
    xfree(roots);
    xfree(indices);
	return ec;
}

/**
 * Derives the FORS public key from a signature.
 * This can be used for verification by comparing to a known public key, or to
 * subsequently verify a signature on the derived public key. The latter is the
 * typical use-case when used as an FTS below an OTS in a hypertree.
 * Assumes m contains at least ctx->FORS_height * ctx->FORS_trees bits.
 */
gcry_err_code_t _gcry_sphincsplus_fors_pk_from_sig(unsigned char *pk,
                      const unsigned char *sig, const unsigned char *m,
                      const _gcry_sphincsplus_param_t* ctx,
                      const uint32_t fors_addr[8])
{
    gcry_err_code_t ec = 0;
    // uint32_t indices[ctx->FORS_trees];
    // unsigned char roots[ctx->FORS_trees * ctx->n];
    // unsigned char leaf[ctx->n];
    uint32_t *indices = NULL;
    unsigned char *roots = NULL;
    unsigned char *leaf = NULL;
    uint32_t fors_tree_addr[8] = {0};
    uint32_t fors_pk_addr[8] = {0};
    uint32_t idx_offset;
    unsigned int i;

    indices = xtrymalloc_secure(sizeof(uint32_t) * ctx->FORS_trees);
    if (!indices)
    {
      ec = gpg_err_code_from_syserror();
      goto leave;
    }
    roots = xtrymalloc_secure(ctx->FORS_trees * ctx->n);
    if (!roots)
    {
      ec = gpg_err_code_from_syserror();
      goto leave;
    }
    leaf = xtrymalloc_secure(ctx->n);
    if (!leaf)
    {
      ec = gpg_err_code_from_syserror();
      goto leave;
    }

    _gcry_sphincsplus_copy_keypair_addr(ctx, fors_tree_addr, fors_addr);
    _gcry_sphincsplus_copy_keypair_addr(ctx, fors_pk_addr, fors_addr);

    _gcry_sphincsplus_set_type(ctx, fors_tree_addr, SPX_ADDR_TYPE_FORSTREE);
    _gcry_sphincsplus_set_type(ctx, fors_pk_addr, SPX_ADDR_TYPE_FORSPK);

    message_to_indices(ctx, indices, m);

    for (i = 0; i < ctx->FORS_trees; i++) {
        idx_offset = i * (1 << ctx->FORS_height);

        _gcry_sphincsplus_set_tree_height(ctx, fors_tree_addr, 0);
        _gcry_sphincsplus_set_tree_index(ctx, fors_tree_addr, indices[i] + idx_offset);

        /* Derive the leaf from the included secret key part. */
        fors_sk_to_leaf(leaf, sig, ctx, fors_tree_addr);
        sig += ctx->n;

        /* Derive the corresponding root node of this tree. */
        _gcry_sphincsplus_compute_root(roots + i*ctx->n, leaf, indices[i], idx_offset,
                     sig, ctx->FORS_height, ctx, fors_tree_addr);
        sig += ctx->n * ctx->FORS_height;
    }

    /* Hash horizontally across all tree roots to derive the public key. */
    _gcry_sphincsplus_thash(pk, roots, ctx->FORS_trees, ctx, fors_pk_addr);

leave:
    xfree(indices);
    xfree(roots);
    xfree(leaf);
	return ec;
}
