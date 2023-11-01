#include "config.h"

#include "types.h"
#include <string.h>

#include "slhdsa-utils.h"
#include "slhdsa-utilsx1.h"
#include "slhdsa-wots.h"
#include "slhdsa-wotsx1.h"
#include "slhdsa-merkle.h"
#include "slhdsa-address.h"

#include "g10lib.h"

/*
 * This generates a Merkle signature (WOTS signature followed by the Merkle
 * authentication path).  This is in this file because most of the complexity
 * is involved with the WOTS signature; the Merkle authentication path logic
 * is mostly hidden in treehashx4
 */
gcry_err_code_t _gcry_slhdsa_merkle_sign(byte *sig, unsigned char *root,
                 const _gcry_slhdsa_param_t *ctx,
                 u32 wots_addr[8], u32 tree_addr[8],
                 u32 idx_leaf)
{
    gcry_err_code_t ec = 0;
    unsigned char *auth_path = sig + ctx->WOTS_bytes;
    struct _gcry_slhdsa_leaf_info_x1_t info = { 0 };
    unsigned *steps = NULL;

    steps = xtrymalloc_secure(sizeof(unsigned) * ctx->WOTS_len);
    if (!steps)
    {
      ec = gpg_err_code_from_syserror();
      goto leave;
    }

    info.wots_sig = sig;
    ec = _gcry_slhdsa_chain_lengths(ctx, steps, root);
    if (ec)
      goto leave;
    info.wots_steps = steps;

    _gcry_slhdsa_set_type(ctx, &tree_addr[0], SLHDSA_ADDR_TYPE_HASHTREE);
    _gcry_slhdsa_set_type(ctx, &info.pk_addr[0], SLHDSA_ADDR_TYPE_WOTSPK);
    _gcry_slhdsa_copy_subtree_addr(ctx, &info.leaf_addr[0], wots_addr);
    _gcry_slhdsa_copy_subtree_addr(ctx, &info.pk_addr[0], wots_addr);

    info.wots_sign_leaf = idx_leaf;

    ec = treehashx1(root, auth_path, ctx,
                idx_leaf, 0,
                ctx->tree_height,
                _gcry_slhdsa_wots_gen_leafx1,
                tree_addr, &info);
    if (ec)
      goto leave;

leave:
  xfree(steps);
	return ec;
}

/* Compute root node of the top-most subtree. */
gcry_err_code_t _gcry_slhdsa_merkle_gen_root(unsigned char *root, const _gcry_slhdsa_param_t *ctx)
{
    /* We do not need the auth path in key generation, but it simplifies the
       code to have just one _gcry_slhdsa_treehash routine that computes both root and path
       in one function. */
    gcry_err_code_t ec = 0;
    unsigned char *auth_path = NULL;
    u32 top_tree_addr[8] = {0};
    u32 wots_addr[8] = {0};

    auth_path = xtrymalloc_secure(ctx->tree_height * ctx->n + ctx->WOTS_bytes);
    if (!auth_path)
    {
      ec = gpg_err_code_from_syserror();
      goto leave;
    }

    _gcry_slhdsa_set_layer_addr(ctx, top_tree_addr, ctx->d - 1);
    _gcry_slhdsa_set_layer_addr(ctx, wots_addr, ctx->d - 1);

    ec = _gcry_slhdsa_merkle_sign(auth_path, root, ctx,
                wots_addr, top_tree_addr,
                (u32)~0 /* ~0 means "don't bother generating an auth path */ );

leave:
    xfree(auth_path);
	return ec;
}
