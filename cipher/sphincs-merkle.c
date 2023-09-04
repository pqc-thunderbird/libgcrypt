#include <stdint.h>
#include <string.h>

#include "sphincs-utils.h"
#include "sphincs-utilsx1.h"
#include "sphincs-wots.h"
#include "sphincs-wotsx1.h"
#include "sphincs-merkle.h"
#include "sphincs-address.h"

/*
 * This generates a Merkle signature (WOTS signature followed by the Merkle
 * authentication path).  This is in this file because most of the complexity
 * is involved with the WOTS signature; the Merkle authentication path logic
 * is mostly hidden in treehashx4
 */
void merkle_sign(uint8_t *sig, unsigned char *root,
                 const spx_ctx *ctx,
                 uint32_t wots_addr[8], uint32_t tree_addr[8],
                 uint32_t idx_leaf)
{
    unsigned char *auth_path = sig + ctx->WOTS_bytes;
    struct leaf_info_x1 info = { 0 };
    unsigned steps[ ctx->WOTS_len ];

    info.wots_sig = sig;
    chain_lengths(ctx, steps, root);
    info.wots_steps = steps;

    set_type(ctx, &tree_addr[0], SPX_ADDR_TYPE_HASHTREE);
    set_type(ctx, &info.pk_addr[0], SPX_ADDR_TYPE_WOTSPK);
    copy_subtree_addr(ctx, &info.leaf_addr[0], wots_addr);
    copy_subtree_addr(ctx, &info.pk_addr[0], wots_addr);

    info.wots_sign_leaf = idx_leaf;

    treehashx1(root, auth_path, ctx,
                idx_leaf, 0,
                ctx->tree_height,
                wots_gen_leafx1,
                tree_addr, &info);
}

/* Compute root node of the top-most subtree. */
void merkle_gen_root(unsigned char *root, const spx_ctx *ctx)
{
    /* We do not need the auth path in key generation, but it simplifies the
       code to have just one treehash routine that computes both root and path
       in one function. */
    unsigned char auth_path[ctx->tree_height * ctx->n + ctx->WOTS_bytes];
    uint32_t top_tree_addr[8] = {0};
    uint32_t wots_addr[8] = {0};

    set_layer_addr(ctx, top_tree_addr, ctx->d - 1);
    set_layer_addr(ctx, wots_addr, ctx->d - 1);

    merkle_sign(auth_path, root, ctx,
                wots_addr, top_tree_addr,
                (uint32_t)~0 /* ~0 means "don't bother generating an auth path */ );
}
