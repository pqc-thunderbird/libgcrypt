#include "config.h"

#include <string.h>

#include "slhdsa-utils.h"
#include "slhdsa-utilsx1.h"
#include "slhdsa-params.h"
#include "slhdsa-thash.h"
#include "slhdsa-address.h"

#include "g10lib.h"

/*
 * Generate the entire Merkle tree, computing the authentication path for
 * leaf_idx, and the resulting root node using Merkle's _gcry_slhdsa_treehash algorithm.
 * Expects the layer and tree parts of the tree_addr to be set, as well as the
 * tree type (i.e. SLHDSA_ADDR_TYPE_HASHTREE or SLHDSA_ADDR_TYPE_FORSTREE)
 *
 * This expects tree_addr to be initialized to the addr structures for the
 * Merkle tree nodes
 *
 * Applies the offset idx_offset to indices before building addresses, so that
 * it is possible to continue counting indices across trees.
 *
 * This works by using the standard Merkle tree building algorithm,
 */
gcry_err_code_t treehashx1(unsigned char *root, unsigned char *auth_path,
                const _gcry_slhdsa_param_t* ctx,
                u32 leaf_idx, u32 idx_offset,
                u32 tree_height,
                gcry_err_code_t (*gen_leaf)(
                   unsigned char* /* Where to write the leaves */,
                   const _gcry_slhdsa_param_t* /* ctx */,
                   u32 idx, void *info),
                u32 tree_addr[8],
                void *info)
{
    gcry_err_code_t ec = 0;
    u32 idx;
    u32 max_idx = (u32)((1 << tree_height) - 1);

    /* This is where we keep the intermediate nodes */
    byte *stack = NULL;
    unsigned char *current = NULL;

    stack = xtrymalloc_secure(tree_height*ctx->n);
    if (!stack)
    {
      ec = gpg_err_code_from_syserror();
      goto leave;
    }

    for (idx = 0;; idx++) {
        u32 internal_idx_offset = idx_offset;
        u32 internal_idx = idx;
        u32 internal_leaf = leaf_idx;
        u32 h;     /* The height we are in the Merkle tree */
        /* variable current: Current logical node is at */
            /* index[ctx->n].  We do this to minimize the number of copies */
            /* needed during a _gcry_slhdsa_thash */

        xfree(current); /* free for previous loop iteration */
        current = xtrymalloc_secure(2*ctx->n);
        if (!current)
        {
            ec = gpg_err_code_from_syserror();
            goto leave;
        }

        /* TODO check error code */
        gen_leaf( &current[ctx->n], ctx, idx + idx_offset,
                    info );

        /* Now combine the freshly generated right node with previously */
        /* generated left ones */
        for (h=0;; h++, internal_idx >>= 1, internal_leaf >>= 1) {
            unsigned char *left;

            /* Check if we hit the top of the tree */
            if (h == tree_height) {
                /* We hit the root; return it */
                memcpy( root, &current[ctx->n], ctx->n );
                goto leave;
            }

            /*
             * Check if the node we have is a part of the
             * authentication path; if it is, write it out
             */
            if ((internal_idx ^ internal_leaf) == 0x01) {
                memcpy( &auth_path[ h * ctx->n ],
                        &current[ctx->n],
                        ctx->n );
            }

            /*
             * Check if we're at a left child; if so, stop going up the stack
             * Exception: if we've reached the end of the tree, keep on going
             * (so we combine the last 4 nodes into the one root node in two
             * more iterations)
             */
            if ((internal_idx & 1) == 0 && idx < max_idx) {
                break;
            }

            /* Ok, we're at a right node */
            /* Now combine the left and right logical nodes together */

            /* Set the address of the node we're creating. */
            internal_idx_offset >>= 1;
            _gcry_slhdsa_set_tree_height(ctx, tree_addr, h + 1);
            _gcry_slhdsa_set_tree_index(ctx, tree_addr, internal_idx/2 + internal_idx_offset );

            left = &stack[h * ctx->n];
            memcpy( &current[0], left, ctx->n );
            _gcry_slhdsa_thash( &current[1 * ctx->n],
                   &current[0 * ctx->n],
                   2, ctx, tree_addr);
        }

        /* We've hit a left child; save the current for when we get the */
        /* corresponding right right */
        memcpy( &stack[h * ctx->n], &current[ctx->n], ctx->n);
    }

leave:
    xfree(stack);
    xfree(current);
	return ec;
}
