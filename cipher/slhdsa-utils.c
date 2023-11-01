#include "config.h"

#include <string.h>

#include "slhdsa-utils.h"
#include "slhdsa-hash.h"
#include "slhdsa-thash.h"
#include "slhdsa-address.h"

#include "g10lib.h"

/**
 * Converts the value of 'in' to 'outlen' bytes in big-endian byte order.
 */
void _gcry_slhdsa_ull_to_bytes(unsigned char *out, unsigned int outlen,
                  unsigned long long in)
{
    int i;

    /* Iterate over out in decreasing order, for big-endianness. */
    for (i = (signed int)outlen - 1; i >= 0; i--) {
        out[i] = in & 0xff;
        in = in >> 8;
    }
}

void _gcry_slhdsa_u32_to_bytes(unsigned char *out, u32 in)
{
    out[0] = (unsigned char)(in >> 24);
    out[1] = (unsigned char)(in >> 16);
    out[2] = (unsigned char)(in >> 8);
    out[3] = (unsigned char)in;
}

/**
 * Converts the inlen bytes in 'in' from big-endian byte order to an integer.
 */
unsigned long long _gcry_slhdsa_bytes_to_ull(const unsigned char *in, unsigned int inlen)
{
    unsigned long long retval = 0;
    unsigned int i;

    for (i = 0; i < inlen; i++) {
        retval |= ((unsigned long long)in[i]) << (8*(inlen - 1 - i));
    }
    return retval;
}

/**
 * Computes a root node given a leaf and an auth path.
 * Expects address to be complete other than the tree_height and tree_index.
 */
gcry_err_code_t _gcry_slhdsa_compute_root(unsigned char *root, const unsigned char *leaf,
                  u32 leaf_idx, u32 idx_offset,
                  const unsigned char *auth_path, u32 tree_height,
                  const _gcry_slhdsa_param_t *ctx, u32 addr[8])
{
    gcry_err_code_t ec = 0;
    u32 i;
    unsigned char *buffer = NULL;

    buffer = xtrymalloc_secure(2 * ctx->n);
    if (!buffer)
    {
      ec = gpg_err_code_from_syserror();
      goto leave;
    }

    /* If leaf_idx is odd (last bit = 1), current path element is a right child
       and auth_path has to go left. Otherwise it is the other way around. */
    if (leaf_idx & 1) {
        memcpy(buffer + ctx->n, leaf, ctx->n);
        memcpy(buffer, auth_path, ctx->n);
    }
    else {
        memcpy(buffer, leaf, ctx->n);
        memcpy(buffer + ctx->n, auth_path, ctx->n);
    }
    auth_path += ctx->n;

    for (i = 0; i < tree_height - 1; i++) {
        leaf_idx >>= 1;
        idx_offset >>= 1;
        /* Set the address of the node we're creating. */
        _gcry_slhdsa_set_tree_height(ctx, addr, i + 1);
        _gcry_slhdsa_set_tree_index(ctx, addr, leaf_idx + idx_offset);

        /* Pick the right or left neighbor, depending on parity of the node. */
        if (leaf_idx & 1) {
            _gcry_slhdsa_thash(buffer + ctx->n, buffer, 2, ctx, addr);
            memcpy(buffer, auth_path, ctx->n);
        }
        else {
            _gcry_slhdsa_thash(buffer, buffer, 2, ctx, addr);
            memcpy(buffer + ctx->n, auth_path, ctx->n);
        }
        auth_path += ctx->n;
    }

    /* The last iteration is exceptional; we do not copy an auth_path node. */
    leaf_idx >>= 1;
    idx_offset >>= 1;
    _gcry_slhdsa_set_tree_height(ctx, addr, tree_height);
    _gcry_slhdsa_set_tree_index(ctx, addr, leaf_idx + idx_offset);
    _gcry_slhdsa_thash(root, buffer, 2, ctx, addr);

leave:
    xfree(buffer);
	return ec;
}

/**
 * For a given leaf index, computes the authentication path and the resulting
 * root node using Merkle's _gcry_slhdsa_treehash algorithm.
 * Expects the layer and tree parts of the tree_addr to be set, as well as the
 * tree type (i.e. SLHDSA_ADDR_TYPE_HASHTREE or SLHDSA_ADDR_TYPE_FORSTREE).
 * Applies the offset idx_offset to indices before building addresses, so that
 * it is possible to continue counting indices across trees.
 */
gcry_err_code_t _gcry_slhdsa_treehash(unsigned char *root, unsigned char *auth_path, const _gcry_slhdsa_param_t* ctx,
              u32 leaf_idx, u32 idx_offset, u32 tree_height,
              void (*gen_leaf)(
                 unsigned char* /* leaf */,
                 const _gcry_slhdsa_param_t* /* ctx */,
                 u32 /* addr_idx */, const u32[8] /* tree_addr */),
              u32 tree_addr[8])
{
    gcry_err_code_t ec = 0;
    unsigned char *stack = NULL;
    unsigned char *heights = NULL;
    unsigned int offset = 0;
    u32 idx;
    u32 tree_idx;

    stack = xtrymalloc_secure((tree_height+1)*ctx->n);
    if (!stack)
    {
      ec = gpg_err_code_from_syserror();
      goto leave;
    }
    heights = xtrymalloc_secure(tree_height+1);
    if (!heights)
    {
      ec = gpg_err_code_from_syserror();
      goto leave;
    }

    for (idx = 0; idx < (u32)(1 << tree_height); idx++) {
        /* Add the next leaf node to the stack. */
        gen_leaf(stack + offset*ctx->n, ctx, idx + idx_offset, tree_addr);
        offset++;
        heights[offset - 1] = 0;

        /* If this is a node we need for the auth path.. */
        if ((leaf_idx ^ 0x1) == idx) {
            memcpy(auth_path, stack + (offset - 1)*ctx->n, ctx->n);
        }

        /* While the top-most nodes are of equal height.. */
        while (offset >= 2 && heights[offset - 1] == heights[offset - 2]) {
            /* Compute index of the new node, in the next layer. */
            tree_idx = (idx >> (heights[offset - 1] + 1));

            /* Set the address of the node we're creating. */
            _gcry_slhdsa_set_tree_height(ctx, tree_addr, heights[offset - 1] + 1);
            _gcry_slhdsa_set_tree_index(ctx, tree_addr,
                           tree_idx + (idx_offset >> (heights[offset-1] + 1)));
            /* Hash the top-most nodes from the stack together. */
            _gcry_slhdsa_thash(stack + (offset - 2)*ctx->n,
                  stack + (offset - 2)*ctx->n, 2, ctx, tree_addr);
            offset--;
            /* Note that the top-most node is now one layer higher. */
            heights[offset - 1]++;

            /* If this is a node we need for the auth path.. */
            if (((leaf_idx >> heights[offset - 1]) ^ 0x1) == tree_idx) {
                memcpy(auth_path + heights[offset - 1]*ctx->n,
                       stack + (offset - 1)*ctx->n, ctx->n);
            }
        }
    }
    memcpy(root, stack, ctx->n);
leave:
    xfree(stack);
    xfree(heights);
    return ec;
}
