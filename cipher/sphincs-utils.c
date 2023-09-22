#include "config.h"

#include <string.h>

#include "sphincs-utils.h"
#include "sphincs-hash.h"
#include "sphincs-thash.h"
#include "sphincs-address.h"

#include "g10lib.h"

/**
 * Converts the value of 'in' to 'outlen' bytes in big-endian byte order.
 */
void _gcry_sphincsplus_ull_to_bytes(unsigned char *out, unsigned int outlen,
                  unsigned long long in)
{
    int i;

    /* Iterate over out in decreasing order, for big-endianness. */
    for (i = (signed int)outlen - 1; i >= 0; i--) {
        out[i] = in & 0xff;
        in = in >> 8;
    }
}

void _gcry_sphincsplus_u32_to_bytes(unsigned char *out, uint32_t in)
{
    out[0] = (unsigned char)(in >> 24);
    out[1] = (unsigned char)(in >> 16);
    out[2] = (unsigned char)(in >> 8);
    out[3] = (unsigned char)in;
}

/**
 * Converts the inlen bytes in 'in' from big-endian byte order to an integer.
 */
unsigned long long _gcry_sphincsplus_bytes_to_ull(const unsigned char *in, unsigned int inlen)
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
gcry_err_code_t _gcry_sphincsplus_compute_root(unsigned char *root, const unsigned char *leaf,
                  uint32_t leaf_idx, uint32_t idx_offset,
                  const unsigned char *auth_path, uint32_t tree_height,
                  const _gcry_sphincsplus_param_t *ctx, uint32_t addr[8])
{
    gcry_err_code_t ec = 0;
    uint32_t i;
    //unsigned char buffer[2 * ctx->n];
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
        _gcry_sphincsplus_set_tree_height(ctx, addr, i + 1);
        _gcry_sphincsplus_set_tree_index(ctx, addr, leaf_idx + idx_offset);

        /* Pick the right or left neighbor, depending on parity of the node. */
        if (leaf_idx & 1) {
            _gcry_sphincsplus_thash(buffer + ctx->n, buffer, 2, ctx, addr);
            memcpy(buffer, auth_path, ctx->n);
        }
        else {
            _gcry_sphincsplus_thash(buffer, buffer, 2, ctx, addr);
            memcpy(buffer + ctx->n, auth_path, ctx->n);
        }
        auth_path += ctx->n;
    }

    /* The last iteration is exceptional; we do not copy an auth_path node. */
    leaf_idx >>= 1;
    idx_offset >>= 1;
    _gcry_sphincsplus_set_tree_height(ctx, addr, tree_height);
    _gcry_sphincsplus_set_tree_index(ctx, addr, leaf_idx + idx_offset);
    _gcry_sphincsplus_thash(root, buffer, 2, ctx, addr);

leave:
    xfree(buffer);
	return ec;
}

/**
 * For a given leaf index, computes the authentication path and the resulting
 * root node using Merkle's _gcry_sphincsplus_treehash algorithm.
 * Expects the layer and tree parts of the tree_addr to be set, as well as the
 * tree type (i.e. SPX_ADDR_TYPE_HASHTREE or SPX_ADDR_TYPE_FORSTREE).
 * Applies the offset idx_offset to indices before building addresses, so that
 * it is possible to continue counting indices across trees.
 */
void _gcry_sphincsplus_treehash(unsigned char *root, unsigned char *auth_path, const _gcry_sphincsplus_param_t* ctx,
              uint32_t leaf_idx, uint32_t idx_offset, uint32_t tree_height,
              void (*gen_leaf)(
                 unsigned char* /* leaf */,
                 const _gcry_sphincsplus_param_t* /* ctx */,
                 uint32_t /* addr_idx */, const uint32_t[8] /* tree_addr */),
              uint32_t tree_addr[8])
{
    SPX_VLA(uint8_t, stack, (tree_height+1)*ctx->n);
    SPX_VLA(unsigned int, heights, tree_height+1);
    unsigned int offset = 0;
    uint32_t idx;
    uint32_t tree_idx;

    for (idx = 0; idx < (uint32_t)(1 << tree_height); idx++) {
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
            _gcry_sphincsplus_set_tree_height(ctx, tree_addr, heights[offset - 1] + 1);
            _gcry_sphincsplus_set_tree_index(ctx, tree_addr,
                           tree_idx + (idx_offset >> (heights[offset-1] + 1)));
            /* Hash the top-most nodes from the stack together. */
            _gcry_sphincsplus_thash(stack + (offset - 2)*ctx->n,
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
}
