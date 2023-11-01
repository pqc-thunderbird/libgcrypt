#ifndef SLHDSA_UTILS_H
#define SLHDSA_UTILS_H

#include "config.h"

#include "types.h"
#include "slhdsa-params.h"
#include "slhdsa-context.h"

#include "g10lib.h"

/**
 * Converts the value of 'in' to 'outlen' bytes in big-endian byte order.
 */
void _gcry_slhdsa_ull_to_bytes(unsigned char *out, unsigned int outlen,
                  unsigned long long in);
void _gcry_slhdsa_u32_to_bytes(unsigned char *out, u32 in);

/**
 * Converts the inlen bytes in 'in' from big-endian byte order to an integer.
 */
unsigned long long _gcry_slhdsa_bytes_to_ull(const unsigned char *in, unsigned int inlen);

/**
 * Computes a root node given a leaf and an auth path.
 * Expects address to be complete other than the tree_height and tree_index.
 */
gcry_err_code_t _gcry_slhdsa_compute_root(unsigned char *root, const unsigned char *leaf,
                  u32 leaf_idx, u32 idx_offset,
                  const unsigned char *auth_path, u32 tree_height,
                  const _gcry_slhdsa_param_t *ctx, u32 addr[8]);

/**
 * For a given leaf index, computes the authentication path and the resulting
 * root node using Merkle's _gcry_slhdsa_treehash algorithm.
 * Expects the layer and tree parts of the tree_addr to be set, as well as the
 * tree type (i.e. SLHDSA_ADDR_TYPE_HASHTREE or SLHDSA_ADDR_TYPE_FORSTREE).
 * Applies the offset idx_offset to indices before building addresses, so that
 * it is possible to continue counting indices across trees.
 */
gcry_err_code_t _gcry_slhdsa_treehash(unsigned char *root, unsigned char *auth_path,
              const _gcry_slhdsa_param_t* ctx,
              u32 leaf_idx, u32 idx_offset, u32 tree_height,
              gcry_err_code_t (*gen_leaf)(
                 unsigned char* /* leaf */,
                 const _gcry_slhdsa_param_t* ctx /* ctx */,
                 u32 /* addr_idx */, const u32[8] /* tree_addr */),
              u32 tree_addr[8]);


#endif
