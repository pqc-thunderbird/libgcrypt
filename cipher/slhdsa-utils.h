#ifndef SLHDSA_UTILS_H
#define SLHDSA_UTILS_H

#include "config.h"

#include "types.h"
#include "slhdsa-context.h"

#include "g10lib.h"

/**
 * Converts the value of 'in' to 'outlen' bytes in big-endian byte order.
 */
void _gcry_slhdsa_ull_to_bytes(byte *out, unsigned int outlen, unsigned long long in);
void _gcry_slhdsa_u32_to_bytes(byte *out, u32 in);

/**
 * Converts the inlen bytes in 'in' from big-endian byte order to an integer.
 */
unsigned long long _gcry_slhdsa_bytes_to_ull(const byte *in, unsigned int inlen);

/**
 * Computes a root node given a leaf and an auth path.
 * Expects address to be complete other than the tree_height and tree_index.
 */
gcry_err_code_t _gcry_slhdsa_compute_root(byte *root,
                                          const byte *leaf,
                                          u32 leaf_idx,
                                          u32 idx_offset,
                                          const byte *auth_path,
                                          u32 tree_height,
                                          const _gcry_slhdsa_param_t *ctx,
                                          u32 addr[8]);

#endif