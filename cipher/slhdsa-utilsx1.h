#ifndef SLHDSA_UTILSX4_H
#define SLHDSA_UTILSX4_H

#include "config.h"

#include <stdint.h>
#include "slhdsa-params.h"
#include "slhdsa-context.h"

#include "g10lib.h"

/**
 * For a given leaf index, computes the authentication path and the resulting
 * root node using Merkle's _gcry_slhdsa_treehash algorithm.
 * Expects the layer and tree parts of the tree_addr to be set, as well as the
 * tree type (i.e. SLHDSA_ADDR_TYPE_HASHTREE or SLHDSA_ADDR_TYPE_FORSTREE).
 * Applies the offset idx_offset to indices before building addresses, so that
 * it is possible to continue counting indices across trees.
 */
gcry_err_code_t
treehashx1(unsigned char *root, unsigned char *auth_path,
                const _gcry_slhdsa_param_t* ctx,
                uint32_t leaf_idx, uint32_t idx_offset, uint32_t tree_height,
                gcry_err_code_t (*gen_leaf)(
                   unsigned char* /* Where to write the leaf */,
                   const _gcry_slhdsa_param_t* /* ctx */,
                   uint32_t addr_idx, void *info),
                uint32_t tree_addrx4[8], void *info);

#endif
