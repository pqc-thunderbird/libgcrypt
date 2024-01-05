#ifndef SLHDSA_UTILSX4_H
#define SLHDSA_UTILSX4_H

#include "config.h"
#include "avx2-immintrin-support.h"

#include "types.h"
#include "slhdsa-context.h"

#include "g10lib.h"

/**
 * For a given leaf index, computes the authentication path and the resulting
 * root node using Merkle's TreeHash algorithm.
 * Expects the layer and tree parts of the tree_addr to be set, as well as the
 * tree type (i.e. SLHDSA_ADDR_TYPE_HASHTREE or SLHDSA_ADDR_TYPE_FORSTREE).
 * Applies the offset idx_offset to indices before building addresses, so that
 * it is possible to continue counting indices across trees.
 */
gcry_err_code_t _gcry_slhdsa_treehashx1(unsigned char *root,
                                        unsigned char *auth_path,
                                        const _gcry_slhdsa_param_t *ctx,
                                        u32 leaf_idx,
                                        u32 idx_offset,
                                        u32 tree_height,
                                        gcry_err_code_t (*gen_leaf)(unsigned char * /* Where to write the leaf */,
                                                                    const _gcry_slhdsa_param_t * /* ctx */,
                                                                    u32 addr_idx,
                                                                    void *info),
                                        u32 tree_addrx4[8],
                                        void *info);

#ifdef USE_AVX2
gcry_err_code_t _gcry_slhdsa_treehashx8(unsigned char *root,
                                        unsigned char *auth_path,
                                        const _gcry_slhdsa_param_t *ctx,
                                        uint32_t leaf_idx,
                                        uint32_t idx_offset,
                                        uint32_t tree_height,
                                        gcry_err_code_t (*gen_leafx8)(unsigned char * /* Where to write the leaves */,
                                                                      const _gcry_slhdsa_param_t *,
                                                                      uint32_t idx,
                                                                      void *info),
                                        uint32_t tree_addrx8[8 * 8],
                                        void *info);

gcry_err_code_t _gcry_slhdsa_treehashx4(unsigned char *root,
                                        unsigned char *auth_path,
                                        const _gcry_slhdsa_param_t *ctx,
                                        uint32_t leaf_idx,
                                        uint32_t idx_offset,
                                        uint32_t tree_height,
                                        gcry_err_code_t (*gen_leafx4)(unsigned char * /* Where to write the leaves */,
                                                                      const _gcry_slhdsa_param_t *,
                                                                      uint32_t idx,
                                                                      void *info),
                                        uint32_t tree_addrx4[4 * 8],
                                        void *info);
#endif

#endif
