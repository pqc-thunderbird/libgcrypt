#ifndef SPX_UTILS_H
#define SPX_UTILS_H

#include "config.h"

#include <stdint.h>
#include "sphincs-params.h"
#include "sphincs-context.h"

#include "g10lib.h"

/* To support MSVC use alloca() instead of VLAs. See #20. */
#ifdef _MSC_VER
/* MSVC defines _alloca in malloc.h */
# include <malloc.h>
/* Note: _malloca(), which is recommended over deprecated _alloca,
   requires that you call _freea(). So we stick with _alloca */
# define SPX_VLA(__t,__x,__s) __t *__x = (__t*)_alloca((__s)*sizeof(__t))
#else
# define SPX_VLA(__t,__x,__s) __t __x[__s]
#endif

/**
 * Converts the value of 'in' to 'outlen' bytes in big-endian byte order.
 */
void _gcry_sphincsplus_ull_to_bytes(unsigned char *out, unsigned int outlen,
                  unsigned long long in);
void _gcry_sphincsplus_u32_to_bytes(unsigned char *out, uint32_t in);

/**
 * Converts the inlen bytes in 'in' from big-endian byte order to an integer.
 */
unsigned long long _gcry_sphincsplus_bytes_to_ull(const unsigned char *in, unsigned int inlen);

/**
 * Computes a root node given a leaf and an auth path.
 * Expects address to be complete other than the tree_height and tree_index.
 */
gcry_err_code_t _gcry_sphincsplus_compute_root(unsigned char *root, const unsigned char *leaf,
                  uint32_t leaf_idx, uint32_t idx_offset,
                  const unsigned char *auth_path, uint32_t tree_height,
                  const _gcry_sphincsplus_param_t *ctx, uint32_t addr[8]);

/**
 * For a given leaf index, computes the authentication path and the resulting
 * root node using Merkle's _gcry_sphincsplus_treehash algorithm.
 * Expects the layer and tree parts of the tree_addr to be set, as well as the
 * tree type (i.e. SPX_ADDR_TYPE_HASHTREE or SPX_ADDR_TYPE_FORSTREE).
 * Applies the offset idx_offset to indices before building addresses, so that
 * it is possible to continue counting indices across trees.
 */
void _gcry_sphincsplus_treehash(unsigned char *root, unsigned char *auth_path,
              const _gcry_sphincsplus_param_t* ctx,
              uint32_t leaf_idx, uint32_t idx_offset, uint32_t tree_height,
              void (*gen_leaf)(
                 unsigned char* /* leaf */,
                 const _gcry_sphincsplus_param_t* ctx /* ctx */,
                 uint32_t /* addr_idx */, const uint32_t[8] /* tree_addr */),
              uint32_t tree_addr[8]);


#endif
