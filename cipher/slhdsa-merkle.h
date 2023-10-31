#if !defined( MERKLE_H_ )
#define MERKLE_H_

#include "config.h"

#include <stdint.h>

#include "g10lib.h"


/* Generate a Merkle signature (WOTS signature followed by the Merkle */
/* authentication path) */
gcry_err_code_t _gcry_slhdsa_merkle_sign(uint8_t *sig, unsigned char *root,
        const _gcry_slhdsa_param_t* ctx,
        uint32_t wots_addr[8], uint32_t tree_addr[8],
        uint32_t idx_leaf);

/* Compute the root node of the top-most subtree. */
gcry_err_code_t _gcry_slhdsa_merkle_gen_root(unsigned char *root, const _gcry_slhdsa_param_t* ctx);

#endif /* MERKLE_H_ */
