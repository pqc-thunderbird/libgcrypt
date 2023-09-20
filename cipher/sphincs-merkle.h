#if !defined( MERKLE_H_ )
#define MERKLE_H_

#include <stdint.h>

/* Generate a Merkle signature (WOTS signature followed by the Merkle */
/* authentication path) */
void _gcry_sphincsplus_merkle_sign(uint8_t *sig, unsigned char *root,
        const _gcry_sphincsplus_param_t* ctx,
        uint32_t wots_addr[8], uint32_t tree_addr[8],
        uint32_t idx_leaf);

/* Compute the root node of the top-most subtree. */
void _gcry_sphincsplus_merkle_gen_root(unsigned char *root, const _gcry_sphincsplus_param_t* ctx);

#endif /* MERKLE_H_ */
