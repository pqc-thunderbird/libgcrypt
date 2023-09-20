#ifndef SPX_CONTEXT_H
#define SPX_CONTEXT_H

#include <stdint.h>

#include "sphincs-params.h"

typedef struct {
    uint8_t *pub_seed;
    uint8_t *sk_seed;

    // sha256 state that absorbed pub_seed
    uint8_t *state_seeded;

    // sha512 state that absorbed pub_seed
    uint8_t *state_seeded_512;

    uint8_t n; /* Hash output length in bytes */
    uint8_t seed_bytes; /* seed length */

    /* Hypertree */
    uint8_t tree_height;
    uint8_t full_height;
    uint8_t d;

    /* FORS */
    uint8_t FORS_height;
    uint8_t FORS_trees;
    uint16_t FORS_msg_bytes;
    uint16_t FORS_bytes;
    uint16_t FORS_pk_bytes;

    /* Winternitz parameters */
    uint8_t WOTS_w;
    uint8_t WOTS_logw;
    uint8_t WOTS_len1;
    uint8_t WOTS_len2;
    uint8_t WOTS_len;
    uint16_t WOTS_bytes;
    uint16_t WOTS_pk_bytes;

    /* misc */
    uint8_t do_use_sha512; /* Boolean: If zero, use SHA-256 for all hashes */
    uint8_t addr_bytes; /* Number of address bytes */

    /* sig and key size */
    uint16_t signature_bytes;
    uint8_t public_key_bytes;
    uint8_t secret_key_bytes;

    /* hash offsets */
    uint8_t offset_layer;      /* The byte used to specify the Merkle tree layer */
    uint8_t offset_tree;       /* The start of the 8 byte field used to specify the tree */
    uint8_t offset_type;       /* The byte used to specify the hash type (reason) */
    uint8_t offset_kp_addr2;   /* The high byte used to specify the key pair (which one-time signature) */
    uint8_t offset_kp_addr1;   /* The low byte used to specify the key pair */
    uint8_t offset_chain_addr; /* The byte used to specify the chain address (which Winternitz chain) */
    uint8_t offset_hash_addr;  /* The byte used to specify the hash address (where in the Winternitz chain) */
    uint8_t offset_tree_hgt;   /* The byte used to specify the height of this node in the FORS or Merkle tree */
    uint8_t offset_tree_index; /* The start of the 4 byte field used to specify the node in the FORS or Merkle tree */

    uint8_t is_sha2;  /* Boolean: is a SHA2 parameter set (SHAKE otherwise) */
} _gcry_sphincsplus_param_t;

#endif
