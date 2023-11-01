/* Based on the public domain implementation in
 * crypto_hash/sha512/ref/ from http://bench.cr.yp.to/supercop.html
 * by D. J. Bernstein */

// #include <stddef.h>
// #include "types.h"
// #include <string.h>

// #include "slhdsa-utils.h"
// #include "slhdsa-sha2.h"

/* TODO: implement seed_state? */

// /**
//  * Absorb the constant pub_seed using one round of the compression function
//  * This initializes state_seeded and state_seeded_512, which can then be
//  * reused in _gcry_slhdsa_thash
//  **/
// void seed_state(_gcry_slhdsa_param_t *ctx) {
//     byte block[SLHDSA_SHA512_BLOCK_BYTES];
//     size_t i;

//     for (i = 0; i < ctx->n; ++i) {
//         block[i] = ctx->pub_seed[i];
//     }
//     for (i = ctx->n; i < SLHDSA_SHA512_BLOCK_BYTES; ++i) {
//         block[i] = 0;
//     }
//     /* block has been properly initialized for both SHA-256 and SHA-512 */

//     sha256_inc_init(ctx->state_seeded);
//     sha256_inc_blocks(ctx->state_seeded, block, 1);
//     if(ctx->do_use_sha512)
//     {
//         sha512_inc_init(ctx->state_seeded_512);
//         sha512_inc_blocks(ctx->state_seeded_512, block, 1);
//     }
// }
