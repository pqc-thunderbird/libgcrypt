#include <config.h>

#include <stdint.h>
#include <string.h>

#include "sphincs-utils.h"
#include "sphincs-hash.h"
#include "sphincs-thash.h"
#include "sphincs-wots.h"
#include "sphincs-wotsx1.h"
#include "sphincs-address.h"
#include "sphincs-params.h"

#include "g10lib.h"

/*
 * This generates a WOTS public key
 * It also generates the WOTS signature if leaf_info indicates
 * that we're signing with this WOTS key
 */
gcry_err_code_t _gcry_sphincsplus_wots_gen_leafx1(unsigned char *dest,
                   const _gcry_sphincsplus_param_t *ctx,
                   uint32_t leaf_idx, void *v_info) {
    gcry_err_code_t ec = 0;

    struct _gcry_sphincsplus_leaf_info_x1_t *info = v_info;
    uint32_t *leaf_addr = info->leaf_addr;
    uint32_t *pk_addr = info->pk_addr;
    unsigned int i, k;
    unsigned char *pk_buffer = NULL;
    unsigned char *buffer;
    uint32_t wots_k_mask;

    pk_buffer = xtrymalloc_secure(ctx->WOTS_bytes);
    if (!pk_buffer)
    {
      ec = gpg_err_code_from_syserror();
      goto leave;
    }

    if (leaf_idx == info->wots_sign_leaf) {
        /* We're traversing the leaf that's signing; generate the WOTS */
        /* signature */
        wots_k_mask = 0;
    } else {
        /* Nope, we're just generating pk's; turn off the signature logic */
        wots_k_mask = (uint32_t)~0;
    }

    _gcry_sphincsplus_set_keypair_addr(ctx, leaf_addr, leaf_idx );
    _gcry_sphincsplus_set_keypair_addr(ctx, pk_addr, leaf_idx );

    for (i = 0, buffer = pk_buffer; i < ctx->WOTS_len; i++, buffer += ctx->n) {
        uint32_t wots_k = info->wots_steps[i] | wots_k_mask; /* Set wots_k to */
            /* the step if we're generating a signature, ~0 if we're not */

        /* Start with the secret seed */
        _gcry_sphincsplus_set_chain_addr(ctx, leaf_addr, i);
        _gcry_sphincsplus_set_hash_addr(ctx, leaf_addr, 0);
        _gcry_sphincsplus_set_type(ctx, leaf_addr, SPX_ADDR_TYPE_WOTSPRF);

        _gcry_sphincsplus_prf_addr(buffer, ctx, leaf_addr);

        _gcry_sphincsplus_set_type(ctx, leaf_addr, SPX_ADDR_TYPE_WOTS);

        /* Iterate down the WOTS chain */
        for (k=0;; k++) {
            /* Check if this is the value that needs to be saved as a */
            /* part of the WOTS signature */
            if (k == wots_k) {
                memcpy( info->wots_sig + i * ctx->n, buffer, ctx->n );
            }

            /* Check if we hit the top of the chain */
            if (k == ctx->WOTS_w - 1) break;

            /* Iterate one step on the chain */
            _gcry_sphincsplus_set_hash_addr(ctx, leaf_addr, k);

            _gcry_sphincsplus_thash(buffer, buffer, 1, ctx, leaf_addr);
        }
    }

    /* Do the final _gcry_sphincsplus_thash to generate the public keys */
    _gcry_sphincsplus_thash(dest, pk_buffer, ctx->WOTS_len, ctx, pk_addr);

leave:
    xfree(pk_buffer);
	return ec;
}
