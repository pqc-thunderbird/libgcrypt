#ifndef SLHDSA_WOTS_H
#define SLHDSA_WOTS_H

#include <config.h>

#include "types.h"

#include "slhdsa-context.h"

#include "g10lib.h"

/**
 * Takes a WOTS signature and an n-byte message, computes a WOTS public key.
 *
 * Writes the computed public key to 'pk'.
 */
gcry_err_code_t _gcry_slhdsa_wots_pk_from_sig(unsigned char *pk,
                                              const unsigned char *sig,
                                              const unsigned char *msg,
                                              const _gcry_slhdsa_param_t *ctx,
                                              u32 addr[8]);
#ifdef USE_AVX2
gcry_err_code_t _gcry_slhdsa_wots_pk_from_sig_avx2(unsigned char *pk,
                                                   const unsigned char *sig,
                                                   const unsigned char *msg,
                                                   const _gcry_slhdsa_param_t *ctx,
                                                   u32 addr[8]);
#endif

/*
 * Compute the chain lengths needed for a given message hash
 */
gcry_err_code_t _gcry_slhdsa_chain_lengths(const _gcry_slhdsa_param_t *ctx,
                                           unsigned int *lengths,
                                           const unsigned char *msg);


#ifdef USE_AVX2
struct _gcry_slhdsa_leaf_info_x8_t {
    unsigned char *wots_sig;
    uint32_t wots_sign_leaf; /* The index of the WOTS we're using to sign */
    uint32_t *wots_steps;
    uint32_t leaf_addr[8*8];
    uint32_t pk_addr[8*8];
};
struct _gcry_slhdsa_leaf_info_x4_t {
    unsigned char *wots_sig;
    uint32_t wots_sign_leaf; /* The index of the WOTS we're using to sign */
    uint32_t *wots_steps;
    uint32_t leaf_addr[4*8];
    uint32_t pk_addr[4*8];
};
gcry_err_code_t _gcry_slhdsa_wots_gen_leafx8(unsigned char *dest, const _gcry_slhdsa_param_t *ctx, uint32_t leaf_idx, void *v_info);
gcry_err_code_t _gcry_slhdsa_wots_gen_leafx4(unsigned char *dest, const _gcry_slhdsa_param_t *ctx, uint32_t leaf_idx, void *v_info);
#endif
#endif
