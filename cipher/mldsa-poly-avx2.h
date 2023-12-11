#ifndef POLY_H
#define POLY_H

#include <stdint.h>
#include "mldsa-align-avx2.h"
#include "mldsa-params-avx2.h"
#include "mldsa-symmetric-avx2.h"

#include "mldsa-poly.h"

typedef ALIGNED_INT32(GCRY_MLDSA_N) poly;

void poly_reduce(gcry_mldsa_poly *a);
void poly_caddq(gcry_mldsa_poly *a);

void poly_add(gcry_mldsa_poly *c, const gcry_mldsa_poly *a, const gcry_mldsa_poly *b);
void poly_sub(gcry_mldsa_poly *c, const gcry_mldsa_poly *a, const gcry_mldsa_poly *b);
void poly_shiftl(gcry_mldsa_poly *a);

void poly_ntt(gcry_mldsa_poly *a);
void poly_invntt_tomont(gcry_mldsa_poly *a);
void poly_nttunpack(gcry_mldsa_poly *a);
void poly_pointwise_montgomery(gcry_mldsa_poly *c, const gcry_mldsa_poly *a, const gcry_mldsa_poly *b);

void poly_power2round(gcry_mldsa_poly *a1, gcry_mldsa_poly *a0, const gcry_mldsa_poly *a);
void poly_decompose(gcry_mldsa_param_t *params, gcry_mldsa_poly *a1, gcry_mldsa_poly *a0, const gcry_mldsa_poly *a);
unsigned int poly_make_hint(gcry_mldsa_param_t *params, byte hint[GCRY_MLDSA_N], const gcry_mldsa_poly *a0, const gcry_mldsa_poly *a1);
void poly_use_hint(gcry_mldsa_param_t *params, gcry_mldsa_poly *b, const gcry_mldsa_poly *a, const gcry_mldsa_poly *h);

int poly_chknorm(const gcry_mldsa_poly *a, int32_t B);
void poly_uniform_gamma1_preinit(gcry_mldsa_param_t *params, gcry_mldsa_poly *a, stream256_state *state);
void poly_uniform_gamma1(gcry_mldsa_param_t *params, gcry_mldsa_poly *a, const byte seed[GCRY_MLDSA_CRHBYTES], uint16_t nonce);
void poly_challenge(gcry_mldsa_param_t *params, gcry_mldsa_poly *c, const byte seed[GCRY_MLDSA_SEEDBYTES]);

void poly_uniform_4x(gcry_mldsa_poly *a0,
                     gcry_mldsa_poly *a1,
                     gcry_mldsa_poly *a2,
                     gcry_mldsa_poly *a3,
                     const byte seed[GCRY_MLDSA_SEEDBYTES],
                     uint16_t nonce0,
                     uint16_t nonce1,
                     uint16_t nonce2,
                     uint16_t nonce3);
void poly_uniform_eta_4x(gcry_mldsa_param_t *params, gcry_mldsa_poly *a0,
                         gcry_mldsa_poly *a1,
                         gcry_mldsa_poly *a2,
                         gcry_mldsa_poly *a3,
                         const byte seed[GCRY_MLDSA_CRHBYTES],
                         uint16_t nonce0,
                         uint16_t nonce1,
                         uint16_t nonce2,
                         uint16_t nonce3);
void poly_uniform_gamma1_4x(gcry_mldsa_param_t *params, gcry_mldsa_poly *a0,
                            gcry_mldsa_poly *a1,
                            gcry_mldsa_poly *a2,
                            gcry_mldsa_poly *a3,
                            const byte seed[GCRY_MLDSA_CRHBYTES],
                            uint16_t nonce0,
                            uint16_t nonce1,
                            uint16_t nonce2,
                            uint16_t nonce3);

void polyeta_pack(byte *r, const gcry_mldsa_poly *a);
void polyeta_unpack(gcry_mldsa_poly *r, const byte *a);

void polyt1_pack(byte r[GCRY_MLDSA_POLYT1_PACKEDBYTES], const gcry_mldsa_poly *a);
void polyt1_unpack(gcry_mldsa_poly *r, const byte a[GCRY_MLDSA_POLYT1_PACKEDBYTES]);

void polyt0_pack(byte r[GCRY_MLDSA_POLYT0_PACKEDBYTES], const gcry_mldsa_poly *a);
void polyt0_unpack(gcry_mldsa_poly *r, const byte a[GCRY_MLDSA_POLYT0_PACKEDBYTES]);

void polyz_pack(gcry_mldsa_param_t *params, byte *r, const gcry_mldsa_poly *a);
void polyz_unpack(gcry_mldsa_param_t *params, gcry_mldsa_poly *r, const byte *a);

void polyw1_pack(gcry_mldsa_param_t *params, byte *r, const gcry_mldsa_poly *a);

#endif
