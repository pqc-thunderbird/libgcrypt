#ifndef POLY_H
#define POLY_H

#include <stdint.h>
#include "mldsa-align-avx2.h"
#include "mldsa-params-avx2.h"
#include "mldsa-symmetric-avx2.h"

#include "mldsa-poly.h"

typedef ALIGNED_INT32(N) poly;

void poly_reduce(gcry_mldsa_poly *a);
#define poly_caddq DILITHIUM_NAMESPACE(poly_caddq)
void poly_caddq(gcry_mldsa_poly *a);

#define poly_add DILITHIUM_NAMESPACE(poly_add)
void poly_add(gcry_mldsa_poly *c, const gcry_mldsa_poly *a, const gcry_mldsa_poly *b);
#define poly_sub DILITHIUM_NAMESPACE(poly_sub)
void poly_sub(gcry_mldsa_poly *c, const gcry_mldsa_poly *a, const gcry_mldsa_poly *b);
#define poly_shiftl DILITHIUM_NAMESPACE(poly_shiftl)
void poly_shiftl(gcry_mldsa_poly *a);

void poly_ntt(gcry_mldsa_poly *a);
void poly_invntt_tomont(gcry_mldsa_poly *a);
void poly_nttunpack(gcry_mldsa_poly *a);
#define poly_pointwise_montgomery DILITHIUM_NAMESPACE(poly_pointwise_montgomery)
void poly_pointwise_montgomery(gcry_mldsa_poly *c, const gcry_mldsa_poly *a, const gcry_mldsa_poly *b);

#define poly_power2round DILITHIUM_NAMESPACE(poly_power2round)
void poly_power2round(gcry_mldsa_poly *a1, gcry_mldsa_poly *a0, const gcry_mldsa_poly *a);
#define poly_decompose DILITHIUM_NAMESPACE(poly_decompose)
void poly_decompose(gcry_mldsa_poly *a1, gcry_mldsa_poly *a0, const gcry_mldsa_poly *a);
#define poly_make_hint DILITHIUM_NAMESPACE(poly_make_hint)
unsigned int poly_make_hint(uint8_t hint[N], const gcry_mldsa_poly *a0, const gcry_mldsa_poly *a1);
#define poly_use_hint DILITHIUM_NAMESPACE(poly_use_hint)
void poly_use_hint(gcry_mldsa_poly *b, const gcry_mldsa_poly *a, const gcry_mldsa_poly *h);

#define poly_chknorm DILITHIUM_NAMESPACE(poly_chknorm)
int poly_chknorm(const gcry_mldsa_poly *a, int32_t B);
#define poly_uniform_preinit DILITHIUM_NAMESPACE(poly_uniform_preinit)
void poly_uniform_preinit(gcry_mldsa_poly *a, stream128_state *state);
#define poly_uniform DILITHIUM_NAMESPACE(poly_uniform)
void poly_uniform(gcry_mldsa_poly *a, const uint8_t seed[SEEDBYTES], uint16_t nonce);
#define poly_uniform_eta_preinit DILITHIUM_NAMESPACE(poly_uniform_eta_preinit)
void poly_uniform_eta_preinit(gcry_mldsa_poly *a, stream256_state *state);
#define poly_uniform_eta DILITHIUM_NAMESPACE(poly_uniform_eta)
void poly_uniform_eta(gcry_mldsa_poly *a, const uint8_t seed[CRHBYTES], uint16_t nonce);
#define poly_uniform_gamma1_preinit DILITHIUM_NAMESPACE(poly_uniform_gamma1_preinit)
void poly_uniform_gamma1_preinit(gcry_mldsa_poly *a, stream256_state *state);
#define poly_uniform_gamma1 DILITHIUM_NAMESPACE(poly_uniform_gamma1)
void poly_uniform_gamma1(gcry_mldsa_poly *a, const uint8_t seed[CRHBYTES], uint16_t nonce);
#define poly_challenge DILITHIUM_NAMESPACE(poly_challenge)
void poly_challenge(gcry_mldsa_poly *c, const uint8_t seed[SEEDBYTES]);

#define poly_uniform_4x DILITHIUM_NAMESPACE(poly_uniform_4x)
void poly_uniform_4x(gcry_mldsa_poly *a0,
                     gcry_mldsa_poly *a1,
                     gcry_mldsa_poly *a2,
                     gcry_mldsa_poly *a3,
                     const uint8_t seed[SEEDBYTES],
                     uint16_t nonce0,
                     uint16_t nonce1,
                     uint16_t nonce2,
                     uint16_t nonce3);
#define poly_uniform_eta_4x DILITHIUM_NAMESPACE(poly_uniform_eta_4x)
void poly_uniform_eta_4x(gcry_mldsa_poly *a0,
                         gcry_mldsa_poly *a1,
                         gcry_mldsa_poly *a2,
                         gcry_mldsa_poly *a3,
                         const uint8_t seed[CRHBYTES],
                         uint16_t nonce0,
                         uint16_t nonce1,
                         uint16_t nonce2,
                         uint16_t nonce3);
#define poly_uniform_gamma1_4x DILITHIUM_NAMESPACE(poly_uniform_gamma1_4x)
void poly_uniform_gamma1_4x(gcry_mldsa_poly *a0,
                            gcry_mldsa_poly *a1,
                            gcry_mldsa_poly *a2,
                            gcry_mldsa_poly *a3,
                            const uint8_t seed[CRHBYTES],
                            uint16_t nonce0,
                            uint16_t nonce1,
                            uint16_t nonce2,
                            uint16_t nonce3);

#define polyeta_pack DILITHIUM_NAMESPACE(polyeta_pack)
void polyeta_pack(uint8_t r[POLYETA_PACKEDBYTES], const gcry_mldsa_poly *a);
#define polyeta_unpack DILITHIUM_NAMESPACE(polyeta_unpack)
void polyeta_unpack(gcry_mldsa_poly *r, const uint8_t a[POLYETA_PACKEDBYTES]);

#define polyt1_pack DILITHIUM_NAMESPACE(polyt1_pack)
void polyt1_pack(uint8_t r[POLYT1_PACKEDBYTES], const gcry_mldsa_poly *a);
#define polyt1_unpack DILITHIUM_NAMESPACE(polyt1_unpack)
void polyt1_unpack(gcry_mldsa_poly *r, const uint8_t a[POLYT1_PACKEDBYTES]);

#define polyt0_pack DILITHIUM_NAMESPACE(polyt0_pack)
void polyt0_pack(uint8_t r[POLYT0_PACKEDBYTES], const gcry_mldsa_poly *a);
#define polyt0_unpack DILITHIUM_NAMESPACE(polyt0_unpack)
void polyt0_unpack(gcry_mldsa_poly *r, const uint8_t a[POLYT0_PACKEDBYTES]);

#define polyz_pack DILITHIUM_NAMESPACE(polyz_pack)
void polyz_pack(uint8_t r[POLYZ_PACKEDBYTES], const gcry_mldsa_poly *a);
#define polyz_unpack DILITHIUM_NAMESPACE(polyz_unpack)
void polyz_unpack(gcry_mldsa_poly *r, const uint8_t *a);

#define polyw1_pack DILITHIUM_NAMESPACE(polyw1_pack)
void polyw1_pack(uint8_t *r, const gcry_mldsa_poly *a);

#endif
