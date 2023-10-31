#ifndef _GCRY_MLDSA_POLY_H
#define _GCRY_MLDSA_POLY_H

#include <stdint.h>
#include "mldsa-params.h"

typedef struct {
  int32_t coeffs[GCRY_MLDSA_N];
} gcry_mldsa_poly;

void _gcry_mldsa_poly_reduce(gcry_mldsa_poly *a);
void _gcry_mldsa_poly_caddq(gcry_mldsa_poly *a);

void _gcry_mldsa_poly_add(gcry_mldsa_poly *c, const gcry_mldsa_poly *a, const gcry_mldsa_poly *b);
void _gcry_mldsa_poly_sub(gcry_mldsa_poly *c, const gcry_mldsa_poly *a, const gcry_mldsa_poly *b);
void _gcry_mldsa_poly_shiftl(gcry_mldsa_poly *a);

void _gcry_mldsa_poly_ntt(gcry_mldsa_poly *a);
void _gcry_mldsa_poly_invntt_tomont(gcry_mldsa_poly *a);
void _gcry_mldsa_poly_pointwise_montgomery(gcry_mldsa_poly *c, const gcry_mldsa_poly *a, const gcry_mldsa_poly *b);

void _gcry_mldsa_poly_power2round(gcry_mldsa_poly *a1, gcry_mldsa_poly *a0, const gcry_mldsa_poly *a);
void _gcry_mldsa_poly_decompose(gcry_mldsa_param_t *params, gcry_mldsa_poly *a1, gcry_mldsa_poly *a0, const gcry_mldsa_poly *a);
unsigned int _gcry_mldsa_poly_make_hint(gcry_mldsa_param_t *params, gcry_mldsa_poly *h, const gcry_mldsa_poly *a0, const gcry_mldsa_poly *a1);
void _gcry_mldsa_poly_use_hint(gcry_mldsa_param_t *params, gcry_mldsa_poly *b, const gcry_mldsa_poly *a, const gcry_mldsa_poly *h);

int _gcry_mldsa_poly_chknorm(const gcry_mldsa_poly *a, int32_t B);
void _gcry_mldsa_poly_uniform(gcry_mldsa_poly *a,
                  const uint8_t seed[GCRY_MLDSA_SEEDBYTES],
                  uint16_t nonce);
void _gcry_mldsa_poly_uniform_eta(gcry_mldsa_param_t *params, gcry_mldsa_poly *a,
                      const uint8_t seed[GCRY_MLDSA_CRHBYTES],
                      uint16_t nonce);
void _gcry_mldsa_poly_uniform_gamma1(gcry_mldsa_param_t *params, gcry_mldsa_poly *a,
                         const uint8_t seed[GCRY_MLDSA_CRHBYTES],
                         uint16_t nonce);
void _gcry_mldsa_poly_challenge(gcry_mldsa_param_t *params, gcry_mldsa_poly *c, const uint8_t seed[GCRY_MLDSA_SEEDBYTES]);

void _gcry_mldsa_polyeta_pack(gcry_mldsa_param_t *params, uint8_t *r, const gcry_mldsa_poly *a);
void _gcry_mldsa_polyeta_unpack(gcry_mldsa_param_t *params, gcry_mldsa_poly *r, const uint8_t *a);

void _gcry_mldsa_polyt1_pack(uint8_t *r, const gcry_mldsa_poly *a);
void _gcry_mldsa_polyt1_unpack(gcry_mldsa_poly *r, const uint8_t *a);

void _gcry_mldsa_polyt0_pack(uint8_t *r, const gcry_mldsa_poly *a);
void _gcry_mldsa_polyt0_unpack(gcry_mldsa_poly *r, const uint8_t *a);

void _gcry_mldsa_polyz_pack(gcry_mldsa_param_t *params, uint8_t *r, const gcry_mldsa_poly *a);
void _gcry_mldsa_polyz_unpack(gcry_mldsa_param_t *params, gcry_mldsa_poly *r, const uint8_t *a);

void _gcry_mldsa_polyw1_pack(gcry_mldsa_param_t *params, uint8_t *r, const gcry_mldsa_poly *a);

#endif
