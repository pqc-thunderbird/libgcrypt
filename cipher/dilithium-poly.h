#ifndef _GCRY_DILITHIUM_POLY_H
#define _GCRY_DILITHIUM_POLY_H

#include <stdint.h>
#include "dilithium-params.h"

typedef struct {
  int32_t coeffs[GCRY_DILITHIUM_N];
} gcry_dilithium_poly;

void _gcry_dilithium_poly_reduce(gcry_dilithium_poly *a);
void _gcry_dilithium_poly_caddq(gcry_dilithium_poly *a);

void _gcry_dilithium_poly_add(gcry_dilithium_poly *c, const gcry_dilithium_poly *a, const gcry_dilithium_poly *b);
void _gcry_dilithium_poly_sub(gcry_dilithium_poly *c, const gcry_dilithium_poly *a, const gcry_dilithium_poly *b);
void _gcry_dilithium_poly_shiftl(gcry_dilithium_poly *a);

void _gcry_dilithium_poly_ntt(gcry_dilithium_poly *a);
void _gcry_dilithium_poly_invntt_tomont(gcry_dilithium_poly *a);
void _gcry_dilithium_poly_pointwise_montgomery(gcry_dilithium_poly *c, const gcry_dilithium_poly *a, const gcry_dilithium_poly *b);

void _gcry_dilithium_poly_power2round(gcry_dilithium_poly *a1, gcry_dilithium_poly *a0, const gcry_dilithium_poly *a);
void _gcry_dilithium_poly_decompose(gcry_dilithium_param_t *params, gcry_dilithium_poly *a1, gcry_dilithium_poly *a0, const gcry_dilithium_poly *a);
unsigned int _gcry_dilithium_poly_make_hint(gcry_dilithium_param_t *params, gcry_dilithium_poly *h, const gcry_dilithium_poly *a0, const gcry_dilithium_poly *a1);
void _gcry_dilithium_poly_use_hint(gcry_dilithium_param_t *params, gcry_dilithium_poly *b, const gcry_dilithium_poly *a, const gcry_dilithium_poly *h);

int _gcry_dilithium_poly_chknorm(const gcry_dilithium_poly *a, int32_t B);
void _gcry_dilithium_poly_uniform(gcry_dilithium_poly *a,
                  const uint8_t seed[GCRY_DILITHIUM_SEEDBYTES],
                  uint16_t nonce);
void _gcry_dilithium_poly_uniform_eta(gcry_dilithium_param_t *params, gcry_dilithium_poly *a,
                      const uint8_t seed[GCRY_DILITHIUM_CRHBYTES],
                      uint16_t nonce);
void _gcry_dilithium_poly_uniform_gamma1(gcry_dilithium_param_t *params, gcry_dilithium_poly *a,
                         const uint8_t seed[GCRY_DILITHIUM_CRHBYTES],
                         uint16_t nonce);
void _gcry_dilithium_poly_challenge(gcry_dilithium_param_t *params, gcry_dilithium_poly *c, const uint8_t seed[GCRY_DILITHIUM_SEEDBYTES]);

void _gcry_dilithium_polyeta_pack(gcry_dilithium_param_t *params, uint8_t *r, const gcry_dilithium_poly *a);
void _gcry_dilithium_polyeta_unpack(gcry_dilithium_param_t *params, gcry_dilithium_poly *r, const uint8_t *a);

void _gcry_dilithium_polyt1_pack(uint8_t *r, const gcry_dilithium_poly *a);
void _gcry_dilithium_polyt1_unpack(gcry_dilithium_poly *r, const uint8_t *a);

void _gcry_dilithium_polyt0_pack(uint8_t *r, const gcry_dilithium_poly *a);
void _gcry_dilithium_polyt0_unpack(gcry_dilithium_poly *r, const uint8_t *a);

void _gcry_dilithium_polyz_pack(gcry_dilithium_param_t *params, uint8_t *r, const gcry_dilithium_poly *a);
void _gcry_dilithium_polyz_unpack(gcry_dilithium_param_t *params, gcry_dilithium_poly *r, const uint8_t *a);

void _gcry_dilithium_polyw1_pack(gcry_dilithium_param_t *params, uint8_t *r, const gcry_dilithium_poly *a);

#endif
