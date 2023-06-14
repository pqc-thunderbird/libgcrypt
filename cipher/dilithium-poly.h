#ifndef POLY_H
#define POLY_H

#include <stdint.h>
#include "dilithium-params.h"

typedef struct {
  int32_t coeffs[GCRY_DILITHIUM_N];
} poly;

void _gcry_dilithium_poly_reduce(poly *a);
void _gcry_dilithium_poly_caddq(poly *a);

void _gcry_dilithium_poly_add(poly *c, const poly *a, const poly *b);
void _gcry_dilithium_poly_sub(poly *c, const poly *a, const poly *b);
void _gcry_dilithium_poly_shiftl(poly *a);

void _gcry_dilithium_poly_ntt(poly *a);
void _gcry_dilithium_poly_invntt_tomont(poly *a);
void _gcry_dilithium_poly_pointwise_montgomery(poly *c, const poly *a, const poly *b);

void _gcry_dilithium_poly_power2round(poly *a1, poly *a0, const poly *a);
void _gcry_dilithium_poly_decompose(gcry_dilithium_param_t *params, poly *a1, poly *a0, const poly *a);
unsigned int _gcry_dilithium_poly_make_hint(gcry_dilithium_param_t *params, poly *h, const poly *a0, const poly *a1);
void _gcry_dilithium_poly_use_hint(gcry_dilithium_param_t *params, poly *b, const poly *a, const poly *h);

int _gcry_dilithium_poly_chknorm(const poly *a, int32_t B);
void _gcry_dilithium_poly_uniform(poly *a,
                  const uint8_t seed[GCRY_DILITHIUM_SEEDBYTES],
                  uint16_t nonce);
void _gcry_dilithium_poly_uniform_eta(gcry_dilithium_param_t *params, poly *a,
                      const uint8_t seed[GCRY_DILITHIUM_CRHBYTES],
                      uint16_t nonce);
void _gcry_dilithium_poly_uniform_gamma1(gcry_dilithium_param_t *params, poly *a,
                         const uint8_t seed[GCRY_DILITHIUM_CRHBYTES],
                         uint16_t nonce);
void _gcry_dilithium_poly_challenge(gcry_dilithium_param_t *params, poly *c, const uint8_t seed[GCRY_DILITHIUM_SEEDBYTES]);

void _gcry_dilithium_polyeta_pack(gcry_dilithium_param_t *params, uint8_t *r, const poly *a);
void _gcry_dilithium_polyeta_unpack(gcry_dilithium_param_t *params, poly *r, const uint8_t *a);

void _gcry_dilithium_polyt1_pack(uint8_t *r, const poly *a);
void _gcry_dilithium_polyt1_unpack(poly *r, const uint8_t *a);

void _gcry_dilithium_polyt0_pack(uint8_t *r, const poly *a);
void _gcry_dilithium_polyt0_unpack(poly *r, const uint8_t *a);

void _gcry_dilithium_polyz_pack(gcry_dilithium_param_t *params, uint8_t *r, const poly *a);
void _gcry_dilithium_polyz_unpack(gcry_dilithium_param_t *params, poly *r, const uint8_t *a);

void _gcry_dilithium_polyw1_pack(gcry_dilithium_param_t *params, uint8_t *r, const poly *a);

#endif
