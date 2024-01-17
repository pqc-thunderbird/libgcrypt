#ifndef POLY_H
#define POLY_H

#include <stdint.h>
#include "mlkem-align-avx2.h"
#include "mlkem-params-avx2.h"
#include "mlkem-params.h"
#include "mlkem-poly.h"

void poly_compress_128(uint8_t r[128], const gcry_mlkem_poly *a);
void poly_decompress_128(gcry_mlkem_poly *r, const uint8_t a[128]);
void poly_compress_160(uint8_t r[160], const gcry_mlkem_poly *a);
void poly_decompress_160(gcry_mlkem_poly *r, const uint8_t a[160]);

void poly_tobytes(uint8_t r[GCRY_MLKEM_POLYBYTES], const gcry_mlkem_poly *a);
void poly_frombytes(gcry_mlkem_poly *r, const uint8_t a[GCRY_MLKEM_POLYBYTES]);

void poly_frommsg(gcry_mlkem_poly *r, const uint8_t *msg);
void poly_tomsg(uint8_t *msg, const gcry_mlkem_poly *r);

void poly_getnoise_eta1(gcry_mlkem_poly *r, const uint8_t seed[GCRY_MLKEM_SYMBYTES], uint8_t nonce, gcry_mlkem_param_t const *param);

void poly_getnoise_eta2(gcry_mlkem_poly *r, const uint8_t seed[GCRY_MLKEM_SYMBYTES], uint8_t nonce);

void poly_getnoise_eta1_4x(gcry_mlkem_poly *r0,
                           gcry_mlkem_poly *r1,
                           gcry_mlkem_poly *r2,
                           gcry_mlkem_poly *r3,
                           const uint8_t seed[32],
                           uint8_t nonce0,
                           uint8_t nonce1,
                           uint8_t nonce2,
                           uint8_t nonce3,
                           gcry_mlkem_param_t const *param);

// #if KYBER_K == 2
void poly_getnoise_eta1122_4x(gcry_mlkem_poly *r0,
                              gcry_mlkem_poly *r1,
                              gcry_mlkem_poly *r2,
                              gcry_mlkem_poly *r3,
                              const uint8_t seed[32],
                              uint8_t nonce0,
                              uint8_t nonce1,
                              uint8_t nonce2,
                              uint8_t nonce3,
                              gcry_mlkem_param_t const *param);
// #endif


void poly_ntt(gcry_mlkem_poly *r);
void poly_invntt_tomont(gcry_mlkem_poly *r);
void poly_nttunpack(gcry_mlkem_poly *r);
void poly_basemul_montgomery(gcry_mlkem_poly *r, const gcry_mlkem_poly *a, const gcry_mlkem_poly *b);
void poly_tomont(gcry_mlkem_poly *r);

void poly_reduce(gcry_mlkem_poly *r);

void poly_add(gcry_mlkem_poly *r, const gcry_mlkem_poly *a, const gcry_mlkem_poly *b);
void poly_sub(gcry_mlkem_poly *r, const gcry_mlkem_poly *a, const gcry_mlkem_poly *b);

#endif
