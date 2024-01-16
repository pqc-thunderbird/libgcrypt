#ifndef POLY_H
#define POLY_H

#include <stdint.h>
#include "mlkem-align-avx2.h"
#include "mlkem-params-avx2.h"
#include "mlkem-params.h"

typedef ALIGNED_INT16(GCRY_MLKEM_N) poly;

void poly_compress_128(uint8_t r[128], const poly *a);
void poly_decompress_128(poly *r, const uint8_t a[128]);
void poly_compress_160(uint8_t r[160], const poly *a);
void poly_decompress_160(poly *r, const uint8_t a[160]);

void poly_tobytes(uint8_t r[GCRY_MLKEM_POLYBYTES], const poly *a);
void poly_frombytes(poly *r, const uint8_t a[GCRY_MLKEM_POLYBYTES]);

void poly_frommsg(poly *r, const uint8_t *msg);
void poly_tomsg(uint8_t *msg, const poly *r);

void poly_getnoise_eta1(poly *r, const uint8_t seed[GCRY_MLKEM_SYMBYTES], uint8_t nonce, gcry_mlkem_param_t const *param);

void poly_getnoise_eta2(poly *r, const uint8_t seed[GCRY_MLKEM_SYMBYTES], uint8_t nonce);

void poly_getnoise_eta1_4x(poly *r0,
                           poly *r1,
                           poly *r2,
                           poly *r3,
                           const uint8_t seed[32],
                           uint8_t nonce0,
                           uint8_t nonce1,
                           uint8_t nonce2,
                           uint8_t nonce3,
                           gcry_mlkem_param_t const *param);

// #if KYBER_K == 2
void poly_getnoise_eta1122_4x(poly *r0,
                              poly *r1,
                              poly *r2,
                              poly *r3,
                              const uint8_t seed[32],
                              uint8_t nonce0,
                              uint8_t nonce1,
                              uint8_t nonce2,
                              uint8_t nonce3,
                              gcry_mlkem_param_t const *param);
// #endif


void poly_ntt(poly *r);
void poly_invntt_tomont(poly *r);
void poly_nttunpack(poly *r);
void poly_basemul_montgomery(poly *r, const poly *a, const poly *b);
void poly_tomont(poly *r);

void poly_reduce(poly *r);

void poly_add(poly *r, const poly *a, const poly *b);
void poly_sub(poly *r, const poly *a, const poly *b);

#endif
