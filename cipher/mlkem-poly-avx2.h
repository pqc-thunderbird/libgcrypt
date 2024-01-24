#ifndef POLY_H
#define POLY_H

#include <stdint.h>
#include "mlkem-params.h"
#include "mlkem-poly.h"
#include "g10lib.h"

void _gcry_mlkem_avx2_poly_compress_128 (uint8_t r[128],
                                         const gcry_mlkem_poly *a);
void _gcry_mlkem_avx2_poly_decompress_128 (gcry_mlkem_poly *r,
                                           const uint8_t a[128]);
void _gcry_mlkem_avx2_poly_compress_160 (uint8_t r[160],
                                         const gcry_mlkem_poly *a);
void _gcry_mlkem_avx2_poly_decompress_160 (gcry_mlkem_poly *r,
                                           const uint8_t a[160]);

void _gcry_mlkem_avx2_poly_tobytes (uint8_t r[GCRY_MLKEM_POLYBYTES],
                                    const gcry_mlkem_poly *a);
void _gcry_mlkem_avx2_poly_frombytes (gcry_mlkem_poly *r,
                                      const uint8_t a[GCRY_MLKEM_POLYBYTES]);

void _gcry_mlkem_avx2_poly_frommsg (gcry_mlkem_poly *r, const uint8_t *msg);
void _gcry_mlkem_avx2_poly_tomsg (uint8_t *msg, const gcry_mlkem_poly *r);

gcry_err_code_t _gcry_mlkem_avx2_poly_getnoise_eta2 (
    gcry_mlkem_poly *r,
    const uint8_t seed[GCRY_MLKEM_SYMBYTES],
    uint8_t nonce);

gcry_err_code_t _gcry_mlkem_avx2_poly_getnoise_eta1_4x (gcry_mlkem_poly *r0,
                                             gcry_mlkem_poly *r1,
                                             gcry_mlkem_poly *r2,
                                             gcry_mlkem_poly *r3,
                                             const uint8_t seed[32],
                                             uint8_t nonce0,
                                             uint8_t nonce1,
                                             uint8_t nonce2,
                                             uint8_t nonce3,
                                             gcry_mlkem_param_t const *param);

gcry_err_code_t _gcry_mlkem_avx2_poly_getnoise_eta1122_4x (
    gcry_mlkem_poly *r0,
    gcry_mlkem_poly *r1,
    gcry_mlkem_poly *r2,
    gcry_mlkem_poly *r3,
    const uint8_t seed[32],
    uint8_t nonce0,
    uint8_t nonce1,
    uint8_t nonce2,
    uint8_t nonce3,
    gcry_mlkem_param_t const *param);

void _gcry_mlkem_avx2_poly_ntt (gcry_mlkem_poly *r);
void _gcry_mlkem_avx2_poly_invntt_tomont (gcry_mlkem_poly *r);
void _gcry_mlkem_avx2_poly_nttunpack (gcry_mlkem_poly *r);
void _gcry_mlkem_avx2_poly_basemul_montgomery (gcry_mlkem_poly *r,
                                               const gcry_mlkem_poly *a,
                                               const gcry_mlkem_poly *b);
void _gcry_mlkem_avx2_poly_tomont (gcry_mlkem_poly *r);

void _gcry_mlkem_avx2_poly_reduce (gcry_mlkem_poly *r);

void _gcry_mlkem_avx2_poly_add (gcry_mlkem_poly *r,
                                const gcry_mlkem_poly *a,
                                const gcry_mlkem_poly *b);
void _gcry_mlkem_avx2_poly_sub (gcry_mlkem_poly *r,
                                const gcry_mlkem_poly *a,
                                const gcry_mlkem_poly *b);

#endif
