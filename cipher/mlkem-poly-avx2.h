#ifndef POLY_H
#define POLY_H

#include <stdint.h>
#include "mlkem-align-avx2.h"
#include "mlkem-params-avx2.h"

typedef ALIGNED_INT16(KYBER_N) poly;

void poly_compress(uint8_t r[KYBER_POLYCOMPRESSEDBYTES], const poly *a);
void poly_decompress(poly *r, const uint8_t a[KYBER_POLYCOMPRESSEDBYTES]);

void poly_tobytes(uint8_t r[KYBER_POLYBYTES], const poly *a);
void poly_frombytes(poly *r, const uint8_t a[KYBER_POLYBYTES]);

void poly_frommsg(poly *r, const uint8_t msg[KYBER_INDCPA_MSGBYTES]);
void poly_tomsg(uint8_t msg[KYBER_INDCPA_MSGBYTES], const poly *r);

void poly_getnoise_eta1(poly *r, const uint8_t seed[KYBER_SYMBYTES], uint8_t nonce);

void poly_getnoise_eta2(poly *r, const uint8_t seed[KYBER_SYMBYTES], uint8_t nonce);

void poly_getnoise_eta1_4x(poly *r0,
                           poly *r1,
                           poly *r2,
                           poly *r3,
                           const uint8_t seed[32],
                           uint8_t nonce0,
                           uint8_t nonce1,
                           uint8_t nonce2,
                           uint8_t nonce3);

#if KYBER_K == 2
void poly_getnoise_eta1122_4x(poly *r0,
                              poly *r1,
                              poly *r2,
                              poly *r3,
                              const uint8_t seed[32],
                              uint8_t nonce0,
                              uint8_t nonce1,
                              uint8_t nonce2,
                              uint8_t nonce3);
#endif


void poly_ntt(poly *r);
void poly_invntt_tomont(poly *r);
void poly_nttunpack(poly *r);
void poly_basemul_montgomery(poly *r, const poly *a, const poly *b);
void poly_tomont(poly *r);

void poly_reduce(poly *r);

void poly_add(poly *r, const poly *a, const poly *b);
void poly_sub(poly *r, const poly *a, const poly *b);

#endif
