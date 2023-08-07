#ifndef GCRYPT_KYBER_POLY_H
#define GCRYPT_KYBER_POLY_H

#include <stdint.h>
#include "kyber_params.h"

/*
 * Elements of R_q = Z_q[X]/(X^n + 1). Represents polynomial
 * coeffs[0] + X*coeffs[1] + X^2*coeffs[2] + ... + X^{n-1}*coeffs[n-1]
 */
typedef struct{
  int16_t coeffs[GCRY_KYBER_N];
} gcry_kyber_poly;


void _gcry_kyber_poly_compress(unsigned char* r, const gcry_kyber_poly *a, gcry_kyber_param_t const* param);

void _gcry_kyber_poly_decompress(gcry_kyber_poly *r, const unsigned char* a, gcry_kyber_param_t const* param);


void _gcry_kyber_poly_tobytes(unsigned char r[GCRY_KYBER_POLYBYTES], const gcry_kyber_poly *a);

void _gcry_kyber_poly_frombytes(gcry_kyber_poly *r, const unsigned char a[GCRY_KYBER_POLYBYTES]);


void _gcry_kyber_poly_frommsg(gcry_kyber_poly *r, const unsigned char msg[GCRY_KYBER_INDCPA_MSGBYTES]);

void _gcry_kyber_poly_tomsg(unsigned char msg[GCRY_KYBER_INDCPA_MSGBYTES], const gcry_kyber_poly *r);


void _gcry_kyber_poly_getnoise_eta1(gcry_kyber_poly *r, const unsigned char seed[GCRY_KYBER_SYMBYTES], unsigned char nonce, gcry_kyber_param_t const* param);


void _gcry_kyber_poly_getnoise_eta2(gcry_kyber_poly *r, const unsigned char seed[GCRY_KYBER_SYMBYTES], unsigned char nonce);


void _gcry_kyber_poly_ntt(gcry_kyber_poly *r);

void _gcry_kyber_poly_invntt_tomont(gcry_kyber_poly *r);

void _gcry_kyber_poly_basemul_montgomery(gcry_kyber_poly *r, const gcry_kyber_poly *a, const gcry_kyber_poly *b);

void _gcry_kyber_poly_tomont(gcry_kyber_poly *r);


void _gcry_kyber_poly_reduce(gcry_kyber_poly *r);


void _gcry_kyber_poly_add(gcry_kyber_poly *r, const gcry_kyber_poly *a, const gcry_kyber_poly *b);

void _gcry_kyber_poly_sub(gcry_kyber_poly *r, const gcry_kyber_poly *a, const gcry_kyber_poly *b);

#endif /* GCRYPT_KYBER_POLY_H */
