#ifndef POLY_H
#define POLY_H

#include <stdint.h>
#include "kyber_params.h"

/*
 * Elements of R_q = Z_q[X]/(X^n + 1). Represents polynomial
 * coeffs[0] + X*coeffs[1] + X^2*coeffs[2] + ... + X^{n-1}*coeffs[n-1]
 */
typedef struct{
  int16_t coeffs[KYBER_N];
} poly;

//#define poly_compress KYBER_NAMESPACE(poly_compress)
void poly_compress(unsigned char* r, const poly *a, gcry_kyber_param_t const* param);
//#define poly_decompress KYBER_NAMESPACE(poly_decompress)
void poly_decompress(poly *r, const unsigned char* a, gcry_kyber_param_t const* param);

//#define poly_tobytes KYBER_NAMESPACE(poly_tobytes)
void poly_tobytes(unsigned char r[GCRY_KYBER_POLYBYTES], const poly *a);

void poly_frombytes(poly *r, const unsigned char a[GCRY_KYBER_POLYBYTES]);

//#define poly_frommsg KYBER_NAMESPACE(poly_frommsg)
void poly_frommsg(poly *r, const unsigned char msg[GCRY_KYBER_INDCPA_MSGBYTES]);
//#define poly_tomsg KYBER_NAMESPACE(poly_tomsg)
void poly_tomsg(unsigned char msg[GCRY_KYBER_INDCPA_MSGBYTES], const poly *r);

//#define poly_getnoise_eta1 KYBER_NAMESPACE(poly_getnoise_eta1)
void poly_getnoise_eta1(poly *r, const unsigned char seed[GCRY_KYBER_SYMBYTES], unsigned char nonce, gcry_kyber_param_t const* param);

//#define poly_getnoise_eta2 KYBER_NAMESPACE(poly_getnoise_eta2)
void poly_getnoise_eta2(poly *r, const unsigned char seed[GCRY_KYBER_SYMBYTES], unsigned char nonce);

//#define poly_ntt KYBER_NAMESPACE(poly_ntt)
void poly_ntt(poly *r);
//#define poly_invntt_tomont KYBER_NAMESPACE(poly_invntt_tomont)
void poly_invntt_tomont(poly *r);
//#define poly_basemul_montgomery KYBER_NAMESPACE(poly_basemul_montgomery)
void poly_basemul_montgomery(poly *r, const poly *a, const poly *b);
//#define poly_tomont KYBER_NAMESPACE(poly_tomont)
void poly_tomont(poly *r);

//#define poly_reduce KYBER_NAMESPACE(poly_reduce)
void poly_reduce(poly *r);

//#define poly_add KYBER_NAMESPACE(poly_add)
void poly_add(poly *r, const poly *a, const poly *b);
//#define poly_sub KYBER_NAMESPACE(poly_sub)
void poly_sub(poly *r, const poly *a, const poly *b);

#endif
