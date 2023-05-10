#ifndef POLYVEC_H
#define POLYVEC_H

#include <config.h>
#include <stdint.h>
#include "kyber_params.h"
#include "kyber_poly.h"
#include "g10lib.h"

typedef struct{
  poly *vec; //[KYBER_K];
} gcry_kyber_polyvec;


gcry_error_t gcry_kyber_polymatrix_create(gcry_kyber_polyvec **polymat, gcry_kyber_param_t * param);
void gcry_kyber_polymatrix_destroy(gcry_kyber_polyvec **polymat, gcry_kyber_param_t * param);

gcry_error_t gcry_kyber_polyvec_create(gcry_kyber_polyvec *polyvec, gcry_kyber_param_t * param);
void gcry_kyber_polyvec_destroy(gcry_kyber_polyvec *polyvec);

#define gcry_kyber_polyvec_compress KYBER_NAMESPACE(gcry_kyber_polyvec_compress)
void gcry_kyber_polyvec_compress(uint8_t r[KYBER_POLYVECCOMPRESSEDBYTES], const gcry_kyber_polyvec *a);
#define gcry_kyber_polyvec_decompress KYBER_NAMESPACE(gcry_kyber_polyvec_decompress)
void gcry_kyber_polyvec_decompress(gcry_kyber_polyvec *r, const uint8_t a[KYBER_POLYVECCOMPRESSEDBYTES]);

#define gcry_kyber_polyvec_tobytes KYBER_NAMESPACE(gcry_kyber_polyvec_tobytes)
void gcry_kyber_polyvec_tobytes(uint8_t r[KYBER_POLYVECBYTES], const gcry_kyber_polyvec *a);
#define gcry_kyber_polyvec_frombytes KYBER_NAMESPACE(gcry_kyber_polyvec_frombytes)
void gcry_kyber_polyvec_frombytes(gcry_kyber_polyvec *r, const uint8_t a[KYBER_POLYVECBYTES]);

#define gcry_kyber_polyvec_ntt KYBER_NAMESPACE(gcry_kyber_polyvec_ntt)
void gcry_kyber_polyvec_ntt(gcry_kyber_polyvec *r);
#define gcry_kyber_polyvec_invntt_tomont KYBER_NAMESPACE(gcry_kyber_polyvec_invntt_tomont)
void gcry_kyber_polyvec_invntt_tomont(gcry_kyber_polyvec *r);

#define gcry_kyber_polyvec_basemul_acc_montgomery KYBER_NAMESPACE(gcry_kyber_polyvec_basemul_acc_montgomery)
void gcry_kyber_polyvec_basemul_acc_montgomery(poly *r, const gcry_kyber_polyvec *a, const gcry_kyber_polyvec *b);

#define gcry_kyber_polyvec_reduce KYBER_NAMESPACE(gcry_kyber_polyvec_reduce)
void gcry_kyber_polyvec_reduce(gcry_kyber_polyvec *r);

#define gcry_kyber_polyvec_add KYBER_NAMESPACE(gcry_kyber_polyvec_add)
void gcry_kyber_polyvec_add(gcry_kyber_polyvec *r, const gcry_kyber_polyvec *a, const gcry_kyber_polyvec *b);

#endif
