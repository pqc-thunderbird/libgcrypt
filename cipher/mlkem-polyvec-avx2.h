#ifndef GCRYPT_MLKEM_POLYVEC_AVX2_H
#define GCRYPT_MLKEM_POLYVEC_AVX2_H

#include <stdint.h>
#include "mlkem-params.h"
#include "mlkem-poly-avx2.h"
#include "mlkem-poly.h"
#include "mlkem-polyvec.h"

/**
 * represents the avx2 poly  / polyvec types, each is simply an aligned buffer.
 */
typedef struct
{
  byte *buf;
  byte *alloc_addr;
} gcry_mlkem_polybuf_al;

/* aligned buffer type */
typedef gcry_mlkem_polybuf_al gcry_mlkem_buf_al;

gcry_err_code_t _gcry_mlkem_polybuf_al_create (gcry_mlkem_polybuf_al *vec,
                                               size_t num_elems,
                                               size_t size_elems,
                                               int secure);
void _gcry_mlkem_polybuf_al_destroy (gcry_mlkem_polybuf_al *vec);

gcry_err_code_t _gcry_mlkem_buf_al_create (gcry_mlkem_buf_al *buf,
                                           size_t size,
                                           int secure);

void _gcry_mlkem_buf_al_destroy (gcry_mlkem_buf_al *buf);


void _gcry_mlkem_avx2_polyvec_compress (uint8_t *r,
                                        const gcry_mlkem_poly *a,
                                        const gcry_mlkem_param_t *param);
void _gcry_mlkem_avx2_polyvec_decompress (gcry_mlkem_poly *r,
                                          const uint8_t *a,
                                          const gcry_mlkem_param_t *param);

void _gcry_mlkem_avx2_polyvec_tobytes (uint8_t *r,
                                       const gcry_mlkem_poly *a,
                                       const gcry_mlkem_param_t *param);
void _gcry_mlkem_avx2_polyvec_frombytes (gcry_mlkem_poly *r,
                                         const uint8_t *a,
                                         const gcry_mlkem_param_t *param);

void _gcry_mlkem_avx2_polyvec_ntt (gcry_mlkem_poly *r,
                                   const gcry_mlkem_param_t *param);
void _gcry_mlkem_avx2_polyvec_invntt_tomont (gcry_mlkem_poly *r,
                                             const gcry_mlkem_param_t *param);

gcry_err_code_t _gcry_mlkem_avx2_polyvec_basemul_acc_montgomery (
    gcry_mlkem_poly *r,
    const gcry_mlkem_poly *a,
    const gcry_mlkem_poly *b,
    const gcry_mlkem_param_t *param);

void _gcry_mlkem_avx2_polyvec_reduce (gcry_mlkem_poly *r,
                                      const gcry_mlkem_param_t *param);

void _gcry_mlkem_avx2_polyvec_add (gcry_mlkem_poly *r,
                                   const gcry_mlkem_poly *a,
                                   const gcry_mlkem_poly *b,
                                   const gcry_mlkem_param_t *param);

#endif
