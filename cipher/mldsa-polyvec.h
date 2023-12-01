#ifndef _GCRY_MLDSA_POLYVEC_H
#define _GCRY_MLDSA_POLYVEC_H
#include <config.h>

#include "types.h"
#include "mldsa-params.h"
#include "mldsa-poly.h"
#include "g10lib.h"

typedef struct
{
  gcry_mldsa_poly *vec;
} gcry_mldsa_polyvec;

/**
 * represents the avx2 poly / polymat / polyvec types, each is simply an aligned buffer.
*/
typedef struct
{
  byte *buf;
  byte *alloc_addr;
} gcry_mldsa_polybuf_al;

/* aligned buffer type */
typedef gcry_mldsa_polybuf_al gcry_mldsa_buf_al;

gcry_err_code_t _gcry_mldsa_polymatrix_create(gcry_mldsa_polyvec **polymat,
                                              unsigned char mat_elems,
                                              unsigned char vec_elems);
void _gcry_mldsa_polymatrix_destroy(gcry_mldsa_polyvec **polymat, unsigned char elems);
gcry_err_code_t _gcry_mldsa_polyvec_create(gcry_mldsa_polyvec *polyvec, unsigned char elems);
gcry_err_code_t _gcry_mldsa_polyvec_copy(gcry_mldsa_polyvec *a, gcry_mldsa_polyvec *b, unsigned char elems);
void _gcry_mldsa_polyvec_destroy(gcry_mldsa_polyvec *polyvec);

gcry_err_code_t _gcry_mldsa_polyvecl_uniform_eta(gcry_mldsa_param_t *params,
                                                 gcry_mldsa_polyvec *v,
                                                 const byte seed[GCRY_MLDSA_CRHBYTES],
                                                 u16 nonce);

gcry_err_code_t _gcry_mldsa_polyvecl_uniform_gamma1(gcry_mldsa_param_t *params,
                                                    gcry_mldsa_polyvec *v,
                                                    const byte seed[GCRY_MLDSA_CRHBYTES],
                                                    u16 nonce);

void _gcry_mldsa_polyvecl_reduce(gcry_mldsa_param_t *params, gcry_mldsa_polyvec *v);

void _gcry_mldsa_polyvecl_add(gcry_mldsa_param_t *params,
                              gcry_mldsa_polyvec *w,
                              const gcry_mldsa_polyvec *u,
                              const gcry_mldsa_polyvec *v);

void _gcry_mldsa_polyvecl_ntt(gcry_mldsa_param_t *params, gcry_mldsa_polyvec *v);
void _gcry_mldsa_polyvecl_invntt_tomont(gcry_mldsa_param_t *params, gcry_mldsa_polyvec *v);
void _gcry_mldsa_polyvecl_pointwise_poly_montgomery(gcry_mldsa_param_t *params,
                                                    gcry_mldsa_polyvec *r,
                                                    const gcry_mldsa_poly *a,
                                                    const gcry_mldsa_polyvec *v);

void _gcry_mldsa_polyvecl_pointwise_acc_montgomery(gcry_mldsa_param_t *params,
                                                   gcry_mldsa_poly *w,
                                                   const gcry_mldsa_polyvec *u,
                                                   const gcry_mldsa_polyvec *v);


int _gcry_mldsa_polyvecl_chknorm(gcry_mldsa_param_t *params, const gcry_mldsa_polyvec *v, s32 B);

gcry_err_code_t _gcry_mldsa_polyveck_uniform_eta(gcry_mldsa_param_t *params,
                                                 gcry_mldsa_polyvec *v,
                                                 const byte seed[GCRY_MLDSA_CRHBYTES],
                                                 u16 nonce);

void _gcry_mldsa_polyveck_reduce(gcry_mldsa_param_t *params, gcry_mldsa_polyvec *v);
void _gcry_mldsa_polyveck_caddq(gcry_mldsa_param_t *params, gcry_mldsa_polyvec *v);

void _gcry_mldsa_polyveck_add(gcry_mldsa_param_t *params,
                              gcry_mldsa_polyvec *w,
                              const gcry_mldsa_polyvec *u,
                              const gcry_mldsa_polyvec *v);
void _gcry_mldsa_polyveck_sub(gcry_mldsa_param_t *params,
                              gcry_mldsa_polyvec *w,
                              const gcry_mldsa_polyvec *u,
                              const gcry_mldsa_polyvec *v);
void _gcry_mldsa_polyveck_shiftl(gcry_mldsa_param_t *params, gcry_mldsa_polyvec *v);

void _gcry_mldsa_polyveck_ntt(gcry_mldsa_param_t *params, gcry_mldsa_polyvec *v);
void _gcry_mldsa_polyveck_invntt_tomont(gcry_mldsa_param_t *params, gcry_mldsa_polyvec *v);
void _gcry_mldsa_polyveck_pointwise_poly_montgomery(gcry_mldsa_param_t *params,
                                                    gcry_mldsa_polyvec *r,
                                                    const gcry_mldsa_poly *a,
                                                    const gcry_mldsa_polyvec *v);

int _gcry_mldsa_polyveck_chknorm(gcry_mldsa_param_t *params, const gcry_mldsa_polyvec *v, s32 B);

void _gcry_mldsa_polyveck_power2round(gcry_mldsa_param_t *params,
                                      gcry_mldsa_polyvec *v1,
                                      gcry_mldsa_polyvec *v0,
                                      const gcry_mldsa_polyvec *v);
void _gcry_mldsa_polyveck_decompose(gcry_mldsa_param_t *params,
                                    gcry_mldsa_polyvec *v1,
                                    gcry_mldsa_polyvec *v0,
                                    const gcry_mldsa_polyvec *v);
unsigned int _gcry_mldsa_polyveck_make_hint(gcry_mldsa_param_t *params,
                                            gcry_mldsa_polyvec *h,
                                            const gcry_mldsa_polyvec *v0,
                                            const gcry_mldsa_polyvec *v1);
void _gcry_mldsa_polyveck_use_hint(gcry_mldsa_param_t *params,
                                   gcry_mldsa_polyvec *w,
                                   const gcry_mldsa_polyvec *v,
                                   const gcry_mldsa_polyvec *h);

void _gcry_mldsa_polyveck_pack_w1(gcry_mldsa_param_t *params, byte *r, const gcry_mldsa_polyvec *w1);

gcry_err_code_t _gcry_mldsa_polyvec_matrix_expand(gcry_mldsa_param_t *params,
                                                  gcry_mldsa_polyvec *mat,
                                                  const byte rho[GCRY_MLDSA_SEEDBYTES]);

void _gcry_mldsa_polyvec_matrix_pointwise_montgomery(gcry_mldsa_param_t *params,
                                                     gcry_mldsa_polyvec *t,
                                                     const gcry_mldsa_polyvec *mat,
                                                     const gcry_mldsa_polyvec *v);

#endif
