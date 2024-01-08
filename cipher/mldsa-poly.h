#ifndef _GCRY_MLDSA_POLY_H
#define _GCRY_MLDSA_POLY_H

#include <config.h>

#include "types.h"
#include "mldsa-params.h"
#include "avx2-immintrin-support.h"

#ifdef USE_AVX2
#include <immintrin.h>
#endif

#include "g10lib.h"

#ifdef USE_AVX2
typedef struct
{
  union
  {
    s32 coeffs[GCRY_MLDSA_N];
    __m256i vec[(GCRY_MLDSA_N + 7) / 8];
  };
} gcry_mldsa_poly;
#else
typedef struct
{
  s32 coeffs[GCRY_MLDSA_N];
} gcry_mldsa_poly;
#endif


void _gcry_mldsa_poly_reduce(gcry_mldsa_poly *a);
void _gcry_mldsa_poly_caddq(gcry_mldsa_poly *a);

void _gcry_mldsa_poly_add(gcry_mldsa_poly *c, const gcry_mldsa_poly *a, const gcry_mldsa_poly *b);
void _gcry_mldsa_poly_sub(gcry_mldsa_poly *c, const gcry_mldsa_poly *a, const gcry_mldsa_poly *b);
void _gcry_mldsa_poly_shiftl(gcry_mldsa_poly *a);

void _gcry_mldsa_poly_ntt(gcry_mldsa_poly *a);
void _gcry_mldsa_poly_invntt_tomont(gcry_mldsa_poly *a);
void _gcry_mldsa_poly_pointwise_montgomery(gcry_mldsa_poly *c, const gcry_mldsa_poly *a, const gcry_mldsa_poly *b);

void _gcry_mldsa_poly_power2round(gcry_mldsa_poly *a1, gcry_mldsa_poly *a0, const gcry_mldsa_poly *a);
void _gcry_mldsa_poly_decompose(gcry_mldsa_param_t *params,
                                gcry_mldsa_poly *a1,
                                gcry_mldsa_poly *a0,
                                const gcry_mldsa_poly *a);
unsigned int _gcry_mldsa_poly_make_hint(gcry_mldsa_param_t *params,
                                        gcry_mldsa_poly *h,
                                        const gcry_mldsa_poly *a0,
                                        const gcry_mldsa_poly *a1);
void _gcry_mldsa_poly_use_hint(gcry_mldsa_param_t *params,
                               gcry_mldsa_poly *b,
                               const gcry_mldsa_poly *a,
                               const gcry_mldsa_poly *h);

int _gcry_mldsa_poly_chknorm(const gcry_mldsa_poly *a, s32 B);
gcry_err_code_t _gcry_mldsa_poly_uniform(gcry_mldsa_poly *a, const byte seed[GCRY_MLDSA_SEEDBYTES], u16 nonce);
gcry_err_code_t _gcry_mldsa_poly_uniform_eta(gcry_mldsa_param_t *params,
                                             gcry_mldsa_poly *a,
                                             const byte seed[GCRY_MLDSA_CRHBYTES],
                                             u16 nonce);
gcry_err_code_t _gcry_mldsa_poly_uniform_gamma1(gcry_mldsa_param_t *params,
                                                gcry_mldsa_poly *a,
                                                const byte seed[GCRY_MLDSA_CRHBYTES],
                                                u16 nonce);
gcry_err_code_t _gcry_mldsa_poly_challenge(gcry_mldsa_param_t *params,
                                           gcry_mldsa_poly *c,
                                           const byte seed[GCRY_MLDSA_SEEDBYTES]);

void _gcry_mldsa_polyeta_pack(gcry_mldsa_param_t *params, byte *r, const gcry_mldsa_poly *a);
void _gcry_mldsa_polyeta_unpack(gcry_mldsa_param_t *params, gcry_mldsa_poly *r, const byte *a);

void _gcry_mldsa_polyt1_pack(byte *r, const gcry_mldsa_poly *a);
void _gcry_mldsa_polyt1_unpack(gcry_mldsa_poly *r, const byte *a);

void _gcry_mldsa_polyt0_pack(byte *r, const gcry_mldsa_poly *a);
void _gcry_mldsa_polyt0_unpack(gcry_mldsa_poly *r, const byte *a);

void _gcry_mldsa_polyz_pack(gcry_mldsa_param_t *params, byte *r, const gcry_mldsa_poly *a);
void _gcry_mldsa_polyz_unpack(gcry_mldsa_param_t *params, gcry_mldsa_poly *r, const byte *a);

void _gcry_mldsa_polyw1_pack(gcry_mldsa_param_t *params, byte *r, const gcry_mldsa_poly *a);

#endif
