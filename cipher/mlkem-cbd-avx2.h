#ifndef CBD_H
#define CBD_H

#include <stdint.h>
#include <immintrin.h>
#include "mlkem-poly-avx2.h"

void _gcry_mlkem_avx2_poly_cbd_eta1 (gcry_mlkem_poly *r,
                                     const __m256i *buf,
                                     gcry_mlkem_param_t const *param);
void _gcry_mlkem_avx2_poly_cbd_eta2 (
    gcry_mlkem_poly *r,
    const __m256i buf[GCRY_MLKEM_ETA2 * GCRY_MLKEM_N / 128]);

#endif
