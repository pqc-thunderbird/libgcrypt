#ifndef CBD_H
#define CBD_H

#include <stdint.h>
#include <immintrin.h>
#include "mlkem-params-avx2.h"
#include "mlkem-poly-avx2.h"

void poly_cbd_eta1(poly *r, const __m256i *buf, gcry_mlkem_param_t const *param);
void poly_cbd_eta2(poly *r, const __m256i buf[GCRY_MLKEM_ETA2*GCRY_MLKEM_N/128]);

#endif
