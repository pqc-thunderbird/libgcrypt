#ifndef CBD_H
#define CBD_H

#include <stdint.h>
#include <immintrin.h>
#include "mlkem-params-avx2.h"
#include "mlkem-poly-avx2.h"

void poly_cbd_eta1(poly *r, const __m256i buf[KYBER_ETA1*KYBER_N/128+1]);
void poly_cbd_eta2(poly *r, const __m256i buf[KYBER_ETA2*KYBER_N/128]);

#endif
