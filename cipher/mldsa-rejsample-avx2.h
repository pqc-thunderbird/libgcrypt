#ifndef REJSAMPLE_H
#define REJSAMPLE_H

#include <stdint.h>
#include "mldsa-symmetric-avx2.h"

extern const byte _gcry_mldsa_avx2_idxlut[256][8];

unsigned int _gcry_mldsa_avx2_rej_uniform_avx(int32_t *r, const byte *buf);

unsigned int _gcry_mldsa_avx2_rej_eta_avx_eta2(int32_t *r, const byte *buf);
unsigned int _gcry_mldsa_avx2_rej_eta_avx_eta4(int32_t *r, const byte *buf);

#endif
