#ifndef _GCRY_MLDSA_AVX2_REJSAMPLE_H
#define _GCRY_MLDSA_AVX2_REJSAMPLE_H

#include <stdint.h>

extern const byte _gcry_mldsa_avx2_idxlut[256][8];

unsigned int _gcry_mldsa_avx2_rej_uniform_avx(s32 *r, const byte *buf);

unsigned int _gcry_mldsa_avx2_rej_eta_avx_eta2(s32 *r, const byte *buf);
unsigned int _gcry_mldsa_avx2_rej_eta_avx_eta4(s32 *r, const byte *buf);

#endif
