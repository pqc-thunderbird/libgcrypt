#ifndef REJSAMPLE_H
#define REJSAMPLE_H

#include <stdint.h>
#include "mldsa-params-avx2.h"
#include "mldsa-symmetric-avx2.h"

extern const byte idxlut[256][8];

unsigned int rej_uniform_avx(int32_t *r, const byte *buf);

unsigned int rej_eta_avx_eta2(int32_t *r, const byte *buf);
unsigned int rej_eta_avx_eta4(int32_t *r, const byte *buf);

#endif
