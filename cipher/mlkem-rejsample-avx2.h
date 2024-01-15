#ifndef REJSAMPLE_H
#define REJSAMPLE_H

#include <stdint.h>
#include "mlkem-params-avx2.h"
#include "mlkem-symmetric-avx2.h"

#define REJ_UNIFORM_AVX_NBLOCKS ((12*KYBER_N/8*(1 << 12)/KYBER_Q + XOF_BLOCKBYTES)/XOF_BLOCKBYTES)
#define REJ_UNIFORM_AVX_BUFLEN (REJ_UNIFORM_AVX_NBLOCKS*XOF_BLOCKBYTES)

#define rej_uniform_avx KYBER_NAMESPACE(rej_uniform_avx)
unsigned int rej_uniform_avx(int16_t *r, const uint8_t *buf);

#endif
