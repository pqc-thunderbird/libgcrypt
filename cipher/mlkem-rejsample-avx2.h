#ifndef GCRYPT_MLKEM_REJSAMPLE_AVX2_H
#define GCRYPT_MLKEM_REJSAMPLE_AVX2_H

#include <stdint.h>
#include "mlkem-params.h"
#include "mlkem-fips202x4-avx2.h"

#define XOF_BLOCKBYTES GCRY_SHAKE128_RATE

#define GCRY_MLKEM_REJ_UNIFORM_AVX_NBLOCKS                                    \
  ((12 * GCRY_MLKEM_N / 8 * (1 << 12) / GCRY_MLKEM_Q + XOF_BLOCKBYTES)        \
   / XOF_BLOCKBYTES)
#define GCRY_MLKEM_REJ_UNIFORM_AVX_BUFLEN                                     \
  (GCRY_MLKEM_REJ_UNIFORM_AVX_NBLOCKS * XOF_BLOCKBYTES)

unsigned int _gcry_mlkem_avx2_rej_uniform_avx (int16_t *r, const uint8_t *buf);

#endif
