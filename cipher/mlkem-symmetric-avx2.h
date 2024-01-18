#ifndef SYMMETRIC_H
#define SYMMETRIC_H

#include <stddef.h>
#include <stdint.h>
#include "mlkem-fips202-avx2.h"
#include "mlkem-fips202x4-avx2.h"

typedef keccak_state xof_state;

void kyber_shake128_absorb (keccak_state *s,
                            const uint8_t seed[GCRY_MLKEM_SYMBYTES],
                            uint8_t x,
                            uint8_t y);

void _gcry_mlkem_shake256_prf (uint8_t *out,
                               size_t outlen,
                               const uint8_t key[GCRY_MLKEM_SYMBYTES],
                               uint8_t nonce);

#define XOF_BLOCKBYTES SHAKE128_RATE

#define hash_h(OUT, IN, INBYTES) sha3_256 (OUT, IN, INBYTES)
#define hash_g(OUT, IN, INBYTES) sha3_512 (OUT, IN, INBYTES)
#define xof_absorb(STATE, SEED, X, Y) kyber_shake128_absorb (STATE, SEED, X, Y)
#define xof_squeezeblocks(OUT, OUTBLOCKS, STATE)                              \
  shake128_squeezeblocks (OUT, OUTBLOCKS, STATE)
#define prf(OUT, OUTBYTES, KEY, NONCE)                                        \
  _gcry_mlkem_shake256_prf (OUT, OUTBYTES, KEY, NONCE)
#define rkprf(OUT, KEY, INPUT, INPUT_LEN)                                     \
  _gcry_mlkem_mlkem_shake256_rkprf (OUT, KEY, INPUT, INPUT_LEN)

#endif /* SYMMETRIC_H */
