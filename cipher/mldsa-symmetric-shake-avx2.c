#include <stdint.h>
#include "config.h"
#include "mldsa-params-avx2.h"
#include "mldsa-symmetric-avx2.h"
#include "mldsa-fips202-avx2.h"

void dilithium_shake128_stream_init(keccak_state *state, const byte seed[GCRY_MLDSA_SEEDBYTES], uint16_t nonce)
{
  byte t[2];
  t[0] = nonce;
  t[1] = nonce >> 8;

  shake128_init(state);
  shake128_absorb(state, seed, GCRY_MLDSA_SEEDBYTES);
  shake128_absorb(state, t, 2);
  shake128_finalize(state);
}

void dilithium_shake256_stream_init(keccak_state *state, const byte seed[GCRY_MLDSA_CRHBYTES], uint16_t nonce)
{
  byte t[2];
  t[0] = nonce;
  t[1] = nonce >> 8;

  shake256_init(state);
  shake256_absorb(state, seed, GCRY_MLDSA_CRHBYTES);
  shake256_absorb(state, t, 2);
  shake256_finalize(state);
}
