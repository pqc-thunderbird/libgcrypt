#include <stdint.h>
#include "dilithium-params.h"
#include "dilithium-symmetric.h"
#include "dilithium-fips202.h"

void dilithium_shake128_stream_init(keccak_state *state, const uint8_t seed[GCRY_DILITHIUM_SEEDBYTES], uint16_t nonce)
{
  uint8_t t[2];
  t[0] = nonce;
  t[1] = nonce >> 8;

  shake128_init(state);
  shake128_absorb(state, seed, GCRY_DILITHIUM_SEEDBYTES);
  shake128_absorb(state, t, 2);
  shake128_finalize(state);
}

void dilithium_shake256_stream_init(keccak_state *state, const uint8_t seed[GCRY_DILITHIUM_CRHBYTES], uint16_t nonce)
{
  uint8_t t[2];
  t[0] = nonce;
  t[1] = nonce >> 8;

  shake256_init(state);
  shake256_absorb(state, seed, GCRY_DILITHIUM_CRHBYTES);
  shake256_absorb(state, t, 2);
  shake256_finalize(state);
}
