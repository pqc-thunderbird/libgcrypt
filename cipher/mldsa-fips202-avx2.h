#ifndef FIPS202_H
#define FIPS202_H

#include <stddef.h>
#include <stdint.h>
#include "config.h"
#include "types.h"

#define SHAKE128_RATE 168
#define SHAKE256_RATE 136
#define SHA3_256_RATE 136
#define SHA3_512_RATE 72

#define FIPS202_NAMESPACE(s) pqcrystals_dilithium_fips202_avx2_##s

typedef struct {
  u64 s[25];
  unsigned int pos;
} keccak_state;

#define KeccakF_RoundConstants FIPS202_NAMESPACE(KeccakF_RoundConstants)
extern const u64 KeccakF_RoundConstants[];

#define shake128_init FIPS202_NAMESPACE(shake128_init)
void shake128_init(keccak_state *state);
#define shake128_absorb FIPS202_NAMESPACE(shake128_absorb)
void shake128_absorb(keccak_state *state, const byte *in, size_t inlen);
#define shake128_finalize FIPS202_NAMESPACE(shake128_finalize)
void shake128_finalize(keccak_state *state);
#define shake128_squeeze FIPS202_NAMESPACE(shake128_squeeze)
void shake128_squeeze(byte *out, size_t outlen, keccak_state *state);
#define shake128_absorb_once FIPS202_NAMESPACE(shake128_absorb_once)
void shake128_absorb_once(keccak_state *state, const byte *in, size_t inlen);
#define shake128_squeezeblocks FIPS202_NAMESPACE(shake128_squeezeblocks)
void shake128_squeezeblocks(byte *out, size_t nblocks, keccak_state *state);

#define shake256_init FIPS202_NAMESPACE(shake256_init)
void shake256_init(keccak_state *state);
#define shake256_absorb FIPS202_NAMESPACE(shake256_absorb)
void shake256_absorb(keccak_state *state, const byte *in, size_t inlen);
#define shake256_finalize FIPS202_NAMESPACE(shake256_finalize)
void shake256_finalize(keccak_state *state);
#define shake256_squeeze FIPS202_NAMESPACE(shake256_squeeze)
void shake256_squeeze(byte *out, size_t outlen, keccak_state *state);
#define shake256_absorb_once FIPS202_NAMESPACE(shake256_absorb_once)
void shake256_absorb_once(keccak_state *state, const byte *in, size_t inlen);
#define shake256_squeezeblocks FIPS202_NAMESPACE(shake256_squeezeblocks)
void shake256_squeezeblocks(byte *out, size_t nblocks,  keccak_state *state);

#define shake128 FIPS202_NAMESPACE(shake128)
void shake128(byte *out, size_t outlen, const byte *in, size_t inlen);
#define shake256 FIPS202_NAMESPACE(shake256)
void shake256(byte *out, size_t outlen, const byte *in, size_t inlen);
#define sha3_256 FIPS202_NAMESPACE(sha3_256)
void sha3_256(byte h[32], const byte *in, size_t inlen);
#define sha3_512 FIPS202_NAMESPACE(sha3_512)
void sha3_512(byte h[64], const byte *in, size_t inlen);

#endif
