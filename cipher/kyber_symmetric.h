#ifndef SYMMETRIC_H
#define SYMMETRIC_H

#include <config.h>
#include <stddef.h>
#include <stdint.h>
#include "kyber_params.h"


#include "kyber_fips202.h"

#include "g10lib.h"

typedef keccak_state xof_state;

// TODOMTG: REMOVE:
void kyber_shake128_absorb(keccak_state *s,
                           const uint8_t seed[GCRY_KYBER_SYMBYTES],
                           uint8_t x,
                           uint8_t y);

void _gcry_kyber_shake128_absorb(gcry_md_hd_t h, const unsigned char seed[GCRY_KYBER_SYMBYTES], unsigned char x, unsigned char y);

//#define kyber_shake256_prf KYBER_NAMESPACE(kyber_shake256_prf)
gcry_err_code_t kyber_shake256_prf(uint8_t *out, size_t outlen, const uint8_t key[GCRY_KYBER_SYMBYTES], uint8_t nonce);

gcry_err_code_t _gcry_kyber_shake128_squeezeblocks(gcry_md_hd_t h, uint8_t *out, size_t nblocks );

gcry_err_code_t _gcry_kyber_prf(uint8_t *out, size_t outlen, const uint8_t key[GCRY_KYBER_SYMBYTES], uint8_t nonce);

#define XOF_BLOCKBYTES SHAKE128_RATE

//#define hash_h(OUT, IN, INBYTES) sha3_256(OUT, IN, INBYTES)
//#define hash_g(OUT, IN, INBYTES) sha3_512(OUT, IN, INBYTES)
#define xof_absorb(STATE, SEED, X, Y) kyber_shake128_absorb(STATE, SEED, X, Y)
#define xof_squeezeblocks(OUT, OUTBLOCKS, STATE) shake128_squeezeblocks(OUT, OUTBLOCKS, STATE)
//#define prf(OUT, OUTBYTES, KEY, NONCE) kyber_shake256_prf(OUT, OUTBYTES, KEY, NONCE)
//#define kdf(OUT, IN, INBYTES) shake256(OUT, KYBER_SSBYTES, IN, INBYTES)


#endif /* SYMMETRIC_H */
