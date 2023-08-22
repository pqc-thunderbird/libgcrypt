#ifndef GCRYPT_KYBER_SYMMETRIC_H
#define GCRYPT_KYBER_SYMMETRIC_H

#include <config.h>
#include <stddef.h>
#include <stdint.h>
#include "kyber_params.h"


#include "g10lib.h"


void _gcry_kyber_shake128_absorb(gcry_md_hd_t h, const unsigned char seed[GCRY_KYBER_SYMBYTES], unsigned char x, unsigned char y);

/*************************************************
 * Name:        kyber_shake256_prf
 *
 * Description: Usage of SHAKE256 as a PRF, concatenates secret and public
 *input and then generates outlen bytes of SHAKE256 output
 *
 * Arguments:   - unsigned char *out: pointer to output
 *              - size_t outlen: number of requested output bytes
 *              - const unsigned char *key: pointer to the key (of length
 *GCRY_KYBER_SYMBYTES)
 *              - unsigned char nonce: single-byte nonce (public PRF input)
 **************************************************/
gcry_err_code_t _gcry_kyber_shake256_prf(uint8_t *out, size_t outlen, const uint8_t key[GCRY_KYBER_SYMBYTES], uint8_t nonce);

gcry_err_code_t _gcry_kyber_shake128_squeezeblocks(gcry_md_hd_t h, uint8_t *out, size_t nblocks );

gcry_err_code_t _gcry_kyber_prf(uint8_t *out, size_t outlen, const uint8_t key[GCRY_KYBER_SYMBYTES], uint8_t nonce);



#endif /* GCRYPT_KYBER_SYMMETRIC_H */
