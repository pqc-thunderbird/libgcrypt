#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "kyber_params.h"
#include "kyber_symmetric.h"
#include "kyber_fips202.h"

#include "gcrypt.h"

/*************************************************
* Name:        kyber_shake128_absorb
*
* Description: Absorb step of the SHAKE128 specialized for the Kyber context.
*
* Arguments:   - keccak_state *state: pointer to (uninitialized) output Keccak state
*              - const unsigned char *seed: pointer to GCRY_KYBER_SYMBYTES input to be absorbed into state
*              - unsigned char i: additional byte of input
*              - unsigned char j: additional byte of input
**************************************************/
// TODOMTG: REMOVE WHEN NEW IS WORKING
void kyber_shake128_absorb(keccak_state *state,
                           const unsigned char seed[GCRY_KYBER_SYMBYTES],
                           unsigned char x,
                           unsigned char y)
{
  unsigned char extseed[GCRY_KYBER_SYMBYTES+2];

  memcpy(extseed, seed, GCRY_KYBER_SYMBYTES);
  extseed[GCRY_KYBER_SYMBYTES+0] = x;
  extseed[GCRY_KYBER_SYMBYTES+1] = y;

  shake128_absorb_once(state, extseed, sizeof(extseed));
}

void _gcry_kyber_shake128_absorb(gcry_md_hd_t h, const unsigned char seed[GCRY_KYBER_SYMBYTES], unsigned char x, unsigned char y)
{
  unsigned char extseed[GCRY_KYBER_SYMBYTES+2];

  memcpy(extseed, seed, GCRY_KYBER_SYMBYTES);
  extseed[GCRY_KYBER_SYMBYTES+0] = x;
  extseed[GCRY_KYBER_SYMBYTES+1] = y;

  _gcry_md_write(h, extseed, sizeof(extseed));

}


gcry_err_code_t _gcry_kyber_shake128_squeezeblocks(gcry_md_hd_t h, uint8_t *out, size_t nblocks )
{
  return _gcry_md_extract(h, GCRY_MD_SHAKE128, out, SHAKE128_RATE * nblocks);
  //keccak_squeezeblocks(out, nblocks, state->s, SHAKE128_RATE);
}

/*************************************************
* Name:        kyber_shake256_prf
*
* Description: Usage of SHAKE256 as a PRF, concatenates secret and public input
*              and then generates outlen bytes of SHAKE256 output
*
* Arguments:   - unsigned char *out: pointer to output
*              - size_t outlen: number of requested output bytes
*              - const unsigned char *key: pointer to the key (of length GCRY_KYBER_SYMBYTES)
*              - unsigned char nonce: single-byte nonce (public PRF input)
**************************************************/
gcry_err_code_t kyber_shake256_prf(unsigned char *out, size_t outlen, const unsigned char key[GCRY_KYBER_SYMBYTES], unsigned char nonce)
{
  unsigned char extkey[GCRY_KYBER_SYMBYTES+1];
  gcry_err_code_t ec = 0;
  gcry_md_hd_t h;

  memcpy(extkey, key, GCRY_KYBER_SYMBYTES);
  extkey[GCRY_KYBER_SYMBYTES] = nonce;

#if 0
  shake256(out, outlen, extkey, sizeof(extkey));
#else

  if ((ec = _gcry_md_open(&h, GCRY_MD_SHAKE256, GCRY_MD_FLAG_SECURE)))
    {
      return ec;
    }
  _gcry_md_write(h, extkey, sizeof(extkey));
  ec = _gcry_md_extract(h, GCRY_MD_SHAKE256, out, outlen);
  _gcry_md_close(h);
  return ec;
#endif
}

gcry_err_code_t _gcry_kyber_prf(unsigned char *out, size_t outlen, const unsigned char key[GCRY_KYBER_SYMBYTES], unsigned char nonce) //OUT, OUTBYTES, KEY, NONCE)
{
    return kyber_shake256_prf(out, outlen, key, nonce);
}
