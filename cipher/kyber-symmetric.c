#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "kyber-params.h"
#include "kyber-symmetric.h"

#include "gcrypt.h"


void
_gcry_kyber_shake128_absorb (gcry_md_hd_t h,
                             const unsigned char seed[GCRY_KYBER_SYMBYTES],
                             unsigned char x,
                             unsigned char y)
{
  unsigned char extseed[GCRY_KYBER_SYMBYTES + 2];

  memcpy (extseed, seed, GCRY_KYBER_SYMBYTES);
  extseed[GCRY_KYBER_SYMBYTES + 0] = x;
  extseed[GCRY_KYBER_SYMBYTES + 1] = y;

  _gcry_md_write (h, extseed, sizeof (extseed));
}


gcry_err_code_t
_gcry_kyber_shake128_squeezeblocks (gcry_md_hd_t h,
                                    uint8_t *out,
                                    size_t nblocks)
{
  return _gcry_md_extract (
      h, GCRY_MD_SHAKE128, out, GCRY_SHAKE128_RATE * nblocks);
}

gcry_err_code_t
_gcry_kyber_shake256_prf (unsigned char *out,
                          size_t outlen,
                          const unsigned char key[GCRY_KYBER_SYMBYTES],
                          unsigned char nonce)
{
  unsigned char extkey[GCRY_KYBER_SYMBYTES + 1];
  gcry_err_code_t ec = 0;
  gcry_md_hd_t h;

  memcpy (extkey, key, GCRY_KYBER_SYMBYTES);
  extkey[GCRY_KYBER_SYMBYTES] = nonce;
  ec = _gcry_md_open (&h, GCRY_MD_SHAKE256, GCRY_MD_FLAG_SECURE);
  if (ec)
    {
      return ec;
    }
  _gcry_md_write (h, extkey, sizeof (extkey));
  ec = _gcry_md_extract (h, GCRY_MD_SHAKE256, out, outlen);
  _gcry_md_close (h);
  return ec;
}

gcry_err_code_t
_gcry_kyber_prf (unsigned char *out,
                 size_t outlen,
                 const unsigned char key[GCRY_KYBER_SYMBYTES],
                 unsigned char nonce)
{
  return _gcry_kyber_shake256_prf (out, outlen, key, nonce);
}
