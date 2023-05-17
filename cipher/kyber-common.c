
//#include <config.h>
#include "kyber-common.h"
#include "kyber_params.h"
#include "kyber_indcpa.h"
#include "kyber_polyvec.h"
#include "kyber_poly.h"
#include "kyber_ntt.h"
#include "kyber_verify.h"
#include "kyber_symmetric.h"
#include "kyber_randombytes.h"
#include "gcrypt.h"

#include "g10lib.h"


gcry_err_code_t crypto_kem_keypair_derand(uint8_t *pk, uint8_t *sk, gcry_kyber_param_t *param, uint8_t *coins)
{
  gpg_err_code_t ec = 0;
  if ((ec = indcpa_keypair(pk, sk, param, coins)))
    {
      return ec;
    }
  memcpy(&sk[param->indcpa_secret_key_bytes], pk, param->public_key_bytes);
  //_gcry_md_hash_buffer(GCRY_MD_SHA3_256, sk + KYBER_SECRETKEYBYTES - 2 * KYBER_SYMBYTES, pk, KYBER_PUBLICKEYBYTES);
  _gcry_md_hash_buffer(GCRY_MD_SHA3_256, sk + param->secret_key_bytes - 2 * KYBER_SYMBYTES, pk, param->public_key_bytes);
  /* Value z for pseudo-random output on reject */
  memcpy(sk + param->secret_key_bytes - KYBER_SYMBYTES, coins + KYBER_SYMBYTES, KYBER_SYMBYTES);
  return ec;
}

static gcry_err_code_t kyber_shake256_rkprf(uint8_t out[KYBER_SSBYTES],
                                            const uint8_t key[KYBER_SYMBYTES],
                                            const uint8_t* input,
                                            size_t input_length)
{
  gcry_md_hd_t h;
  gcry_err_code_t ec = 0;
  if ((ec = _gcry_md_open(&h, GCRY_MD_SHAKE256, GCRY_MD_FLAG_SECURE)))
    {
      return ec;
    }
  _gcry_md_write(h, key, KYBER_SYMBYTES);
  _gcry_md_write(h, input, input_length);
  ec = _gcry_md_extract(h, GCRY_MD_SHAKE256, out, KYBER_SSBYTES);
  _gcry_md_close(h);
  return ec;
}


gcry_err_code_t crypto_kem_keypair(uint8_t *pk, uint8_t *sk, gcry_kyber_param_t *param)
{
  uint8_t coins[2 * KYBER_SYMBYTES];
  _gcry_randomize(coins, 2 * KYBER_SYMBYTES, GCRY_VERY_STRONG_RANDOM);
  return crypto_kem_keypair_derand(pk, sk, param, coins);
}

gcry_err_code_t crypto_kem_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk, gcry_kyber_param_t *param)
{
  gcry_err_code_t ec = 0;
  int fail;
  uint8_t buf[2 * KYBER_SYMBYTES];
  /* Will contain key, coins */
  uint8_t kr[2 * KYBER_SYMBYTES];

  uint8_t *cmp = NULL;
  // const uint8_t *pk = sk+KYBER_INDCPA_SECRETKEYBYTES;
  const uint8_t *pk = sk + param->indcpa_secret_key_bytes;

  cmp = xtrymalloc(param->ciphertext_bytes);
  if ((ec = indcpa_dec(buf, ct, sk, param)))
    {
      goto end;
    }

  /* Multitarget countermeasure for coins + contributory KEM */
  memcpy(buf + KYBER_SYMBYTES, sk + param->secret_key_bytes - 2 * KYBER_SYMBYTES, KYBER_SYMBYTES);
  _gcry_md_hash_buffer(GCRY_MD_SHA3_512, kr, buf, 2 * KYBER_SYMBYTES);

  /* coins are in kr+KYBER_SYMBYTES */
  if ((ec = indcpa_enc(cmp, buf, pk, kr + KYBER_SYMBYTES, param)))
    {
      goto end;
    }

  fail = verify(ct, cmp, KYBER_CIPHERTEXTBYTES);


  /* Compute rejection key */
  if ((ec = kyber_shake256_rkprf(ss, sk + param->secret_key_bytes - KYBER_SYMBYTES, ct, param->ciphertext_bytes)))
    {
      goto end;
    }

  /* Copy true key to return buffer if fail is false */
  cmov(ss, kr, KYBER_SYMBYTES, !fail);

end:
  xfree(cmp);
  return ec;
}

gcry_err_code_t kyber_kem_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk, gcry_kyber_param_t *param)
{
  uint8_t coins[KYBER_SYMBYTES];
  _gcry_randomize(coins, KYBER_SYMBYTES, GCRY_VERY_STRONG_RANDOM);
  return kyber_kem_enc_derand(ct, ss, pk, param, coins);
}

gcry_err_code_t kyber_kem_enc_derand(
    uint8_t *ct, uint8_t *ss, const uint8_t *pk, gcry_kyber_param_t *param, uint8_t *coins)
{
  gpg_err_code_t ec = 0;
  uint8_t buf[2 * KYBER_SYMBYTES];
  /* Will contain key, coins */
  uint8_t kr[2 * KYBER_SYMBYTES];

  /* Don't release system RNG output */
  _gcry_md_hash_buffer(GCRY_MD_SHA3_256, buf, coins, KYBER_SYMBYTES);

  /* Multitarget countermeasure for coins + contributory KEM */
  //_gcry_md_hash_buffer(GCRY_MD_SHA3_256, buf+KYBER_SYMBYTES, pk, KYBER_PUBLICKEYBYTES);
  _gcry_md_hash_buffer(GCRY_MD_SHA3_256, buf + KYBER_SYMBYTES, pk, param->public_key_bytes);
  //_gcry_md_hash_buffer(GCRY_MD_SHA3_512, kr, buf, 2*KYBER_SYMBYTES);
  _gcry_md_hash_buffer(GCRY_MD_SHA3_512, kr, buf, 2 * KYBER_SYMBYTES);

  /* coins are in kr+KYBER_SYMBYTES */
  if ((ec = indcpa_enc(ct, buf, pk, kr + KYBER_SYMBYTES, param)))
    {
      goto end;
    }

#if 0
    /* overwrite coins in kr with H(c) */
    _gcry_md_hash_buffer(GCRY_MD_SHA3_256, kr+KYBER_SYMBYTES, ct, KYBER_CIPHERTEXTBYTES);
    /* hash concatenation of pre-k and H(c) to k */
    kdf(ss, kr, 2*KYBER_SYMBYTES);
#endif

  memcpy(ss, kr, KYBER_SYMBYTES);
end:
  return ec;
}
