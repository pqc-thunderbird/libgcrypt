#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "mlkem-kem-avx2.h"
#include "mlkem-indcpa-avx2.h"
#include "mlkem-verify-avx2.h"
#include "g10lib.h"


gcry_err_code_t
_gcry_mlkem_avx2_kem_keypair_derand (uint8_t *pk,
                                     uint8_t *sk,
                                     const uint8_t *coins,
                                     const gcry_mlkem_param_t *param)
{
  gpg_err_code_t ec = 0;
  ec = _gcry_mlkem_avx2_indcpa_keypair_derand (pk, sk, coins, param);
  if (ec)
    {
      return ec;
    }
  memcpy (&sk[param->indcpa_secret_key_bytes], pk, param->public_key_bytes);
  _gcry_md_hash_buffer (GCRY_MD_SHA3_256,
                        sk + param->secret_key_bytes - 2 * GCRY_MLKEM_SYMBYTES,
                        pk,
                        param->public_key_bytes);
  /* Value z for pseudo-random output on reject */
  memcpy (sk + param->secret_key_bytes - GCRY_MLKEM_SYMBYTES,
          coins + GCRY_MLKEM_SYMBYTES,
          GCRY_MLKEM_SYMBYTES);
  return ec;
}

gcry_err_code_t
_gcry_mlkem_avx2_kem_keypair (uint8_t *pk,
                              uint8_t *sk,
                              const gcry_mlkem_param_t *param)
{
  // TODO: remove this function and use #ifdef USE_AVX2 in _gcry_mlkem_kem_keypair
  gcry_err_code_t ec = 0;
  byte *coins        = NULL;
  coins              = xtrymalloc_secure (GCRY_MLKEM_COINS_SIZE);
  if (!coins)
    {
      ec = gpg_err_code_from_syserror ();
      goto leave;
    }
  _gcry_randomize (coins, GCRY_MLKEM_COINS_SIZE, GCRY_VERY_STRONG_RANDOM);
  ec = _gcry_mlkem_avx2_kem_keypair_derand (
      pk,
      sk,
      coins,
      param); // TODO align order of coins and param with existing call

leave:
  xfree (coins);
  return ec;
}

/*************************************************
 * Name:        crypto_kem_enc_derand
 *
 * Description: Generates cipher text and shared
 *              secret for given public key
 *
 * Arguments:   - uint8_t *ct: pointer to output cipher text
 *              - uint8_t *ss: pointer to output shared secret
 *              - const uint8_t *pk: pointer to input public key
 *              - const uint8_t *coins: pointer to input randomness
 **
 * Returns 0 (success)
 **************************************************/
static gcry_err_code_t
crypto_kem_enc_derand (uint8_t *ct,
                       uint8_t *ss,
                       const uint8_t *pk,
                       const uint8_t *coins,
                       const gcry_mlkem_param_t *param)
{
  gcry_err_code_t ec = 0;
  byte *buf = NULL;
  /* Will contain key, coins */
  byte *kr = NULL;

  buf = xtrymalloc_secure (2 * GCRY_MLKEM_SYMBYTES);
  if (!buf)
    {
      ec = gpg_error_from_syserror ();
      goto leave;
    }
  kr = xtrymalloc_secure (2 * GCRY_MLKEM_SYMBYTES);
  if (!kr)
    {
      ec = gpg_error_from_syserror ();
      goto leave;
    }

  memcpy (buf, coins, GCRY_MLKEM_SYMBYTES);

  /* Multitarget countermeasure for coins + contributory KEM */
  _gcry_md_hash_buffer (GCRY_MD_SHA3_256,
                        buf + GCRY_MLKEM_SYMBYTES,
                        pk,
                        param->public_key_bytes);
  _gcry_md_hash_buffer (GCRY_MD_SHA3_512, kr, buf, 2 * GCRY_MLKEM_SYMBYTES);

  /* coins are in kr+GCRY_MLKEM_SYMBYTES */
  ec = _gcry_mlkem_avx2_indcpa_enc (ct, buf, pk, kr + GCRY_MLKEM_SYMBYTES, param);
  if (ec)
    goto leave;

  memcpy (ss, kr, GCRY_MLKEM_SYMBYTES);

leave:
  return ec;
  xfree(buf);
  xfree(kr);
}

/*************************************************
 * Name:        _gcry_mlkem_avx2_kem_enc
 *
 * Description: Generates cipher text and shared
 *              secret for given public key
 *
 * Arguments:   - uint8_t *ct: pointer to output cipher text
 *              - uint8_t *ss: pointer to output shared secret
 *              - const uint8_t *pk: pointer to input public key
 *
 * Returns 0 (success)
 **************************************************/
gcry_err_code_t
_gcry_mlkem_avx2_kem_enc (uint8_t *ct,
                          uint8_t *ss,
                          const uint8_t *pk,
                          const gcry_mlkem_param_t *param)
{
  gcry_err_code_t ec = 0;
  byte *coins        = NULL;
  coins              = xtrymalloc_secure (GCRY_MLKEM_SYMBYTES);
  if (!coins)
    {
      ec = gpg_error_from_syserror ();
      goto leave;
    }

  _gcry_randomize (coins, GCRY_MLKEM_SYMBYTES, GCRY_VERY_STRONG_RANDOM);
  crypto_kem_enc_derand (ct, ss, pk, coins, param);

leave:
  xfree (coins);
  return ec;
}

/*************************************************
 * Name:        _gcry_mlkem_avx2_kem_dec
 *
 * Description: Generates shared secret for given
 *              cipher text and private key
 *
 * Arguments:   - uint8_t *ss: pointer to output shared secret
 *              - const uint8_t *ct: pointer to input cipher text
 *              - const uint8_t *sk: pointer to input private key
 *
 * Returns 0.
 *
 * On failure, ss will contain a pseudo-random value.
 **************************************************/
gcry_err_code_t
_gcry_mlkem_avx2_kem_dec (uint8_t *ss,
                          const uint8_t *ct,
                          const uint8_t *sk,
                          const gcry_mlkem_param_t *param)
{
  gcry_err_code_t ec = 0;
  int fail;
  byte *buf = NULL;
  /* Will contain key, coins */
  byte *kr          = NULL;
  byte *cmp         = NULL;
  const uint8_t *pk = sk + param->polyvec_bytes;

  buf = xtrymalloc_secure (2 * GCRY_MLKEM_SYMBYTES);
  if (!buf)
    {
      ec = gpg_error_from_syserror ();
      goto leave;
    }
  kr = xtrymalloc_secure (2 * GCRY_MLKEM_SYMBYTES);
  if (!kr)
    {
      ec = gpg_error_from_syserror ();
      goto leave;
    }
  cmp = xtrymalloc_secure (param->ciphertext_bytes + GCRY_MLKEM_SYMBYTES);
  if (!cmp)
    {
      ec = gpg_error_from_syserror ();
      goto leave;
    }

  _gcry_mlkem_avx2_indcpa_dec (buf, ct, sk, param);

  /* Multitarget countermeasure for coins + contributory KEM */
  memcpy (buf + GCRY_MLKEM_SYMBYTES,
          sk + param->secret_key_bytes - 2 * GCRY_MLKEM_SYMBYTES,
          GCRY_MLKEM_SYMBYTES);
  _gcry_md_hash_buffer (GCRY_MD_SHA3_512, kr, buf, 2 * GCRY_MLKEM_SYMBYTES);

  /* coins are in kr+GCRY_MLKEM_SYMBYTES */
  _gcry_mlkem_avx2_indcpa_enc (cmp, buf, pk, kr + GCRY_MLKEM_SYMBYTES, param);

  fail = _gcry_mlkem_avx2_verify (ct, cmp, param->ciphertext_bytes);

  /* Compute rejection key */
  _gcry_mlkem_mlkem_shake256_rkprf (ss,
                                    sk + param->secret_key_bytes
                                        - GCRY_MLKEM_SYMBYTES,
                                    ct,
                                    param->ciphertext_bytes);

  /* Copy true key to return buffer if fail is false */
  _gcry_mlkem_cmov (ss, kr, GCRY_MLKEM_SYMBYTES, !fail);

leave:
  xfree (buf);
  xfree (kr);
  xfree (cmp);
  return ec;
}