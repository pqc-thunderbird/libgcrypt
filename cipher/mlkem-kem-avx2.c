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
                                     const gcry_mlkem_param_t *param,
                                     const uint8_t *coins)
{
  gpg_err_code_t ec = 0;
  ec = _gcry_mlkem_avx2_indcpa_keypair_derand (pk, sk, coins, param);
  if (ec)
    {
      goto leave;
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

leave:
  return ec;
}

/*************************************************
 * Name:        _gcry_mlkem_avx2_kem_enc_derand
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
gcry_err_code_t
_gcry_mlkem_avx2_kem_enc_derand (uint8_t *ct,
                                 uint8_t *ss,
                                 const uint8_t *pk,
                                 const gcry_mlkem_param_t *param,
                                 const uint8_t *coins)
{
  gcry_err_code_t ec = 0;
  byte *buf          = NULL;
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
  ec = _gcry_mlkem_avx2_indcpa_enc (
      ct, buf, pk, kr + GCRY_MLKEM_SYMBYTES, param);
  if (ec)
    goto leave;

  memcpy (ss, kr, GCRY_MLKEM_SYMBYTES);

leave:
  return ec;
  xfree (buf);
  xfree (kr);
}
