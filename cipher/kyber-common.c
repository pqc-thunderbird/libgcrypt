
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


int crypto_kem_keypair_derand(uint8_t *pk,
                       uint8_t *sk,
                       gcry_kyber_param_t* param,
                       uint8_t* coins
                       )
{
  indcpa_keypair(pk, sk, param, coins);
  /*for(i=0;i<KYBER_INDCPA_PUBLICKEYBYTES;i++)
    sk[i+KYBER_INDCPA_SECRETKEYBYTES] = pk[i];*/
  memcpy(&sk[param->indcpa_secret_key_bytes], pk, param->public_key_bytes);
  hash_h(sk+KYBER_SECRETKEYBYTES-2*KYBER_SYMBYTES, pk, KYBER_PUBLICKEYBYTES);
  /* Value z for pseudo-random output on reject */
  //randombytes(sk+KYBER_SECRETKEYBYTES-KYBER_SYMBYTES, KYBER_SYMBYTES);
  memcpy(sk+KYBER_SECRETKEYBYTES-KYBER_SYMBYTES, coins+KYBER_SYMBYTES, KYBER_SYMBYTES);
  return 0;

#if 0
  memcpy(sk+KYBER_INDCPA_SECRETKEYBYTES, pk, KYBER_PUBLICKEYBYTES);
  hash_h(sk+KYBER_SECRETKEYBYTES-2*KYBER_SYMBYTES, pk, KYBER_PUBLICKEYBYTES);
  /* Value z for pseudo-random output on reject */
  memcpy(sk+KYBER_SECRETKEYBYTES-KYBER_SYMBYTES, coins+KYBER_SYMBYTES, KYBER_SYMBYTES);
#endif
}

static void kyber_shake256_rkprf(uint8_t out[KYBER_SSBYTES], const uint8_t key[KYBER_SYMBYTES], const uint8_t input[KYBER_CIPHERTEXTBYTES])
{
  keccak_state s;

  shake256_init(&s);
  shake256_absorb(&s, key, KYBER_SYMBYTES);
  shake256_absorb(&s, input, KYBER_CIPHERTEXTBYTES);
  shake256_finalize(&s);
  shake256_squeeze(out, KYBER_SSBYTES, &s);
}


int crypto_kem_keypair(uint8_t *pk,
                       uint8_t *sk,
                       gcry_kyber_param_t* param)
{
  uint8_t coins[2*KYBER_SYMBYTES];
  randombytes(coins, 2*KYBER_SYMBYTES);
  crypto_kem_keypair_derand(pk, sk, param, coins);
  return 0;
}

int crypto_kem_dec(uint8_t *ss,
                   const uint8_t *ct,
                   const uint8_t *sk,
                   gcry_kyber_param_t* param
                   )
{

  size_t i;
  int fail;
  uint8_t buf[2*KYBER_SYMBYTES];
  /* Will contain key, coins */
  uint8_t kr[2*KYBER_SYMBYTES];
  uint8_t cmp[KYBER_CIPHERTEXTBYTES];
  const uint8_t *pk = sk+KYBER_INDCPA_SECRETKEYBYTES;

  indcpa_dec(buf, ct, sk, param);

  /* Multitarget countermeasure for coins + contributory KEM */
  for(i=0;i<KYBER_SYMBYTES;i++)
    buf[KYBER_SYMBYTES+i] = sk[KYBER_SECRETKEYBYTES-2*KYBER_SYMBYTES+i];
  hash_g(kr, buf, 2*KYBER_SYMBYTES);

  /* coins are in kr+KYBER_SYMBYTES */
  indcpa_enc(cmp, buf, pk, kr+KYBER_SYMBYTES, param);

  fail = verify(ct, cmp, KYBER_CIPHERTEXTBYTES);

#if 0
  /* overwrite coins in kr with H(c) */
  hash_h(kr+KYBER_SYMBYTES, ct, KYBER_CIPHERTEXTBYTES);

  /* Overwrite pre-k with z on re-encryption failure */
  cmov(kr, sk+KYBER_SECRETKEYBYTES-KYBER_SYMBYTES, KYBER_SYMBYTES, fail);

  /* hash concatenation of pre-k and H(c) to k */
  kdf(ss, kr, 2*KYBER_SYMBYTES);
#endif

  /* Compute rejection key */
  kyber_shake256_rkprf(ss,sk+KYBER_SECRETKEYBYTES-KYBER_SYMBYTES,ct);

  /* Copy true key to return buffer if fail is false */
  cmov(ss,kr,KYBER_SYMBYTES,!fail);
  return 0;
}

int kyber_kem_enc(uint8_t *ct,
                   uint8_t *ss,
                   const uint8_t *pk,
                   gcry_kyber_param_t* param
                   )
{
  uint8_t coins[KYBER_SYMBYTES];
  randombytes(coins, KYBER_SYMBYTES);
  kyber_kem_enc_derand(ct, ss, pk, param, coins);
  return 0;
}

int kyber_kem_enc_derand(uint8_t *ct,
                   uint8_t *ss,
                   const uint8_t *pk,
                   gcry_kyber_param_t* param,
                   uint8_t * coins
                   )
{
    uint8_t buf[2*KYBER_SYMBYTES];
    /* Will contain key, coins */
    uint8_t kr[2*KYBER_SYMBYTES];

    //randombytes(buf, KYBER_SYMBYTES);
    /* Don't release system RNG output */
    hash_h(buf, coins, KYBER_SYMBYTES);

    /* Multitarget countermeasure for coins + contributory KEM */
    //hash_h(buf+KYBER_SYMBYTES, pk, KYBER_PUBLICKEYBYTES);
    _gcry_md_hash_buffer(GCRY_MD_SHA3_256, buf+KYBER_SYMBYTES, pk, KYBER_PUBLICKEYBYTES);
    //hash_g(kr, buf, 2*KYBER_SYMBYTES);
    _gcry_md_hash_buffer(GCRY_MD_SHA3_512, kr, buf, 2*KYBER_SYMBYTES);

    /* coins are in kr+KYBER_SYMBYTES */
    indcpa_enc(ct, buf, pk, kr+KYBER_SYMBYTES, param);

#if 0
    /* overwrite coins in kr with H(c) */
    hash_h(kr+KYBER_SYMBYTES, ct, KYBER_CIPHERTEXTBYTES);
    /* hash concatenation of pre-k and H(c) to k */
    kdf(ss, kr, 2*KYBER_SYMBYTES);
#endif

    memcpy(ss,kr,KYBER_SYMBYTES);
    return 0;
}
