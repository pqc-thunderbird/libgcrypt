
#include <config.h>
#include <stdio.h>

//#include "gcrypt.h"
#include "kyber.h"
#include "kyber-common.h"

#include "g10lib.h"
//#include "mpi.h"
#include "cipher.h"
#include "pubkey-internal.h"
#include "kyber_verify.h"

//TODOMTG: key size for key gen: public key bit size

static gcry_err_code_t
kyber_generate (const gcry_sexp_t genparms, gcry_sexp_t * r_skey)
{
  gpg_err_code_t ec = 0;

  uint8_t pk[CRYPTO_PUBLICKEYBYTES];
  uint8_t sk[CRYPTO_SECRETKEYBYTES];
  unsigned int nbits;
  ec = _gcry_pk_util_get_nbits (genparms, &nbits);
  if (ec)
    return ec;
  crypto_kem_keypair (pk, sk);

  gcry_mpi_t sk_mpi = NULL, pk_mpi = NULL;
  sk_mpi = mpi_new (CRYPTO_SECRETKEYBYTES * 8);
  pk_mpi = mpi_new (CRYPTO_PUBLICKEYBYTES * 8);
  mpi_set_opaque (sk_mpi, sk, CRYPTO_SECRETKEYBYTES * 8);
  mpi_set_opaque (pk_mpi, pk, CRYPTO_PUBLICKEYBYTES * 8);

  if (!ec)
    {
      ec = sexp_build (r_skey, NULL,
                       "(key-data"
                       " (public-key"
                       "  (kyber(p%m)))"
                       " (private-key"
                       "  (kyber(s%m))))", pk_mpi, sk_mpi);
                       //"  (kyber(s%m)))" " %S)", pk_mpi, sk_mpi);

    }



  return ec;
}


static gcry_err_code_t
kyber_check_secret_key (gcry_sexp_t keyparms)
{
  gpg_err_code_t ec = 0;
  return ec;
}


static gcry_err_code_t
kyber_encap (gcry_sexp_t * r_ciph, gcry_sexp_t * shared_key,
             gcry_sexp_t keyparms)
{
  gpg_err_code_t ec = 0;
  return ec;
}


static gcry_err_code_t
kyber_decrypt (gcry_sexp_t * r_plain, gcry_sexp_t s_data,
               gcry_sexp_t keyparms)
{
  gpg_err_code_t ec = 0;
  unsigned char shared_secret[KYBER_SSBYTES];
  unsigned char shared_secret_str[KYBER_SSBYTES*2+1];
  unsigned char ciphertext[KYBER_CIPHERTEXTBYTES];
  unsigned char ciphertext_str[KYBER_CIPHERTEXTBYTES*2+1];
  unsigned char private_key[KYBER_SECRETKEYBYTES];
  unsigned char private_key_str[KYBER_SECRETKEYBYTES*2+1];

  gcry_mpi_t sk = NULL;
  gcry_mpi_t ct = NULL;
  size_t nwritten = 0;

  _gcry_sexp_dump(keyparms);
  /* Extract the key MPI from the SEXP.  */
  ec = sexp_extract_param (keyparms, NULL, "/s",
      sk,
      NULL);
  if (ec)
    goto leave;

  if(mpi_get_nbits(sk) != KYBER_SECRETKEYBYTES*8)
  {
    printf("error: mpi_get_nbits(sk) != KYBER_SECRETKEYBYTES*8");
  }


  /* Extract the key Ciphertext from the SEXP.  */
  ec = sexp_extract_param (s_data, NULL, "/c",
      ct,
      NULL);
  if (ec)
    goto leave;
  if(mpi_get_nbits(ct) != KYBER_CIPHERTEXTBYTES*8)
    printf("error: mpi_get_nbits(ct) != KYBER_CIPHERTEXTBYTES*8\n");

  // extract the byte arrays from the MPIs:


   _gcry_mpi_print(GCRYMPI_FMT_USG, ciphertext, sizeof(ciphertext), &nwritten, ct);
  if(nwritten != KYBER_CIPHERTEXTBYTES)
  {
    printf("nwritten != KYBER_CIPHERTEXTBYTES\n");
  }

   _gcry_mpi_print(GCRYMPI_FMT_HEX, ciphertext_str, sizeof(ciphertext_str), &nwritten, ct);
  if(nwritten != KYBER_CIPHERTEXTBYTES*2+1)
  {
    printf("nwritten != KYBER_CIPHERTEXTBYTES*2+1\n");
  }
  printf("kyber ciphertext to decrypt: %s", ciphertext_str);


   _gcry_mpi_print(GCRYMPI_FMT_USG, private_key, sizeof(private_key), &nwritten, sk);
  if(nwritten != KYBER_SECRETKEYBYTES)
  {
    printf("nwritten != KYBER_SECRETKEYBYTES\n");
  }

   _gcry_mpi_print(GCRYMPI_FMT_HEX, private_key_str, sizeof(private_key_str), &nwritten, sk);
  if(nwritten != KYBER_SECRETKEYBYTES*2+1)
  {
    printf("nwritten != KYBER_SECRETKEYBYTES*2+1\n");
  }
  printf("kyber private_key to decrypt: %s", private_key_str);


  // ========== perform the decryption ===============
  crypto_kem_dec(shared_secret, ciphertext, private_key);

leave:
  return ec;
}


static unsigned int
kyber_get_nbits (gcry_sexp_t parms)
{
    // TODO: SEE RSA FOR HOW TO PARSE A PARAMS SEXPR
    return 1184;
}

static gpg_err_code_t
selftests_kyber (selftest_report_func_t report, int extended)
{
  return 0;                     /* Succeeded. */
}

/* Run a full self-test for ALGO and return 0 on success.  */
static gpg_err_code_t
run_selftests (int algo, int extended, selftest_report_func_t report)
{
  gpg_err_code_t ec;

  switch (algo)
    {
    case GCRY_PK_KYBER:
      ec = selftests_kyber (report, extended);
      break;
    default:
      ec = GPG_ERR_PUBKEY_ALGO;
      break;

    }
  return ec;
}


static gpg_err_code_t
compute_keygrip (gcry_md_hd_t md, gcry_sexp_t keyparam)
{
  gpg_err_code_t ec = 0;
  return ec;
}

static const char *kyber_names[] = {
  "kyber",
  "openpgp-kyber",              // ? leave?
  NULL,
};

gcry_pk_spec_t _gcry_pubkey_spec_kyber = {
  GCRY_PK_KYBER, {0, 1},
  (GCRY_PK_USAGE_ENCAP),        // TODOMTG: can the key usage "encryption" remain or do we need new KU "encap"?
  "Kyber", kyber_names,
  "p", "s", "a", "", "p",       // elements of pub-key, sec-key, ciphertext, signature, key-grip
  kyber_generate,
  kyber_check_secret_key,
  NULL,                         // encrypt
  kyber_encap,
  kyber_decrypt,
  NULL,                         // sign,
  NULL,                         // verify,
  kyber_get_nbits,
  run_selftests,
  compute_keygrip
};
