
#include <config.h>
#include <stdio.h>

//#include "gcrypt.h"
#include "dilithium.h"
#include "dilithium-api.h"

#include "g10lib.h"
//#include "mpi.h"
#include "cipher.h"
#include "pubkey-internal.h"


static gcry_err_code_t
dilithium_generate (const gcry_sexp_t genparms, gcry_sexp_t * r_skey)
{
  gpg_err_code_t ec = 0;

  uint8_t pk[CRYPTO_PUBLICKEYBYTES];
  uint8_t sk[CRYPTO_SECRETKEYBYTES];
  unsigned int nbits;
  ec = _gcry_pk_util_get_nbits (genparms, &nbits);
  if (ec)
    return ec;
  crypto_sign_keypair (pk, sk);

  gcry_mpi_t sk_mpi = NULL, pk_mpi = NULL;
  sk_mpi = _gcry_mpi_set_opaque_copy (sk_mpi, sk, CRYPTO_SECRETKEYBYTES * 8);
  pk_mpi = _gcry_mpi_set_opaque_copy (pk_mpi, pk, CRYPTO_PUBLICKEYBYTES * 8);

  if (!ec)
    {
      ec = sexp_build (r_skey, NULL,
                       "(key-data"
                       " (public-key"
                       "  (dilithium(p%m)))"
                       " (private-key"
                       "  (dilithium(s%m))))", pk_mpi, sk_mpi);

    }

    _gcry_mpi_release(sk_mpi);
    _gcry_mpi_release(pk_mpi);

  return ec;
}


static gcry_err_code_t
dilithium_check_secret_key (gcry_sexp_t keyparms)
{
  gpg_err_code_t ec = 0;
  return ec;
}


static gcry_err_code_t
dilithium_sign (gcry_sexp_t *r_sig, gcry_sexp_t s_data, gcry_sexp_t keyparms)
{
    return GPG_ERR_NO_ERROR; // TODO
}

static gcry_err_code_t
dilithium_verify (gcry_sexp_t s_sig, gcry_sexp_t s_data, gcry_sexp_t s_keyparms)
{
    return GPG_ERR_NO_ERROR; // TODO
}

static unsigned int
dilithium_get_nbits (gcry_sexp_t parms)
{
    // TODO: SEE RSA FOR HOW TO PARSE A PARAMS SEXPR
    return 5; // TODO: for now nbits == Dilithium Level
}

static gpg_err_code_t
selftests_dilithium (selftest_report_func_t report, int extended)
{
  return GPG_ERR_NO_ERROR; // TODO
}

/* Run a full self-test for ALGO and return 0 on success.  */
static gpg_err_code_t
run_selftests (int algo, int extended, selftest_report_func_t report)
{
  gpg_err_code_t ec;

  switch (algo)
    {
    case GCRY_PK_DILITHIUM:
      ec = selftests_dilithium (report, extended);
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

static const char *dilithium_names[] = {
  "dilithium",
  "openpgp-dilithium",              // ? leave?
  NULL,
};

gcry_pk_spec_t _gcry_pubkey_spec_dilithium = {
  GCRY_PK_DILITHIUM, {0, 1},
  (GCRY_PK_USAGE_SIGN),
  "Dilithium", dilithium_names,
  "p", "s", "a", "", "p",       // elements of pub-key, sec-key, ciphertext, signature, key-grip
  dilithium_generate,
  dilithium_check_secret_key,
  NULL,
  NULL,
  dilithium_sign,
  dilithium_verify,
  dilithium_get_nbits,
  run_selftests,
  compute_keygrip
};
