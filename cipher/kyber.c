
#include <config.h>
#include <stdio.h>

#include "kyber.h"

#include "g10lib.h"
//#include "mpi.h"
#include "cipher.h"
#include "pubkey-internal.h"



static gcry_err_code_t
kyber_generate (const gcry_sexp_t genparms, gcry_sexp_t *r_skey)
{

  gpg_err_code_t ec = 0;

  unsigned int nbits;
  ec = _gcry_pk_util_get_nbits (genparms, &nbits);
  if (ec)
    return ec;

/*
  if (!ec)
    {
      ec = sexp_build (r_skey, NULL,
                       "(key-data"
                       " (public-key"
                       "  (rsa(n%m)(e%m)))"
                       " (private-key"
                       "  (rsa(n%m)(e%m)(d%m)(p%m)(q%m)(u%m)))"
                       " %S)",
                       sk.n, sk.e,
                       sk.n, sk.e, sk.d, sk.p, sk.q, sk.u,
                       swap_info);

    }
    */

  return ec;
}


static gcry_err_code_t
kyber_check_secret_key (gcry_sexp_t keyparms)
{
  gpg_err_code_t ec = 0;
  return ec;
}


static gcry_err_code_t
kyber_encap (gcry_sexp_t *r_ciph, gcry_sexp_t* shared_key, gcry_sexp_t keyparms)
{
  gpg_err_code_t ec = 0;
  return ec;
}


static gcry_err_code_t
kyber_decrypt (gcry_sexp_t *r_plain, gcry_sexp_t s_data, gcry_sexp_t keyparms)
{
  gpg_err_code_t ec = 0;
  return ec;
}


static unsigned int
kyber_get_nbits (gcry_sexp_t parms)
{
  gpg_err_code_t ec = 0;
  return ec;
}

static gpg_err_code_t
selftests_kyber (selftest_report_func_t report, int extended)
{
  return 0; /* Succeeded. */
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

static const char *kyber_names[] =
  {
    "kyber",
    "openpgp-kyber", // ? leave?
    NULL,
  };

gcry_pk_spec_t _gcry_pubkey_spec_kyber =
  {
    GCRY_PK_KYBER, { 0, 1 },
    (GCRY_PK_USAGE_ENCAP), // TODOMTG: can the key usage "encryption" remain or do we need new KU "encap"?
    "Kyber", kyber_names,
    "p", "s", "a", "", "p", // elements of pub-key, sec-key, ciphertext, signature, key-grip
    kyber_generate,
    kyber_check_secret_key,
    NULL, // encrypt
    kyber_encap,
    kyber_decrypt,
    NULL, // kyber_sign,
    NULL, //kyber_verify,
    kyber_get_nbits,
    run_selftests,
    compute_keygrip
  };
