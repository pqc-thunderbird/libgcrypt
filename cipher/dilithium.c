
#include <config.h>
#include <stdio.h>

//#include "gcrypt.h"
#include "dilithium.h"
#include "dilithium-api.h"
#include "dilithium-params.h"

#include "g10lib.h"
#include "mpi.h"
#include "cipher.h"
#include "pubkey-internal.h"


static unsigned int
dilithium_get_nbits (gcry_sexp_t parms)
{
  // TODO: sufficient?
  gcry_sexp_t l1;

  l1 = sexp_find_token (parms, "s", 1);
  if (l1) {
    // private
    return CRYPTO_SECRETKEYBYTES*8;

  }
  else {
    // public
    return CRYPTO_PUBLICKEYBYTES*8;
  }
}

static const char *dilithium_names[] = {
  "dilithium",
  "openpgp-dilithium",              // ? leave?
  NULL,
};


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
  DILITHIUM_NAMESPACE(keypair)(pk, sk);

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
  gpg_err_code_t ec = 0;
  unsigned char sig_buf[CRYPTO_BYTES];
  unsigned char sk_buf[CRYPTO_SECRETKEYBYTES];
  unsigned char *data_buf = NULL;
  size_t data_buf_len = 0;

  struct pk_encoding_ctx ctx;

  gcry_mpi_t sk = NULL;
  gcry_mpi_t sig = NULL;
  gcry_mpi_t data = NULL;
  size_t nwritten = 0;

  unsigned int nbits = dilithium_get_nbits (keyparms);
  _gcry_pk_util_init_encoding_ctx (&ctx, PUBKEY_OP_SIGN, nbits);

  /* Extract the data.  */
  ec = _gcry_pk_util_data_to_mpi (s_data, &data, &ctx);
  if (ec)
    goto leave;
  if (DBG_CIPHER)
    log_printmpi ("dilithium_sign   data", data);

  /* Extract the key MPI from the SEXP.  */
  ec = sexp_extract_param (keyparms, NULL, "/s",
      &sk,
      NULL);
  if (ec)
  {
    printf("error from sexp_extract_param (keyparms)\n");
    goto leave;
  }


  if(mpi_get_nbits(sk) != nbits)
  {
    printf("error: mpi_get_nbits(sk) != nbits");
  }


  /* extract sk from mpi */
   _gcry_mpi_print(GCRYMPI_FMT_USG, sk_buf, sizeof(sk_buf), &nwritten, sk);
  if(nwritten != CRYPTO_SECRETKEYBYTES)
  {
    printf("nwritten != CRYPTO_SECRETKEYBYTES\n");
  }

  /* extract msg from mpi */
  _gcry_mpi_print(GCRYMPI_FMT_USG, NULL, 0, &nwritten, data);
  data_buf_len = nwritten;
  data_buf = xmalloc (data_buf_len);
  _gcry_mpi_print(GCRYMPI_FMT_USG, data_buf, data_buf_len, &nwritten, data);
  if(nwritten != data_buf_len)
  {
    printf("nwritten != data_buf_len\n");
  }

  size_t sig_buf_len = 0;
  if(0 != DILITHIUM_NAMESPACE(signature)(sig_buf, &sig_buf_len, data_buf, data_buf_len, sk_buf))
  {
    printf("sign operation failed\n");
    ec = GPG_ERR_GENERAL;
    goto leave;
  }
  if(sig_buf_len != sizeof(sig_buf))
  {
    printf("unexpected sig buf length\n");
    ec = GPG_ERR_GENERAL;
    goto leave;
  }

  ec = sexp_build (r_sig, NULL, "(sig-val(dilithium(a%b)))", sig_buf_len, sig_buf);
  if(ec)
    printf("sexp build failed\n");

leave:
  _gcry_pk_util_free_encoding_ctx (&ctx);
  if (DBG_CIPHER)
    log_debug ("dilithium_sign    => %s\n", gpg_strerror (ec));
  return ec;
}

static gcry_err_code_t
dilithium_verify (gcry_sexp_t s_sig, gcry_sexp_t s_data, gcry_sexp_t s_keyparms)
{
  gpg_err_code_t ec = 0;
  unsigned char sig_buf[CRYPTO_BYTES];
  unsigned char pk_buf[CRYPTO_PUBLICKEYBYTES];
  unsigned char *data_buf = NULL;
  size_t data_buf_len = 0;

  struct pk_encoding_ctx ctx;

  gcry_mpi_t pk = NULL;
  gcry_mpi_t sig = NULL;
  gcry_mpi_t data = NULL;
  size_t nwritten = 0;

  unsigned int nbits = dilithium_get_nbits (s_keyparms);

  _gcry_pk_util_init_encoding_ctx (&ctx, PUBKEY_OP_VERIFY, nbits);

  /* Extract the data.  */
  ec = _gcry_pk_util_data_to_mpi (s_data, &data, &ctx);
  if (ec)
    goto leave;
  if (DBG_CIPHER)
    log_printmpi ("dilithium_sign   data", data);

  /* Extract the key MPI from the SEXP.  */
  ec = sexp_extract_param (s_keyparms, NULL, "/p",
      &pk,
      NULL);
  if (ec)
  {
    printf("error from sexp_extract_param (s_keyparms) /p\n");
    goto leave;
  }

  /* Extract the sig MPI from the SEXP.  */

/*  ec = sexp_extract_param (s_keyparms, NULL, "/a",
      &pk,
      NULL);
  if (ec)
  {
    printf("error from sexp_extract_param (s_keyparms) /a \n");
    goto leave;
  }
*/
  /* Extract the signature value.  */
  gcry_sexp_t l1 = NULL;
  ec = _gcry_pk_util_preparse_sigval (s_sig, dilithium_names, &l1, NULL);
  if (ec)
    goto leave;
  ec = sexp_extract_param (l1, NULL, "/a", &sig, NULL);
  if (ec)
    goto leave;
  if (DBG_CIPHER)
    log_printmpi ("dilithium_verify  sig", sig);



  if(mpi_get_nbits(pk) != nbits)
  {
    printf("error: mpi_get_nbits(sk) != nbits");
  }


  /* extract pk from mpi */
  _gcry_mpi_print(GCRYMPI_FMT_USG, pk_buf, sizeof(pk_buf), &nwritten, pk);
  if(nwritten != CRYPTO_PUBLICKEYBYTES)
  {
    printf("nwritten != CRYPTO_PUBLICKEYBYTES\n");
  }

  /* extract sig from mpi */
  _gcry_mpi_print(GCRYMPI_FMT_USG, sig_buf, sizeof(sig_buf), &nwritten, sig);
  if(nwritten != CRYPTO_BYTES)
  {
    printf("nwritten != CRYPTO_BYTES\n");
  }

  /* extract msg from mpi */
  _gcry_mpi_print(GCRYMPI_FMT_USG, NULL, 0, &nwritten, data);
  data_buf_len = nwritten;
  data_buf = xmalloc (data_buf_len);
  _gcry_mpi_print(GCRYMPI_FMT_USG, data_buf, data_buf_len, &nwritten, data);
  if(nwritten != data_buf_len)
  {
    printf("nwritten != data_buf_len\n");
  }

  if(0 != DILITHIUM_NAMESPACE(verify)(sig_buf, sizeof(sig_buf), data_buf, data_buf_len, pk_buf))
  {
    printf("verify operation failed\n");
    ec = GPG_ERR_GENERAL;
    goto leave;
  }

leave:
  _gcry_pk_util_free_encoding_ctx (&ctx);
  if (DBG_CIPHER)
    log_debug ("dilithium_verify    => %s\n", gpg_strerror (ec));
  return ec;
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

gcry_pk_spec_t _gcry_pubkey_spec_dilithium = {
  GCRY_PK_DILITHIUM, {0, 1},
  (GCRY_PK_USAGE_SIGN),
  "Dilithium", dilithium_names,
  "p", "s", "", "a", "p",       // elements of pub-key, sec-key, ciphertext, signature, key-grip
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
