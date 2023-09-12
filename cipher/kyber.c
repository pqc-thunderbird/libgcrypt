
#include <config.h>
#include <stdio.h>


#include "kyber-common.h"

#include "g10lib.h"

#include "cipher.h"
#include "pubkey-internal.h"
#include "kyber_aux.h"


static gcry_err_code_t _gcry_kyber_get_param_from_bit_size(
    size_t nbits, gcry_kyber_param_t *param)
{
  switch (nbits)
    {
    case 128:
      param->id                       = GCRY_KYBER_512;
      param->k                        = 2;
      param->eta1                     = 3;
      param->poly_compressed_bytes    = 128;
      param->polyvec_compressed_bytes = param->k * 320;
      break;
    case 192:
      param->id                       = GCRY_KYBER_768;
      param->k                        = 3;
      param->eta1                     = 2;
      param->poly_compressed_bytes    = 128;
      param->polyvec_compressed_bytes = param->k * 320;
      break;
    case 256:
      param->id                       = GCRY_KYBER_1024;
      param->k                        = 4;
      param->eta1                     = 2;
      param->poly_compressed_bytes    = 160;
      param->polyvec_compressed_bytes = param->k * 352;
      break;
    default:
      return GPG_ERR_INV_ARG;
    }

  param->polyvec_bytes           = param->k * GCRY_KYBER_POLYBYTES;
  param->public_key_bytes        = param->polyvec_bytes + GCRY_KYBER_SYMBYTES;
  param->indcpa_secret_key_bytes = param->polyvec_bytes;
  param->ciphertext_bytes
      = param->poly_compressed_bytes + param->polyvec_compressed_bytes;
  param->secret_key_bytes = param->indcpa_secret_key_bytes
                            + param->public_key_bytes
                            + 2 * GCRY_KYBER_SYMBYTES;

  return 0;
}

static gcry_err_code_t kyber_params_from_key_param(const gcry_sexp_t keyparms,
                                                   gcry_kyber_param_t *param,
                                                   unsigned int *nbits_p)
{
  gpg_err_code_t ec = 0;

  unsigned int nbits;
  ec = _gcry_pk_util_get_nbits(keyparms, &nbits);
  if (ec)
    {
      return ec;
    }
  ec = _gcry_kyber_get_param_from_bit_size(nbits, param);
  if (ec)
    {
      return ec;
    }
  if (nbits_p != NULL)
    {
      if (param->id == GCRY_KYBER_512)
        {
          *nbits_p = 128;
        }
      else if (param->id == GCRY_KYBER_768)
        {
          *nbits_p = 192;
        }
      else if (param->id == GCRY_KYBER_1024)
        {
          *nbits_p = 256;
        }
      else
        {
          ec = GPG_ERR_INV_ARG;
        }
    }

  return ec;
}

static gcry_err_code_t extract_opaque_mpi_from_sexp(
    const gcry_sexp_t keyparms,
    const char *label,
    unsigned char **data_p,
    size_t exp_len,
    try_alloc_func_t alloc_func)
{
  gcry_mpi_t sk     = NULL;
  gpg_err_code_t ec = 0;
  size_t nwritten   = 0;

  *data_p = 0;


  ec = sexp_extract_param(keyparms, NULL, label, &sk, NULL);
  if (ec)
    {
      printf("error from sexp_extract_param (keyparms)\n");
      goto leave;
    }
  if (mpi_get_nbits(sk) != exp_len * 8)
    {
      ec = GPG_ERR_INV_ARG;
      goto leave;
    }

  if (!(*data_p = alloc_func(exp_len)))
    {
      ec = gpg_err_code_from_syserror();
      goto leave;
    }
  _gcry_mpi_print(GCRYMPI_FMT_USG, *data_p, exp_len, &nwritten, sk);

  if (exp_len != nwritten)
    {
      ec = GPG_ERR_INV_ARG;
      goto leave;
    }

leave:
  if (sk != NULL)
    {
      _gcry_mpi_release(sk);
    }
  if (ec)
    {
      xfree(*data_p);
      *data_p = 0;
    }
  return ec;
}


static gcry_err_code_t private_key_from_sexp(const gcry_sexp_t keyparms,
                                             const gcry_kyber_param_t param,
                                             unsigned char **sk_p)
{
  return extract_opaque_mpi_from_sexp(
      keyparms, "/s", sk_p, param.secret_key_bytes, _gcry_malloc_secure);
}


static gcry_err_code_t ciphertext_from_sexp(const gcry_sexp_t keyparms,
                                            const gcry_kyber_param_t param,
                                            unsigned char **ct_p)
{
  return extract_opaque_mpi_from_sexp(
      keyparms, "/c", ct_p, param.ciphertext_bytes, _gcry_malloc);
}


static gcry_err_code_t public_key_from_sexp(const gcry_sexp_t keyparms,
                                            const gcry_kyber_param_t param,
                                            unsigned char **pk_p)
{
  return extract_opaque_mpi_from_sexp(
      keyparms, "/p", pk_p, param.public_key_bytes, _gcry_malloc);
}


static gcry_err_code_t kyber_check_secret_key(gcry_sexp_t keyparms)
{

  gpg_err_code_t ec = 0;
  unsigned char shared_secret_1[GCRY_KYBER_SSBYTES],
      shared_secret_2[GCRY_KYBER_SSBYTES];
  unsigned char *private_key = NULL, *ciphertext = NULL;
  unsigned char *public_key = NULL;

  gcry_kyber_param_t param;
  ec = kyber_params_from_key_param(keyparms, &param, NULL);
  if (ec)
    {
      goto leave;
    }

  ciphertext = xtrymalloc(param.ciphertext_bytes);
  if (!ciphertext)
    {
      ec = GPG_ERR_SELFTEST_FAILED;
      goto leave;
    }

  /* Extract the key MPI from the SEXP.  */
  ec = private_key_from_sexp(keyparms, param, &private_key);
  if (ec)
    {
      goto leave;
    }
  public_key
      = private_key
        + param.indcpa_secret_key_bytes; // offset of public key in private key
  ec = _gcry_kyber_kem_enc(ciphertext, shared_secret_1, public_key, &param);
  if (ec)
    {
      goto leave;
    }
  ec = _gcry_kyber_kem_dec(shared_secret_2, ciphertext, private_key, &param);
  if (ec)
    {
      goto leave;
    }

  if (memcmp(shared_secret_1, shared_secret_2, sizeof(shared_secret_1)))
    {
      ec = GPG_ERR_BAD_SECKEY;
      goto leave;
    }

leave:

  xfree(ciphertext);
  xfree(private_key);
  return ec;
}


static gcry_err_code_t kyber_generate(const gcry_sexp_t genparms,
                                      gcry_sexp_t *r_skey)
{
  gpg_err_code_t ec = 0;

  uint8_t *pk = 0, *sk = 0;
  unsigned int nbits;
  gcry_kyber_param_t param;
  gcry_mpi_t sk_mpi = NULL, pk_mpi = NULL;

  ec = kyber_params_from_key_param(genparms, &param, &nbits);
  if (ec)
    {
      goto leave;
    }
  ec = _gcry_pk_util_get_nbits(genparms, &nbits);
  if (!(sk = xtrymalloc_secure(param.secret_key_bytes))
      || !(pk = xtrymalloc(param.public_key_bytes)))
    {
      ec = gpg_err_code_from_syserror();
      goto leave;
    }
  _gcry_kyber_kem_keypair(pk, sk, &param);

  sk_mpi = _gcry_mpi_set_opaque_copy(sk_mpi, sk, param.secret_key_bytes * 8);
  pk_mpi = _gcry_mpi_set_opaque_copy(pk_mpi, pk, param.public_key_bytes * 8);

  if (!ec)
    {
      ec = sexp_build(r_skey,
                      NULL,
                      "(key-data"
                      " (public-key"
                      "  (kyber(p%m) (nbits%u)))"
                      " (private-key"
                      "  (kyber(s%m) (nbits%u))))",
                      pk_mpi,
                      nbits,
                      sk_mpi,
                      nbits,
                      NULL);
    }
  /* call the key check function for now so that we know that it is working: */
  ec = kyber_check_secret_key(*r_skey);
  if (ec)
    {
      goto leave;
    }
leave:
  _gcry_mpi_release(sk_mpi);
  _gcry_mpi_release(pk_mpi);
  xfree(sk);
  xfree(pk);
  return ec;
}


static gcry_err_code_t kyber_encap(gcry_sexp_t *r_ciph,
                                   gcry_sexp_t *r_shared_key,
                                   gcry_sexp_t keyparms)
{

  gpg_err_code_t ec         = 0;
  unsigned char *ciphertext = NULL, *public_key = NULL, *shared_secret = NULL;

  gcry_kyber_param_t param;

  shared_secret = xtrymalloc_secure(GCRY_KYBER_SSBYTES);

  if (!shared_secret)
    {
      ec = gpg_err_code_from_syserror();
      goto leave;
    }
  ec = kyber_params_from_key_param(keyparms, &param, NULL);
  if (ec)
    {
      goto leave;
    }

  ciphertext = xtrymalloc(param.ciphertext_bytes);

  /* Extract the public key MPI from the SEXP.  */
  ec = public_key_from_sexp(keyparms, param, &public_key);
  if (ec)
    {
      goto leave;
    }
  ec = _gcry_kyber_kem_enc(ciphertext, shared_secret, public_key, &param);
  if (ec)
    {
      goto leave;
    }


  ec = sexp_build(r_shared_key,
                  NULL,
                  "(value %b)",
                  (int)GCRY_KYBER_SSBYTES,
                  shared_secret);
  if (ec)
    {
      goto leave;
    }

  ec = sexp_build(r_ciph,
                  NULL,
                  "(ciphertext (kyber(c %b)))",
                  (int)param.ciphertext_bytes,
                  ciphertext);

leave:
  xfree(shared_secret);
  xfree(public_key);
  xfree(ciphertext);
  return ec;
}


static gcry_err_code_t kyber_decrypt(gcry_sexp_t *r_plain,
                                     gcry_sexp_t s_data,
                                     gcry_sexp_t keyparms)
{
  gpg_err_code_t ec          = 0;
  unsigned char *private_key = NULL, *ciphertext = NULL, *shared_secret = NULL;

  shared_secret = xtrymalloc_secure(GCRY_KYBER_SSBYTES);

  if (!shared_secret)
    {
      ec = gpg_err_code_from_syserror();
      goto leave;
    }

  gcry_kyber_param_t param;
  ec = kyber_params_from_key_param(keyparms, &param, NULL);
  if (ec)
    {
      goto leave;
    }

  /* Extract the key MPI from the SEXP.  */
  ec = private_key_from_sexp(keyparms, param, &private_key);
  if (ec)
    {
      goto leave;
    }

  /* Extract the key Ciphertext from the SEXP.  */
  ec = ciphertext_from_sexp(s_data, param, &ciphertext);
  if (ec)
    {
      goto leave;
    }

  // ========== perform the decryption ===============
  ec = _gcry_kyber_kem_dec(shared_secret, ciphertext, private_key, &param);
  if (ec)
    {
      goto leave;
    }

  ec = sexp_build(
      r_plain, NULL, "(value %b)", (int)GCRY_KYBER_SSBYTES, shared_secret);
leave:
  xfree(shared_secret);
  xfree(ciphertext);
  xfree(private_key);
  return ec;
}


static unsigned int kyber_get_nbits(gcry_sexp_t parms)
{
  gpg_err_code_t ec;
  unsigned int nbits;
  ec = _gcry_pk_util_get_nbits(parms, &nbits);
  if (ec)
    {
      return 0;
    }
  return nbits;
}


static const char *kyber_names[] = {
    "kyber",
    "openpgp-kyber", // ? leave?
    NULL,
};

gcry_pk_spec_t _gcry_pubkey_spec_kyber = {
    GCRY_PK_KYBER,
    {0, 1},
    (GCRY_PK_USAGE_ENCAP),
    "Kyber",
    kyber_names,
    "p",
    "s",
    "a",
    "",
    "", // elements of pub-key, sec-key, ciphertext, signature, key-grip
    kyber_generate,
    kyber_check_secret_key,
    NULL, // encrypt
    kyber_encap,
    kyber_decrypt,
    NULL, // sign
    NULL, // verify
    kyber_get_nbits,
    NULL, // run_selftests
    NULL, // compute_keygrip
    NULL, // get_curve
    NULL  // get_curve_param
};
