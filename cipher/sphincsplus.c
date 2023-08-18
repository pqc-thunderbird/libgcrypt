
#include <config.h>
#include <stdio.h>

//#include "gcrypt.h"

#include "g10lib.h"
#include "mpi.h"
#include "cipher.h"
#include "pubkey-internal.h"
#include "params/params-sphincs-sha2-128f.h"

typedef struct {
    uint8_t secret_key_bytes;
    uint8_t public_key_bytes;
    uint16_t signature_bytes;
} gcry_sphincsplus_param_t;


static unsigned int
/* TODOMTG nbits not meaningful for sphincsplus */
sphincsplus_get_nbits (gcry_sexp_t parms)
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

static const char *sphincsplus_names[] = {
  "sphincsplus",
  "openpgp-sphincsplus",              // ? leave?
  NULL,
};


static gcry_err_code_t gcry_sphincsplus_get_param_from_bit_size(size_t nbits,
                                                    gcry_sphincsplus_param_t *param)
{
#if 0
  // nbits: sphincsplus pubkey byte size * 8
  switch (nbits)
  {
    case GCRY_SPHINCSPLUS2_NBITS:
      param->id = GCRY_SPHINCSPLUS2;
      param->k = 4;
      param->l = 4;
      param->eta = 2;
      param->tau = 39;
      param->beta = 78;
      param->gamma1 = 1 << 17;
      param->gamma2 = (GCRY_SPHINCSPLUS_Q-1)/88;
      param->omega = 80;
      break;
    case GCRY_SPHINCSPLUS3_NBITS:
      param->id = GCRY_SPHINCSPLUS3;
      param->k = 6;
      param->l = 5;
      param->eta = 4;
      param->tau = 49;
      param->beta = 196;
      param->gamma1 = 1 << 19;
      param->gamma2 = (GCRY_SPHINCSPLUS_Q-1)/32;
      param->omega = 55;
      break;
    case GCRY_SPHINCSPLUS5_NBITS:
      param->id = GCRY_SPHINCSPLUS5;
      param->k = 8;
      param->l = 7;
      param->eta = 2;
      param->tau = 60;
      param->beta = 120;
      param->gamma1 = 1 << 19;
      param->gamma2 = (GCRY_SPHINCSPLUS_Q-1)/32;
      param->omega = 75;
      break;
    default:
      return GPG_ERR_INV_ARG;
  }

    param->polyvech_packedbytes = param->omega + param->k;

    if(param->gamma1 == (1 << 17))
    {
      param->polyz_packedbytes = 576;
    }
    else if(param->gamma1 == (1 << 19))
    {
      param->polyz_packedbytes = 640;
    }
    else
    {
      printf("error when determining polyz_packedbytes\n");
      return GPG_ERR_GENERAL; // TODOMTG better errcode?
    }


    if(param->gamma2 == (GCRY_SPHINCSPLUS_Q-1)/88)
    {
      param->polyw1_packedbytes = 192;
    }
    else if(param->gamma2 == (GCRY_SPHINCSPLUS_Q-1)/32)
    {
      param->polyw1_packedbytes = 128;
    }
    else
    {
      printf("error when determining polyw1_packedbytes\n");
      return GPG_ERR_GENERAL; // TODOMTG better errcode?
    }

    if(param->eta == 2)
    {
      param->polyeta_packedbytes = 96;
    }
    else if(param->eta == 4)
    {
      param->polyeta_packedbytes = 128;
    }
    else
    {
      printf("error when determining polyeta_packedbytes\n");
      return GPG_ERR_GENERAL; // TODOMTG better errcode?
    }

    param->public_key_bytes = GCRY_SPHINCSPLUS_SEEDBYTES + param->k * GCRY_SPHINCSPLUS_POLYT1_PACKEDBYTES;
    param->secret_key_bytes = 3 * GCRY_SPHINCSPLUS_SEEDBYTES
                              + param->l * param->polyeta_packedbytes
                              + param->k * param->polyeta_packedbytes
                              + param->k * GCRY_SPHINCSPLUS_POLYT0_PACKEDBYTES;
    param->signature_bytes = GCRY_SPHINCSPLUS_SEEDBYTES + param->l * param->polyz_packedbytes + param->polyvech_packedbytes;

  return 0;
#endif
return 0;
}


static gcry_err_code_t extract_opaque_mpi_from_sexp(const gcry_sexp_t keyparms,
                                                    const char *label,
                                                    unsigned char **sk_p,
                                                    size_t exp_len)
{
  gcry_mpi_t sk     = NULL;
  gpg_err_code_t ec = 0;
  size_t nwritten   = 0;
  *sk_p = 0;

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

  if (!(*sk_p = xtrymalloc(exp_len)))
    {
      ec = gpg_err_code_from_syserror();
      goto leave;
    }
  _gcry_mpi_print(GCRYMPI_FMT_USG, *sk_p, exp_len, &nwritten, sk);

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
      xfree(*sk_p);
      *sk_p = 0;
    }
  return ec;
}


static gcry_err_code_t private_key_from_sexp(const gcry_sexp_t keyparms,
                                             const gcry_sphincsplus_param_t param,
                                             unsigned char **sk_p)
{
  return extract_opaque_mpi_from_sexp(
      keyparms, "/s", sk_p, param.secret_key_bytes);
}

static gcry_err_code_t public_key_from_sexp(const gcry_sexp_t keyparms,
                                            const gcry_sphincsplus_param_t param,
                                            unsigned char **pk_p)
{
  return extract_opaque_mpi_from_sexp(
      keyparms, "/p", pk_p, param.public_key_bytes);
}


static gcry_err_code_t
sphincsplus_generate (const gcry_sexp_t genparms, gcry_sexp_t * r_skey)
{
  gpg_err_code_t ec = 0;

  unsigned char *pk = NULL;
  unsigned char * sk = NULL;
  unsigned int nbits;
  gcry_sphincsplus_param_t param;
  param.public_key_bytes = SPX_PK_BYTES;
  param.secret_key_bytes = SPX_SK_BYTES;
  param.signature_bytes = SPX_BYTES;

  ec = _gcry_pk_util_get_nbits (genparms, &nbits);
  if (ec)
    return ec;
  if ((ec = gcry_sphincsplus_get_param_from_bit_size(nbits, &param)))
    return ec;

  if (!(sk = xtrymalloc_secure(param.secret_key_bytes))
    || !(pk = xtrymalloc(param.public_key_bytes)))
  {
    ec = gpg_err_code_from_syserror();
    goto leave;
  }
  //_gcry_sphincsplus_keypair(&param, pk, sk);
  crypto_sign_keypair(pk, sk);

  gcry_mpi_t sk_mpi = NULL;
  gcry_mpi_t pk_mpi = NULL;
  sk_mpi = _gcry_mpi_set_opaque_copy (sk_mpi, sk, param.secret_key_bytes * 8);
  pk_mpi = _gcry_mpi_set_opaque_copy (pk_mpi, pk, param.public_key_bytes * 8);

  if(!sk_mpi || !pk_mpi) {
    // TODO: needed?
    printf("creating sk_mpi or pk_mpi failed!\n");
    ec = gpg_err_code_from_syserror();
    goto leave;
  }

  if (!ec)
    {
      ec = sexp_build(r_skey,
                      NULL,
                      "(key-data"
                      " (public-key"
                      "  (sphincsplus(p%m) (nbits%u)))"
                      " (private-key"
                      "  (sphincsplus(s%m) (nbits%u))))",
                      pk_mpi,
                      nbits,
                      sk_mpi,
                      nbits,
                      NULL);

    }

leave:
  _gcry_mpi_release(sk_mpi);
  _gcry_mpi_release(pk_mpi);
  xfree(sk);
  xfree(pk);
  return ec;
}


static gcry_err_code_t
sphincsplus_check_secret_key (gcry_sexp_t keyparms)
{
  gpg_err_code_t ec = 0;
  return ec;
}

static gcry_err_code_t
sphincsplus_sign (gcry_sexp_t *r_sig, gcry_sexp_t s_data, gcry_sexp_t keyparms)
{
  gpg_err_code_t ec = 0;
  unsigned char *sig_buf = NULL;
  unsigned char *sk_buf = NULL;
  unsigned char *data_buf = NULL;
  size_t data_buf_len = 0;

  struct pk_encoding_ctx ctx;

  //gcry_mpi_t sk = NULL;
  gcry_mpi_t sig = NULL;
  gcry_mpi_t data = NULL;
  size_t nwritten = 0;

  unsigned int nbits = sphincsplus_get_nbits (keyparms);
  gcry_sphincsplus_param_t param;
  param.public_key_bytes = SPX_PK_BYTES;
  param.secret_key_bytes = SPX_SK_BYTES;
  param.signature_bytes = SPX_BYTES;
  if ((ec = gcry_sphincsplus_get_param_from_bit_size(nbits, &param)))
    return ec;
  _gcry_pk_util_init_encoding_ctx (&ctx, PUBKEY_OP_SIGN, nbits);


  ec = _gcry_pk_util_data_to_mpi (s_data, &data, &ctx);
  if (ec)
    goto leave;
  if (!mpi_is_opaque(data))
  {
    printf("sphincsplus only works with opaque mpis!\n");
    ec = GPG_ERR_INV_ARG;
    goto leave;
  }

  /* extract msg from mpi */
  _gcry_mpi_print(GCRYMPI_FMT_USG, NULL, 0, &nwritten, data);
  data_buf_len = nwritten;
  if (!(data_buf = xtrymalloc(data_buf_len)))
  {
    ec = gpg_err_code_from_syserror();
    goto leave;
  }
  _gcry_mpi_print(GCRYMPI_FMT_USG, data_buf, data_buf_len, &nwritten, data);
  if(nwritten != data_buf_len)
  {
    printf("nwritten != data_buf_len\n");
  }

  /* extract sk */
  if ((ec = private_key_from_sexp(keyparms, param, &sk_buf)))
  {
    goto leave;
  }

  if (!(sig_buf = xtrymalloc(param.signature_bytes)))
  {
    ec = gpg_err_code_from_syserror();
    goto leave;
  }

  size_t sig_buf_len;
  //if(0 != _gcry_sphincsplus_sign(&param, sig_buf, &sig_buf_len, data_buf, data_buf_len, sk_buf))
  if(0 != crypto_sign_signature(sig_buf, &sig_buf_len, data_buf, data_buf_len, sk_buf))
  {
    printf("sign operation failed\n");
    ec = GPG_ERR_GENERAL;
    goto leave;
  }
  if(sig_buf_len != param.signature_bytes)
  {
    printf("unexpected sig buf length\n");
    ec = GPG_ERR_GENERAL;
    goto leave;
  }

  ec = sexp_build (r_sig, NULL, "(sig-val(sphincsplus(a%b)))", sig_buf_len, sig_buf);
  if(ec)
    printf("sexp build failed\n");

leave:
  _gcry_pk_util_free_encoding_ctx (&ctx);
  xfree(sk_buf);
  xfree(sig_buf);
  xfree(data_buf);
  _gcry_mpi_release(data);
  if (DBG_CIPHER)
    log_debug ("sphincsplus_sign    => %s\n", gpg_strerror (ec));
  return ec;
}


static gcry_err_code_t
sphincsplus_verify (gcry_sexp_t s_sig, gcry_sexp_t s_data, gcry_sexp_t s_keyparms)
{
  gpg_err_code_t ec = 0;
  unsigned char *sig_buf = NULL;
  unsigned char *pk_buf = NULL;
  unsigned char *data_buf = NULL;
  size_t data_buf_len = 0;

  struct pk_encoding_ctx ctx;

  gcry_mpi_t sig = NULL;
  gcry_mpi_t data = NULL;
  size_t nwritten = 0;
  gcry_sphincsplus_param_t param;
  param.public_key_bytes = SPX_PK_BYTES;
  param.secret_key_bytes = SPX_SK_BYTES;
  param.signature_bytes = SPX_BYTES;
  gcry_sexp_t l1 = NULL;

  unsigned int nbits = sphincsplus_get_nbits (s_keyparms);
  if ((ec = gcry_sphincsplus_get_param_from_bit_size(nbits, &param)))
    return ec;

  _gcry_pk_util_init_encoding_ctx (&ctx, PUBKEY_OP_VERIFY, nbits);

  ec = _gcry_pk_util_data_to_mpi (s_data, &data, &ctx);
  if (ec)
    goto leave;
  if (!mpi_is_opaque(data))
  {
    printf("sphincsplus only works with opaque mpis!\n");
    ec = GPG_ERR_INV_ARG;
    goto leave;
  }

  /* extract msg from mpi */
  _gcry_mpi_print(GCRYMPI_FMT_USG, NULL, 0, &nwritten, data);
  data_buf_len = nwritten;
  if (!(data_buf = xtrymalloc(data_buf_len)))
  {
    ec = gpg_err_code_from_syserror();
    goto leave;
  }
  _gcry_mpi_print(GCRYMPI_FMT_USG, data_buf, data_buf_len, &nwritten, data);
  if(nwritten != data_buf_len)
  {
    printf("nwritten != data_buf_len\n");
  }

  /* extract pk */
  if (ec = public_key_from_sexp(s_keyparms, param, &pk_buf))
  {
    printf("failed to parse public key\n");
    goto leave;
  }

  /* Extract the signature value.  */
  ec = _gcry_pk_util_preparse_sigval (s_sig, sphincsplus_names, &l1, NULL);
  if (ec)
    goto leave;
  ec = sexp_extract_param (l1, NULL, "/a", &sig, NULL);
  if (ec)
    goto leave;
  if (DBG_CIPHER)
    log_printmpi ("sphincsplus_verify  sig", sig);

  /* extract sig from mpi */
  if (!(sig_buf = xtrymalloc(param.signature_bytes)))
  {
    ec = gpg_err_code_from_syserror();
    goto leave;
  }
  _gcry_mpi_print(GCRYMPI_FMT_USG, sig_buf, param.signature_bytes, &nwritten, sig);
  if(nwritten != param.signature_bytes)
  {
    // signature length invalid
    ec = GPG_ERR_BAD_SIGNATURE;
    goto leave;
  }

  if(0 != crypto_sign_verify(sig_buf, param.signature_bytes, data_buf, data_buf_len, pk_buf))
  {
    ec = GPG_ERR_GENERAL;
    goto leave;
  }

leave:
  _gcry_pk_util_free_encoding_ctx (&ctx);
  xfree(pk_buf);
  xfree(data_buf);
  xfree(sig_buf);
  _gcry_mpi_release(data);
  _gcry_mpi_release(sig);
  sexp_release (l1);
  if (DBG_CIPHER)
    log_debug ("sphincsplus_verify    => %s\n", gpg_strerror (ec));
  return ec;
}

static gpg_err_code_t
selftests_sphincsplus (selftest_report_func_t report, int extended)
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
    case GCRY_PK_SPHINCSPLUS:
      ec = selftests_sphincsplus (report, extended);
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

gcry_pk_spec_t _gcry_pubkey_spec_sphincsplus = {
  GCRY_PK_SPHINCSPLUS, {0, 1},
  (GCRY_PK_USAGE_SIGN),
  "sphincsplus", sphincsplus_names,
  "p", "s", "", "a", "p",       // elements of pub-key, sec-key, ciphertext, signature, key-grip
  sphincsplus_generate,
  sphincsplus_check_secret_key,
  NULL,
  NULL,
  sphincsplus_sign,
  sphincsplus_verify,
  sphincsplus_get_nbits,
  run_selftests,
  compute_keygrip
};