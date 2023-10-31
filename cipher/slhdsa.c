
#include <config.h>
#include <stdio.h>

//#include "gcrypt.h"

#include "g10lib.h"
#include "mpi.h"
#include "cipher.h"
#include "pubkey-internal.h"
#include "slhdsa-context.h"
#include "slhdsa-api.h"

static unsigned int
/* TODOMTG nbits not meaningful for slhdsa */
slhdsa_get_nbits (gcry_sexp_t parms)
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

typedef enum {
  SHA2_128f,
  SHA2_128s,
  SHA2_192f,
  SHA2_192s,
  SHA2_256f,
  SHA2_256s,
  SHAKE_128f,
  SHAKE_128s,
  SHAKE_192f,
  SHAKE_192s,
  SHAKE_256f,
  SHAKE_256s
} slhdsa_paramset;

static gcry_err_code_t paramset_from_hash_and_variant(slhdsa_paramset *paramset, const char *hash, const char* variant)
{
  if(strcmp(hash, "SHA2") == 0)
  {
    if(strcmp(variant, "128f") == 0)
    {
      *paramset = SHA2_128f;
    }
    else if(strcmp(variant, "128s") == 0)
    {
      *paramset = SHA2_128s;
    }
    else if(strcmp(variant, "192f") == 0)
    {
      *paramset = SHA2_192f;
    }
    else if(strcmp(variant, "192s") == 0)
    {
      *paramset = SHA2_192s;
    }
    else if(strcmp(variant, "256f") == 0)
    {
      *paramset = SHA2_256f;
    }
    else if(strcmp(variant, "256s") == 0)
    {
      *paramset = SHA2_256s;
    }
    else
    {
      return 1; /* TODO: correct error code */
    }
  }
  else if(strcmp(hash, "SHAKE") == 0)
  {
    if(strcmp(variant, "128f") == 0)
    {
      *paramset = SHAKE_128f;
    }
    else if(strcmp(variant, "128s") == 0)
    {
      *paramset = SHAKE_128s;
    }
    else if(strcmp(variant, "192f") == 0)
    {
      *paramset = SHAKE_192f;
    }
    else if(strcmp(variant, "192s") == 0)
    {
      *paramset = SHAKE_192s;
    }
    else if(strcmp(variant, "256f") == 0)
    {
      *paramset = SHAKE_256f;
    }
    else if(strcmp(variant, "256s") == 0)
    {
      *paramset = SHAKE_256s;
    }
    else
    {
      return 1; /* TODO: correct error code */
    }
  }
  else {
    return 1; /* TODO: correct error code */
  }

  return 0;
}

static void gcry_slhdsa_param_destroy(_gcry_slhdsa_param_t *param)
{
  xfree(param->pub_seed);
  xfree(param->sk_seed);
  xfree(param->state_seeded);
  xfree(param->state_seeded_512);
}

static gcry_err_code_t gcry_slhdsa_get_param_from_paramset_id(_gcry_slhdsa_param_t *param, slhdsa_paramset paramset)
{
  switch(paramset)
  {
   case SHA2_128f:
    param->n = 16;
    param->d = 22;
    param->full_height = 66;
    param->FORS_height = 6;
    param->FORS_trees = 33;
    param->do_use_sha512 = 0;
    param->is_sha2 = 1;
    break;
   case SHA2_128s:
    param->n = 16;
    param->d = 7;
    param->full_height = 63;
    param->FORS_height = 12;
    param->FORS_trees = 14;
    param->do_use_sha512 = 0;
    param->is_sha2 = 1;
    break;
  case SHA2_192f:
    param->n = 24;
    param->d = 22;
    param->full_height = 66;
    param->FORS_height = 8;
    param->FORS_trees = 33;
    param->do_use_sha512 = 1;
    param->is_sha2 = 1;
    break;
  case SHA2_192s:
    param->n = 24;
    param->d = 7;
    param->full_height = 63;
    param->FORS_height = 14;
    param->FORS_trees = 17;
    param->do_use_sha512 = 1;
    param->is_sha2 = 1;
    break;
  case SHA2_256f:
    param->n = 32;
    param->d = 17;
    param->full_height = 68;
    param->FORS_height = 9;
    param->FORS_trees = 35;
    param->do_use_sha512 = 1;
    param->is_sha2 = 1;
    break;
  case SHA2_256s:
    param->n = 32;
    param->d = 8;
    param->full_height = 64;
    param->FORS_height = 14;
    param->FORS_trees = 22;
    param->do_use_sha512 = 1;
    param->is_sha2 = 1;
    break;
  case SHAKE_128f:
    param->n = 16;
    param->d = 22;
    param->full_height = 66;
    param->FORS_height = 6;
    param->FORS_trees = 33;
    param->do_use_sha512 = 0;
    param->is_sha2 = 0;
    break;
   case SHAKE_128s:
    param->n = 16;
    param->d = 7;
    param->full_height = 63;
    param->FORS_height = 12;
    param->FORS_trees = 14;
    param->do_use_sha512 = 0;
    param->is_sha2 = 0;
    break;
  case SHAKE_192f:
    param->n = 24;
    param->d = 22;
    param->full_height = 66;
    param->FORS_height = 8;
    param->FORS_trees = 33;
    param->do_use_sha512 = 0;
    param->is_sha2 = 0;
    break;
  case SHAKE_192s:
    param->n = 24;
    param->d = 7;
    param->full_height = 63;
    param->FORS_height = 14;
    param->FORS_trees = 17;
    param->do_use_sha512 = 0;
    param->is_sha2 = 0;
    break;
  case SHAKE_256f:
    param->n = 32;
    param->d = 17;
    param->full_height = 68;
    param->FORS_height = 9;
    param->FORS_trees = 35;
    param->do_use_sha512 = 0;
    param->is_sha2 = 0;
    break;
  case SHAKE_256s:
    param->n = 32;
    param->d = 8;
    param->full_height = 64;
    param->FORS_height = 14;
    param->FORS_trees = 22;
    param->do_use_sha512 = 0;
    param->is_sha2 = 0;
    break;
  default: return 1; /* TODO: correct error code */
  }

  /* allocate buffers */
  param->pub_seed = NULL;
  param->sk_seed = NULL;
  param->state_seeded = NULL;
  param->state_seeded_512 = NULL;
  param->pub_seed = xtrymalloc(param->n);
  param->sk_seed = xtrymalloc_secure(param->n);
  param->state_seeded = xtrymalloc_secure(40);
  param->state_seeded_512 = xtrymalloc_secure(72);
  if(!param->pub_seed || !param->sk_seed || !param->state_seeded || !param->state_seeded_512)
  {
      return gpg_err_code_from_syserror();
      gcry_slhdsa_param_destroy(param);
  }

  /* derived and fix params */
  param->addr_bytes = 32;
  param->WOTS_w = 16;
  param->WOTS_logw = 4;
  param->seed_bytes = 3*param->n;
  param->tree_height = param->full_height / param->d;
  param->FORS_msg_bytes = (param->FORS_height * param->FORS_trees + 7) / 8;
  param->FORS_bytes = (param->FORS_height + 1) * param->FORS_trees * param->n;
  param->FORS_pk_bytes = param->n;
  param->WOTS_len1 = 8 * param->n / param->WOTS_logw;
  param->WOTS_len2 = 3; /* for all param->n in range [9..136] */

  param->WOTS_len = param->WOTS_len1 + param->WOTS_len2;
  param->WOTS_bytes = param->WOTS_len * param->n;
  param->WOTS_pk_bytes = param->WOTS_bytes;

  /* sig and key size */
  param->signature_bytes = param->n + param->FORS_bytes + param->d * param->WOTS_bytes + param->full_height * param->n;
  param->public_key_bytes = 2 * param->n;
  param->secret_key_bytes = 2 * param->n + param->public_key_bytes;

  /* hash offsets */
  if(param->is_sha2)
  {
    param->offset_layer = 0;
    param->offset_tree = 1;
    param->offset_type = 9;
    param->offset_kp_addr2 = 12;
    param->offset_kp_addr1 = 13;
    param->offset_chain_addr = 17;
    param->offset_hash_addr = 21;
    param->offset_tree_hgt = 17;
    param->offset_tree_index = 18;
  }
  else {
    param->offset_layer = 3;
    param->offset_tree = 8;
    param->offset_type = 19;
    param->offset_kp_addr2 = 22;
    param->offset_kp_addr1 = 23;
    param->offset_chain_addr = 27;
    param->offset_hash_addr = 31;
    param->offset_tree_hgt = 27;
    param->offset_tree_index = 28;
  }

  return 0;
}

const char *hash_alg_map[] = {"SHA2", "SHAKE"};
const char *variant_map[] = {"128f", "128s", "192f", "192s", "256f", "256s"};
static gcry_err_code_t slhdsa_get_hash_alg_and_variant_from_sexp(gcry_sexp_t list, const char **hash_alg, const char **variant)
{
  // char buf[50];
  // const char *s;
  // size_t n;


  // list = sexp_find_token (list, "nbits", 0);
  // if (!list)
  //   return 0; /* No NBITS found.  */

  // s = sexp_nth_data (list, 1, &n);
  // if (!s || n >= DIM (buf) - 1 )
  //   {
  //     /* NBITS given without a cdr.  */
  //     sexp_release (list);
  //     return GPG_ERR_INV_OBJ;
  //   }
  // memcpy (buf, s, n);
  // buf[n] = 0;
  // sexp_release (list);

  // *hash_alg = hash_alg_map[0];
  // *variant = variant_map[0];
  // return 0;

  const char *s_hashalg;
  const char *s_variant;
  size_t n_hashalg;
  size_t n_variant;

  gcry_sexp_t hashalg_sexp;
  gcry_sexp_t variant_sexp;

  hashalg_sexp = sexp_find_token (list, "hash-alg", 0);
  if (!hashalg_sexp)
    return 0; /* No hash-alg found.  */

  s_hashalg = sexp_nth_data (hashalg_sexp, 1, &n_hashalg);
  if (!s_hashalg)
    {
      /* hash-alg given without a cdr.  */
      sexp_release (hashalg_sexp);
      return GPG_ERR_INV_OBJ;
    }

  variant_sexp = sexp_find_token (list, "variant", 0);
  if (!variant_sexp)
    return 0; /* No hash-alg found.  */

  s_variant = sexp_nth_data (variant_sexp, 1, &n_variant);
  if (!s_variant)
    {
      /* hash-alg given without a cdr.  */
      sexp_release (variant_sexp);
      return GPG_ERR_INV_OBJ;
    }


  *hash_alg = NULL;
  *variant = NULL;
  for(size_t i = 0; i < DIM (hash_alg_map); i++)
  {
    if(strncmp(hash_alg_map[i], s_hashalg, n_hashalg) == 0)
    {
      *hash_alg = hash_alg_map[i];
      break;
    }
  }
  for(size_t i = 0; i < DIM (variant_map); i++)
  {
    if(strncmp(variant_map[i], s_variant, n_variant) == 0)
    {
      *variant = variant_map[i];
      break;
    }
  }


  sexp_release (hashalg_sexp);
  sexp_release (variant_sexp);
  if(!(*variant) || !(*hash_alg))
  {
    return GPG_ERR_INV_OBJ;
  }
  return 0;
}

static const char *slhdsa_names[] = {
  "slhdsa",
  "openpgp-slhdsa",              // ? leave?
  NULL,
};




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
                                             const _gcry_slhdsa_param_t param,
                                             unsigned char **sk_p)
{
  return extract_opaque_mpi_from_sexp(
      keyparms, "/s", sk_p, param.secret_key_bytes);
}

static gcry_err_code_t public_key_from_sexp(const gcry_sexp_t keyparms,
                                            const _gcry_slhdsa_param_t param,
                                            unsigned char **pk_p)
{
  return extract_opaque_mpi_from_sexp(
      keyparms, "/p", pk_p, param.public_key_bytes);
}


static gcry_err_code_t
slhdsa_generate (const gcry_sexp_t genparms, gcry_sexp_t * r_skey)
{
  gpg_err_code_t ec = 0;

  unsigned char *pk = NULL;
  unsigned char * sk = NULL;
  unsigned int nbits;
  _gcry_slhdsa_param_t param = {0};
  slhdsa_paramset paramset;

  const char *hash_alg;
  const char *variant;

  gcry_mpi_t sk_mpi = NULL;
  gcry_mpi_t pk_mpi = NULL;

  ec = _gcry_pk_util_get_nbits (genparms, &nbits);
  if (ec)
    return ec;
  if ((ec = slhdsa_get_hash_alg_and_variant_from_sexp(genparms, &hash_alg, &variant)))
    return ec;
  if ((ec = paramset_from_hash_and_variant(&paramset, hash_alg, variant)))
    return ec;
  if ((ec = gcry_slhdsa_get_param_from_paramset_id(&param, paramset)))
    return ec;

  if (!(sk = xtrymalloc_secure(param.secret_key_bytes))
    || !(pk = xtrymalloc(param.public_key_bytes)))
  {
    ec = gpg_err_code_from_syserror();
    goto leave;
  }
  _gcry_slhdsa_keypair(&param, pk, sk);

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
                      "  (slhdsa(p%m) (nbits%u) (hash-alg%s) (variant%s)))"
                      " (private-key"
                      "  (slhdsa(s%m) (nbits%u) (hash-alg%s) (variant%s))))",
                      pk_mpi,
                      nbits,
                      hash_alg, variant,
                      sk_mpi,
                      nbits,
                      hash_alg, variant,
                      NULL);

    }

leave:
  _gcry_mpi_release(sk_mpi);
  _gcry_mpi_release(pk_mpi);
  gcry_slhdsa_param_destroy(&param);
  xfree(sk);
  xfree(pk);
  return ec;
}


static gcry_err_code_t
slhdsa_check_secret_key (gcry_sexp_t keyparms)
{
  gpg_err_code_t ec = 0;

  /* TODO implement */
  (void) keyparms;

  return ec;
}

static gcry_err_code_t
slhdsa_sign (gcry_sexp_t *r_sig, gcry_sexp_t s_data, gcry_sexp_t keyparms)
{
  gpg_err_code_t ec = 0;
  unsigned char *sig_buf = NULL;
  unsigned char *sk_buf = NULL;
  unsigned char *data_buf = NULL;
  size_t data_buf_len = 0;

  struct pk_encoding_ctx ctx;

  //gcry_mpi_t sk = NULL;
  gcry_mpi_t data = NULL;
  size_t nwritten = 0;

  unsigned int nbits = slhdsa_get_nbits (keyparms);
  _gcry_slhdsa_param_t param = {0};
  slhdsa_paramset paramset;
  const char *hash_alg;
  const char *variant;
  size_t sig_buf_len;

  if ((ec = slhdsa_get_hash_alg_and_variant_from_sexp(keyparms, &hash_alg, &variant)))
    return ec;
  if ((ec = paramset_from_hash_and_variant(&paramset, hash_alg, variant)))
    return ec;
  if ((ec = gcry_slhdsa_get_param_from_paramset_id(&param, paramset)))
    return ec;
  _gcry_pk_util_init_encoding_ctx (&ctx, PUBKEY_OP_SIGN, nbits);


  ec = _gcry_pk_util_data_to_mpi (s_data, &data, &ctx);
  if (ec)
    goto leave;
  if (!mpi_is_opaque(data))
  {
    printf("slhdsa only works with opaque mpis!\n");
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

  if(0 != _gcry_slhdsa_signature(&param, sig_buf, &sig_buf_len, data_buf, data_buf_len, sk_buf))
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

  ec = sexp_build (r_sig, NULL, "(sig-val(slhdsa(a%b)))", sig_buf_len, sig_buf);
  if(ec)
    printf("sexp build failed\n");

leave:
  _gcry_pk_util_free_encoding_ctx (&ctx);
  xfree(sk_buf);
  xfree(sig_buf);
  xfree(data_buf);
  gcry_slhdsa_param_destroy(&param);
  _gcry_mpi_release(data);
  if (DBG_CIPHER)
    log_debug ("slhdsa_sign    => %s\n", gpg_strerror (ec));
  return ec;
}


static gcry_err_code_t
slhdsa_verify (gcry_sexp_t s_sig, gcry_sexp_t s_data, gcry_sexp_t s_keyparms)
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
  _gcry_slhdsa_param_t param = {0};
  slhdsa_paramset paramset;
  const char *hash_alg;
  const char *variant;
  gcry_sexp_t l1 = NULL;

  unsigned int nbits = slhdsa_get_nbits (s_keyparms);
  if ((ec = slhdsa_get_hash_alg_and_variant_from_sexp(s_keyparms, &hash_alg, &variant)))
    return ec;
  if ((ec = paramset_from_hash_and_variant(&paramset, hash_alg, variant)))
    return ec;
  if ((ec = gcry_slhdsa_get_param_from_paramset_id(&param, paramset)))
    return ec;

  _gcry_pk_util_init_encoding_ctx (&ctx, PUBKEY_OP_VERIFY, nbits);

  ec = _gcry_pk_util_data_to_mpi (s_data, &data, &ctx);
  if (ec)
    goto leave;
  if (!mpi_is_opaque(data))
  {
    printf("slhdsa only works with opaque mpis!\n");
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
  ec = public_key_from_sexp(s_keyparms, param, &pk_buf);
  if (ec)
  {
    printf("failed to parse public key\n");
    goto leave;
  }

  /* Extract the signature value.  */
  ec = _gcry_pk_util_preparse_sigval (s_sig, slhdsa_names, &l1, NULL);
  if (ec)
    goto leave;
  ec = sexp_extract_param (l1, NULL, "/a", &sig, NULL);
  if (ec)
    goto leave;
  if (DBG_CIPHER)
    log_printmpi ("slhdsa_verify  sig", sig);

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

  if(0 != _gcry_slhdsa_verify(&param, sig_buf, param.signature_bytes, data_buf, data_buf_len, pk_buf))
  {
    ec = GPG_ERR_GENERAL;
    goto leave;
  }

leave:
  _gcry_pk_util_free_encoding_ctx (&ctx);
  xfree(pk_buf);
  xfree(data_buf);
  xfree(sig_buf);
  gcry_slhdsa_param_destroy(&param);
  _gcry_mpi_release(data);
  _gcry_mpi_release(sig);
  sexp_release (l1);
  if (DBG_CIPHER)
    log_debug ("slhdsa_verify    => %s\n", gpg_strerror (ec));
  return ec;
}

static gpg_err_code_t
selftests_slhdsa (selftest_report_func_t report, int extended)
{
  (void) report;
  (void) extended;

  return GPG_ERR_NO_ERROR; // TODO implement
}

/* Run a full self-test for ALGO and return 0 on success.  */
static gpg_err_code_t
run_selftests (int algo, int extended, selftest_report_func_t report)
{
  gpg_err_code_t ec;

  switch (algo)
    {
    case GCRY_PK_SLHDSA:
      ec = selftests_slhdsa (report, extended);
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

  (void) md;
  (void) keyparam;

  /* TODO: implement */

  return ec;
}

gcry_pk_spec_t _gcry_pubkey_spec_slhdsa = {
  GCRY_PK_SLHDSA, {0, 1},
  (GCRY_PK_USAGE_SIGN),
  "slhdsa", slhdsa_names,
  "p", "s", "", "a", "p",       // elements of pub-key, sec-key, ciphertext, signature, key-grip
  slhdsa_generate,
  slhdsa_check_secret_key,
  NULL,
  NULL,
  slhdsa_sign,
  slhdsa_verify,
  slhdsa_get_nbits,
  run_selftests,
  compute_keygrip
};