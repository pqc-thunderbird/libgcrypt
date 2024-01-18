/* mlkem.c - API functions for ML-KEM
 * Copyright (C) 2023 MTG AG
 * The code was created based on the reference implementation that is part of the ML-KEM NIST submission.
 *
 * This file is part of Libgcrypt.
 *
 * Libgcrypt is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * Libgcrypt is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include <config.h>
#include <stdio.h>


// #include "gcrypt.h"
#include "mlkem-common.h"

#include "g10lib.h"

#include "cipher.h"
#include "mlkem-params.h"
#include "pubkey-internal.h"
#include "mlkem-aux.h"
#include "bufhelp.h"


static gcry_err_code_t
_gcry_mlkem_get_param_from_bitstrength (size_t nbits,
                                        gcry_mlkem_param_t *param)
{
  switch (nbits)
    {
    case 128:
      param->id                       = GCRY_MLKEM_512;
      param->k                        = 2;
      param->eta1                     = 3;
      param->poly_compressed_bytes    = 128;
      param->polyvec_compressed_bytes = param->k * 320;
      break;
    case 192:
      param->id                       = GCRY_MLKEM_768;
      param->k                        = 3;
      param->eta1                     = 2;
      param->poly_compressed_bytes    = 128;
      param->polyvec_compressed_bytes = param->k * 320;
      break;
    case 256:
      param->id                       = GCRY_MLKEM_1024;
      param->k                        = 4;
      param->eta1                     = 2;
      param->poly_compressed_bytes    = 160;
      param->polyvec_compressed_bytes = param->k * 352;
      break;
    default:
      return GPG_ERR_INV_ARG;
    }

  param->polyvec_bytes           = param->k * GCRY_MLKEM_POLYBYTES;
  param->public_key_bytes        = param->polyvec_bytes + GCRY_MLKEM_SYMBYTES;
  param->indcpa_secret_key_bytes = param->polyvec_bytes;
  param->ciphertext_bytes
      = param->poly_compressed_bytes + param->polyvec_compressed_bytes;
  param->secret_key_bytes = param->indcpa_secret_key_bytes
                            + param->public_key_bytes
                            + 2 * GCRY_MLKEM_SYMBYTES;

  return 0;
}

/**
 * return the bit strength (128, 192, 256) roughly associated with the given ML-KEM parameter set based on the private key size in bytes.
 */
static unsigned
bitstrength_from_private_size_bytes (size_t private_key_size_bytes)
{
  unsigned bit_strengths[] = {128, 192, 256};
  for (unsigned i = 0; i < 3; i++)
    {
      gpg_error_t ec;
      unsigned b = bit_strengths[i];
      gcry_mlkem_param_t p;
      ec = _gcry_mlkem_get_param_from_bitstrength (b, &p);
      if (ec)
        {
          return 0;
        }
      if (p.secret_key_bytes == private_key_size_bytes)
        {
          return b;
        }
    }
  return 0;
}


/**
 * return the bit strength (128, 192, 256) roughly associated with the given ML-KEM parameter set based on the public key size in bytes.
 */
static unsigned
bitstrength_from_public_size_bytes (size_t public_key_size_bytes)
{
  unsigned bit_strengths[] = {128, 192, 256};
  for (unsigned i = 0; i < 3; i++)
    {
      gpg_error_t ec;
      unsigned b = bit_strengths[i];
      gcry_mlkem_param_t p;
      ec = _gcry_mlkem_get_param_from_bitstrength (b, &p);
      if (ec)
        {
          return 0;
        }
      if (p.public_key_bytes == public_key_size_bytes)
        {
          return b;
        }
    }
  return 0;
}

static gcry_err_code_t
mlkem_params_from_private_key_size (size_t private_key_size,
                                    gcry_mlkem_param_t *param,
                                    unsigned int *nbits_p)
{
  gpg_err_code_t ec = 0;

  unsigned int bit_strength;
  bit_strength = bitstrength_from_private_size_bytes (private_key_size);
  if (!bit_strength)
    {
      return GPG_ERR_INV_PARAMETER;
    }
  ec = _gcry_mlkem_get_param_from_bitstrength (bit_strength, param);
  if (ec)
    {
      return ec;
    }
  if (nbits_p != NULL)
    {
      switch (param->id)
        {
        case GCRY_MLKEM_512:
          {
            *nbits_p = 128;
            break;
          }
        case GCRY_MLKEM_768:
          {
            *nbits_p = 192;
            break;
          }
        case GCRY_MLKEM_1024:
          {
            *nbits_p = 256;
            break;
          }
        default:
          {
            ec = GPG_ERR_INV_ARG;
          }
        }
    }

  return ec;
}
static gcry_err_code_t
mlkem_params_from_key_param (const gcry_sexp_t keyparms,
                             gcry_mlkem_param_t *param,
                             unsigned int *nbits_p)
{
  gpg_err_code_t ec = 0;

  unsigned int nbits;
  ec = _gcry_pk_util_get_nbits (keyparms, &nbits);
  if (ec)
    {
      return ec;
    }
  ec = _gcry_mlkem_get_param_from_bitstrength (nbits, param);
  if (ec)
    {
      return ec;
    }
  if (nbits_p != NULL)
    {
      switch (param->id)
        {
        case GCRY_MLKEM_512:
          {
            *nbits_p = 128;
            break;
          }
        case GCRY_MLKEM_768:
          {
            *nbits_p = 192;
            break;
          }
        case GCRY_MLKEM_1024:
          {
            *nbits_p = 256;
            break;
          }
        default:
          {
            ec = GPG_ERR_INV_ARG;
          }
        }
    }

  return ec;
}

static gcry_err_code_t
extract_opaque_mpi_from_sexp (const gcry_sexp_t keyparms,
                              const char *label,
                              unsigned char **data_p,
                              size_t *data_len_p,
                              const u16 * expected_size_bytes_opt,
                              xtry_alloc_func_t alloc_func)
{
  gcry_mpi_t sk     = NULL;
  gpg_err_code_t ec = 0;
  size_t nwritten   = 0;
  size_t data_len = 0;

  *data_p = 0;


  ec = sexp_extract_param (keyparms, NULL, label, &sk, NULL);
  if (ec)
    {
      printf ("error from sexp_extract_param (keyparms)\n");
      goto leave;
    }
  data_len = mpi_get_nbits (sk);
  if(data_len % 8)
  {
      return GPG_ERR_INV_PARAMETER;
  }
  data_len /= 8;
  if (expected_size_bytes_opt
      && mpi_get_nbits (sk) != *expected_size_bytes_opt * 8)
    {
      ec = GPG_ERR_INV_ARG;
      goto leave;
    }
  *data_p = alloc_func (data_len);
  if (*data_p == NULL)
    {
      ec = gpg_err_code_from_syserror ();
      goto leave;
    }
  _gcry_mpi_print (GCRYMPI_FMT_USG, *data_p, data_len, &nwritten, sk);

  if (data_len != nwritten)
    {
      ec = GPG_ERR_INV_ARG;
      goto leave;
    }
  if (data_len_p)
    {
      *data_len_p = data_len;
    }

leave:
  if (sk != NULL)
    {
      _gcry_mpi_release (sk);
    }
  if (ec)
    {
      xfree (*data_p);
      *data_p = 0;
    }
  return ec;
}

/**
 * get the private key binary value from an s-expression. if sk_len_p is non-null, the variable it points to receives the size of the private key. If param is non-null, the variable pointed to by it is used to verify the length of the
 * private key against the expected length based on the parameters.
 */
static gcry_err_code_t
private_key_from_sexp (const gcry_sexp_t keyparms,
                       unsigned char **sk_p,
                       size_t *sk_len_p,
                       const gcry_mlkem_param_t *param)
{
  return extract_opaque_mpi_from_sexp (
      keyparms, "/z", sk_p, sk_len_p, param != NULL ? &param->secret_key_bytes: (u16*) NULL, _gcry_malloc_secure);
}


/**
 * get the ciphertext binary value from an s-expression. if ct_len_p is non-null, the variable it points to receives the size of the ciphertext. If param is non-null, the variable pointed to by it is used to verify the length of the
 * ciphertext against the expected length based on the parameters.
 */
static gcry_err_code_t
ciphertext_from_sexp (const gcry_sexp_t keyparms,
                      unsigned char **ct_p,
                      size_t *ct_len_p,
                      const gcry_mlkem_param_t *param)
{

  return extract_opaque_mpi_from_sexp (
      keyparms, "/c", ct_p, ct_len_p, param != NULL ? &param->ciphertext_bytes: (u16*) NULL, _gcry_malloc);
}


/**
 * get the public key binary value from an s-expression. if pk_len_p is non-null, the variable it points to receives the size of the public key. If param is non-null, the variable pointed to by it is used to verify the length of the
 * public key against the expected length based on the parameters.
 */
static gcry_err_code_t
public_key_from_sexp (const gcry_sexp_t keyparms,
                      unsigned char **pk_p,
                      size_t *pk_len_p,
                      const gcry_mlkem_param_t *param)
{

  return extract_opaque_mpi_from_sexp (
      keyparms, "/y", pk_p, pk_len_p, param != NULL ? &param->public_key_bytes : (u16*) NULL, _gcry_malloc);
}


static gcry_err_code_t
mlkem_check_secret_key (gcry_sexp_t keyparms)
{

  gpg_err_code_t ec = 0;
  unsigned char shared_secret_1[GCRY_MLKEM_SSBYTES],
      shared_secret_2[GCRY_MLKEM_SSBYTES];
  unsigned char *private_key = NULL, *ciphertext = NULL;
  unsigned char *public_key     = NULL;
  size_t private_key_size_bytes = 0;

  gcry_mlkem_param_t param;

  /* Extract the key MPI from the SEXP.  */
  ec = private_key_from_sexp (keyparms, &private_key, &private_key_size_bytes, NULL);
  if (ec)
    {
      goto leave;
    }
  ec = mlkem_params_from_private_key_size (
      private_key_size_bytes, &param, NULL);
  if (ec)
    {
      goto leave;
    }

  ciphertext = xtrymalloc (param.ciphertext_bytes);
  if (!ciphertext)
    {
      ec = GPG_ERR_SELFTEST_FAILED;
      goto leave;
    }

  public_key
      = private_key
        + param
              .indcpa_secret_key_bytes; /* offset of public key in private key */
  ec = _gcry_mlkem_kem_enc (ciphertext, shared_secret_1, public_key, &param);
  if (ec)
    {
      goto leave;
    }
  ec = _gcry_mlkem_kem_dec (shared_secret_2, ciphertext, private_key, &param);
  if (ec)
    {
      goto leave;
    }

  if (!buf_eq_const (
          shared_secret_1, shared_secret_2, sizeof (shared_secret_1)))
    {
      ec = GPG_ERR_BAD_SECKEY;
      goto leave;
    }

leave:

  xfree (ciphertext);
  xfree (private_key);
  return ec;
}


static gcry_err_code_t
mlkem_generate (const gcry_sexp_t genparms, gcry_sexp_t *r_skey)
{
  gpg_err_code_t ec = 0;

  byte *pk = 0, *sk = 0;
  unsigned int nbits;
  gcry_mlkem_param_t param;
  gcry_mpi_t sk_mpi = NULL, pk_mpi = NULL;

  ec = mlkem_params_from_key_param (genparms, &param, &nbits);
  if (ec)
    {
      goto leave;
    }
  ec = _gcry_pk_util_get_nbits (genparms, &nbits);
  if (!(sk = xtrymalloc_secure (param.secret_key_bytes))
      || !(pk = xtrymalloc (param.public_key_bytes)))
    {
      ec = gpg_err_code_from_syserror ();
      goto leave;
    }
  ec = _gcry_mlkem_kem_keypair (pk, sk, &param);
  if(ec)
  {
      goto leave;
  }

  sk_mpi = _gcry_mpi_set_opaque_copy (sk_mpi, sk, param.secret_key_bytes * 8);
  pk_mpi = _gcry_mpi_set_opaque_copy (pk_mpi, pk, param.public_key_bytes * 8);

#if 0
  // debug code ===>
  //
   {
  unsigned char dbg_buf [10000];
  size_t written;

    _gcry_mpi_print(GCRYMPI_FMT_HEX, dbg_buf, sizeof(dbg_buf), &written, pk_mpi);
    dbg_buf[written + 1] = 0;
  printf("mlkem_generate(): public key mpi = %s\n", dbg_buf);
   }
  // <=== debug code
#endif

  if (!ec)
    {
      ec = sexp_build (r_skey,
                       NULL,
                       "(key-data"
                       " (public-key"
                       "  (mlkem(y%M) ))"
                       " (private-key"
                       "  (mlkem(y%M)(z%M) )))",
                       pk_mpi,
                       pk_mpi,
                       sk_mpi,
                       NULL);
      // dbg code ===>
#if 0
      {
      char buf[10000];
    _gcry_sexp_sprint(r_skey, GCRYSEXP_FMT_DEFAULT, buf, sizeof(buf));
    printf("mlkem_generate(): s-expr = %s\n", buf);
      }
#endif
    // <=== dbg code
    }
  /* call the key check function for now so that we know that it is working: */
  if(!ec)
  {
    ec = mlkem_check_secret_key (*r_skey);
  }
  if (ec)
    {
      goto leave;
    }
leave:
  _gcry_mpi_release (sk_mpi);
  _gcry_mpi_release (pk_mpi);
  xfree (sk);
  xfree (pk);
  return ec;
}


static gcry_err_code_t
mlkem_encap (gcry_sexp_t *r_ciph,
             gcry_sexp_t *r_shared_key,
             gcry_sexp_t keyparms)
{

  gpg_err_code_t ec         = 0;
  unsigned char *ciphertext = NULL, *public_key = NULL, *shared_secret = NULL;
    size_t public_key_size_bytes;
    size_t bit_strength;
  gcry_mlkem_param_t param;


  /* Extract the public key MPI from the SEXP.  */
  ec = public_key_from_sexp (keyparms, &public_key, &public_key_size_bytes, NULL);
  if (ec)
    {
      goto leave;
    }
  bit_strength = bitstrength_from_public_size_bytes(public_key_size_bytes);
  if(!bit_strength)
  {
     ec = GPG_ERR_INV_PARAMETER;
     goto leave;
  }

  ec = _gcry_mlkem_get_param_from_bitstrength(bit_strength, &param);
  if (ec)
    {
      goto leave;
    }


  shared_secret = xtrymalloc_secure (GCRY_MLKEM_SSBYTES);

  if (!shared_secret)
    {
      ec = gpg_err_code_from_syserror ();
      goto leave;
    }

  ciphertext = xtrymalloc (param.ciphertext_bytes);

  ec = _gcry_mlkem_kem_enc (ciphertext, shared_secret, public_key, &param);
  if (ec)
    {
      goto leave;
    }


  ec = sexp_build (r_shared_key,
                   NULL,
                   "(value %b)",
                   (int)GCRY_MLKEM_SSBYTES,
                   shared_secret);
  if (ec)
    {
      goto leave;
    }

  ec = sexp_build (r_ciph,
                   NULL,
                   "(ciphertext (mlkem(c %b)))",
                   (int)param.ciphertext_bytes,
                   ciphertext);

leave:
  xfree (shared_secret);
  xfree (public_key);
  xfree (ciphertext);
  return ec;
}


static gcry_err_code_t
mlkem_decrypt (gcry_sexp_t *r_plain, gcry_sexp_t s_data, gcry_sexp_t keyparms)
{
  gcry_mlkem_param_t param;
  gpg_err_code_t ec          = 0;
  unsigned char *private_key = NULL, *ciphertext = NULL, *shared_secret = NULL;
  size_t private_key_size_bytes;
  unsigned bit_strength;

  shared_secret = xtrymalloc_secure (GCRY_MLKEM_SSBYTES);

  if (!shared_secret)
    {
      ec = gpg_err_code_from_syserror ();
      goto leave;
    }


  /* Extract the key MPI from the SEXP.  */
  ec = private_key_from_sexp (keyparms, &private_key, &private_key_size_bytes, NULL);
  if (ec)
    {
      goto leave;
    }

  bit_strength = bitstrength_from_private_size_bytes(private_key_size_bytes);
  if(!bit_strength)
  {
      ec = GPG_ERR_INV_PARAMETER;
      goto leave;
  }

  ec = _gcry_mlkem_get_param_from_bitstrength(bit_strength, &param);
  if (ec)
    {
      goto leave;
    }


  /* Extract the key Ciphertext from the SEXP.  */

  ec = ciphertext_from_sexp (s_data, &ciphertext, NULL, &param);
  if (ec)
    {
      goto leave;
    }

  /* perform the decryption */
  ec = _gcry_mlkem_kem_dec (shared_secret, ciphertext, private_key, &param);
  if (ec)
    {
      goto leave;
    }

  ec = sexp_build (
      r_plain, NULL, "(value %b)", (int)GCRY_MLKEM_SSBYTES, shared_secret);
leave:
  xfree (shared_secret);
  xfree (ciphertext);
  xfree (private_key);
  return ec;
}


static unsigned int
mlkem_get_nbits (gcry_sexp_t parms)
{
  gcry_sexp_t l1;
  unsigned int bit_strength, bit_length;
  gcry_mpi_t p;
  //unsigned char* dbg_buf;
  //size_t dbg_buf_size;
  l1 = sexp_find_token (parms, "y", 1);
  if (!l1)
    return 0; /* Parameter N not found.  */

  p = sexp_nth_mpi (l1, 1, GCRYMPI_FMT_OPAQUE);

  // debug code ===>
#if 0
    _gcry_mpi_aprint(GCRYMPI_FMT_HEX, &dbg_buf, &dbg_buf_size, p);
  printf("mlkem_get_nbits: public key = %s\n", dbg_buf);
#endif
  // <=== debug code
  sexp_release (l1);
  bit_length = p? mpi_get_nbits (p) : 0;
  _gcry_mpi_release (p);
  bit_strength = bitstrength_from_public_size_bytes((bit_length + 7) / 8);
  return bit_strength;
}

static gpg_err_code_t
compute_keygrip (gcry_md_hd_t md, gcry_sexp_t keyparam)
{
  gcry_sexp_t l1;
  const char *data;
  size_t datalen;

  l1 = sexp_find_token (keyparam, "y", 1);
  if (!l1)
    return GPG_ERR_NO_OBJ;

  data = sexp_nth_data (l1, 1, &datalen);
  if (!data)
    {
      sexp_release (l1);
      return GPG_ERR_NO_OBJ;
    }

  _gcry_md_write (md, data, datalen);
  sexp_release (l1);

  return 0;
}



static const char *mlkem_names[] = {
    "mlkem",
    "openpgp-mlkem", /* ? leave? */
    NULL,
};

gcry_pk_spec_t _gcry_pubkey_spec_mlkem = {
    GCRY_PK_MLKEM,
    {0, 1},
    (GCRY_PK_USAGE_ENCAP),
    "ML-KEM-ipd", /* following the naming scheme given at https://github.com/ietf-wg-pquip/state-of-protocols-and-pqc#user-content-algorithm-names */
    mlkem_names,
    "y",
    "z",
    "a",
    "",
    "y", /* elements of pub-key, sec-key, ciphertext, signature, key-grip */
    mlkem_generate,
    mlkem_check_secret_key,
    NULL, /* encrypt */
    mlkem_encap,
    mlkem_decrypt,
    NULL, /* sign */
    NULL, /* verify */
    mlkem_get_nbits,
    NULL, /* run_selftests */
    compute_keygrip, /* compute_keygrip */
    NULL, /* get_curve */
    NULL  /* get_curve_param */
};
