
#include <config.h>
#include <stdio.h>

//#include "gcrypt.h"
#include "kyber-common.h"

#include "g10lib.h"
//#include "mpi.h"
#include "cipher.h"
#include "pubkey-internal.h"
#include "kyber_verify.h"

//TODOMTG: key size for key gen: public key bit size

/*
 * Kyber params used in code:
 * - fixed: N, Q, POLYBYTES, ETA2, SYMBYTES, SBYTES, KYBER_INDCPA_MSGBYTES
 * - dynamic:
 *   - K
 *   - ETA1
 *   - KYBER_POLYCOMPRESSEDBYTES
 *   - KYBER_POLYVECCOMPRESSEDBYTES
 *   - KYBER_INDCPA_PUBLICKEYBYTES
 *   - KYBER_INDCPA_SECRETKEYBYTES
 *   - KYBER_INDCPA_BYTES
 *   - KYBER_SECRETKEYBYTES
 *   - KYBER_CIPHERTEXTBYTES
 *   - KYBER_PUBLICKEYBYTES
 *
 */


static gcry_err_code_t get_kyber_param_from_bit_size(size_t nbits, gcry_kyber_param_t* param )
{
  switch (nbits)
  {
    case 512:
        param->id = GCRY_KYBER_512;
        param->k = 2;
        param->eta1 = 3;
        param->poly_compressed_bytes = 128;
        param->polyvec_compressed_bytes = param->k * 320;
        break;
    case 768:
        param->id = GCRY_KYBER_768;
        param->k = 3;
        param->eta1 = 2;
        param->poly_compressed_bytes = 128;
        param->polyvec_compressed_bytes = param->k * 320;
        break;
    case 1024:
        param->id = GCRY_KYBER_1024;
        param->k = 4;
        param->eta1 = 2;
        param->poly_compressed_bytes = 160;
        param->polyvec_compressed_bytes = param->k * 352;
        break;
    default:
      return GPG_ERR_INV_ARG;
  }

  param->polyvec_bytes = param->k * GCRY_KYBER_POLYBYTES;
  param->public_key_bytes = param->polyvec_bytes + KYBER_SYMBYTES;
  param->indcpa_secret_key_bytes = param->polyvec_bytes;
  param->ciphertext_bytes = param->poly_compressed_bytes + param->polyvec_compressed_bytes;
  param->secret_key_bytes = param->indcpa_secret_key_bytes + param->public_key_bytes + 2*KYBER_SYMBYTES;

  return 0;

}


static gcry_err_code_t
kyber_generate (const gcry_sexp_t genparms, gcry_sexp_t * r_skey)
{
    gpg_err_code_t ec = 0;

    /*uint8_t pk[CRYPTO_PUBLICKEYBYTES];
      uint8_t sk[CRYPTO_SECRETKEYBYTES];*/
    uint8_t * pk = 0, * sk = 0;
    unsigned int nbits;
    gcry_kyber_param_t param;
    ec = _gcry_pk_util_get_nbits (genparms, &nbits);
    if (ec)
    {
        return ec;
    }
    if((ec = get_kyber_param_from_bit_size(nbits, &param)))
    {
        return ec;
    }
    if(!(sk = xtrymalloc_secure(param.secret_key_bytes)) || !(pk = xtrymalloc(param.public_key_bytes)))
    {
        ec = gpg_err_code_from_syserror ();
        goto leave;
    }
    crypto_kem_keypair (pk, sk, &param);

    gcry_mpi_t sk_mpi = NULL, pk_mpi = NULL;
    //sk_mpi = mpi_new (0);
    //pk_mpi = mpi_new (0);
    sk_mpi = _gcry_mpi_set_opaque_copy (sk_mpi, sk, CRYPTO_SECRETKEYBYTES * 8);
    pk_mpi = _gcry_mpi_set_opaque_copy (pk_mpi, pk, CRYPTO_PUBLICKEYBYTES * 8);

    if (!ec)
    {
        ec = sexp_build (r_skey, NULL,
                "(key-data"
                " (public-key"
                "  (kyber(p%m) (nbits%u)))"
                " (private-key"
                "  (kyber(s%m) (nbits%u))))", pk_mpi, nbits, sk_mpi, nbits, NULL);
        //"  (kyber(s%m)))" " %S)", pk_mpi, sk_mpi);

    }
leave:
    _gcry_mpi_release(sk_mpi);
    _gcry_mpi_release(pk_mpi);
    xfree(sk);
    xfree(pk);
    return ec;
}


static gcry_err_code_t
kyber_check_secret_key (gcry_sexp_t keyparms)
{
  keyparms = keyparms;
  gpg_err_code_t ec = 0;
  return ec;
}


static gcry_err_code_t
kyber_encap (gcry_sexp_t * r_ciph, gcry_sexp_t * r_shared_key,
             gcry_sexp_t keyparms)
{

    gpg_err_code_t ec = 0;
    unsigned char shared_secret[KYBER_SSBYTES];
    //unsigned char shared_secret_str[KYBER_SSBYTES*2+5];
    unsigned char ciphertext[KYBER_CIPHERTEXTBYTES];
    //unsigned char ciphertext_str[KYBER_CIPHERTEXTBYTES*2+5];
    unsigned char public_key[KYBER_SECRETKEYBYTES];
    unsigned char public_key_str[KYBER_SECRETKEYBYTES*2+5];

    gcry_mpi_t pk = NULL;
    size_t nwritten = 0;
    unsigned int nbits;

    /* Extract the key MPI from the SEXP.  */
    ec = sexp_extract_param (keyparms, NULL, "/p",
            &pk,
            NULL);
    if (ec)
    {
        printf("error from sexp_extract_param (keyparms)\n");
        goto leave;
    }

    gcry_kyber_param_t param;
    ec = _gcry_pk_util_get_nbits (keyparms, &nbits);
    if (ec)
    {
        // TODO: PROPER CLEANUP ?
        return ec;
    }
    if((ec = get_kyber_param_from_bit_size(nbits, &param)))
    {
        // TODO: PROPER CLEANUP ?
        return ec;
    }

    if(mpi_get_nbits(pk) != KYBER_PUBLICKEYBYTES*8)
    {
        printf("error: mpi_get_nbits(sk) != KYBER_PUBLICKEYBYTES*8");
    }

    _gcry_mpi_print(GCRYMPI_FMT_USG, public_key, sizeof(public_key), &nwritten, pk);
    if(nwritten != KYBER_PUBLICKEYBYTES)
    {
        printf("nwritten != KYBER_PUBLICKEYBYTES\n");
    }

    _gcry_mpi_print(GCRYMPI_FMT_HEX, public_key_str, sizeof(public_key_str), &nwritten, pk);
    /*if(nwritten != KYBER_SECRETKEYBYTES*2+1)
      {
      printf("nwritten != KYBER_SECRETKEYBYTES*2+1\n");
      }*/
    //printf("kyber public_key used to decrypt: %s\n", public_key_str);
    _gcry_mpi_release(pk);

    kyber_kem_enc(ciphertext, shared_secret, public_key, &param);


    ec = sexp_build (r_shared_key, NULL, "(value %b)", (int)KYBER_SSBYTES, shared_secret);
    if(ec)
    {
        goto leave;
    }

    ec = sexp_build (r_ciph, NULL, "(ciphertext (kyber(c %b)))", (int)KYBER_CIPHERTEXTBYTES, ciphertext);

leave:
    return ec;
}


static gcry_err_code_t
kyber_decrypt (gcry_sexp_t * r_plain, gcry_sexp_t s_data,
               gcry_sexp_t keyparms)
{
    gpg_err_code_t ec = 0;
    unsigned char shared_secret[KYBER_SSBYTES];
    //unsigned char shared_secret_str[KYBER_SSBYTES*2+5];
    unsigned char ciphertext[KYBER_CIPHERTEXTBYTES];
    unsigned char ciphertext_str[KYBER_CIPHERTEXTBYTES*2+5];
    unsigned char private_key[KYBER_SECRETKEYBYTES];
    unsigned char private_key_str[KYBER_SECRETKEYBYTES*2+5];

    gcry_mpi_t sk = NULL;
    gcry_mpi_t ct = NULL;
    size_t nwritten = 0;

    unsigned int nbits;
    /* Extract the key MPI from the SEXP.  */
    ec = sexp_extract_param (keyparms, NULL, "/s",
            &sk,
            NULL);
    if (ec)
    {
        printf("error from sexp_extract_param (keyparms)\n");
        goto leave;
    }

    if(mpi_get_nbits(sk) != KYBER_SECRETKEYBYTES*8)
    {
        printf("error: mpi_get_nbits(sk) != KYBER_SECRETKEYBYTES*8");
    }


    /* Extract the key Ciphertext from the SEXP.  */
    ec = sexp_extract_param (s_data, NULL, "/c",
            &ct,
            NULL);
    if (ec)
        goto leave;
    if(mpi_get_nbits(ct) != KYBER_CIPHERTEXTBYTES*8)
        printf("error: mpi_get_nbits(ct) != KYBER_CIPHERTEXTBYTES*8\n");

    gcry_kyber_param_t param;
    ec = _gcry_pk_util_get_nbits (keyparms, &nbits);
    if (ec)
    {
        // TODO: PROPER CLEANUP
        return ec;
    }
    if((ec = get_kyber_param_from_bit_size(nbits, &param)))
    {
        // TODO: PROPER CLEANUP
        return ec;
    }
    // extract the byte arrays from the MPIs:


    _gcry_mpi_print(GCRYMPI_FMT_USG, ciphertext, sizeof(ciphertext), &nwritten, ct);
    if(nwritten != KYBER_CIPHERTEXTBYTES)
    {
        printf("%zul = nwritten != KYBER_CIPHERTEXTBYTES = %ul\n", nwritten, KYBER_CIPHERTEXTBYTES);
        goto leave;
    }
    _gcry_mpi_print(GCRYMPI_FMT_HEX, ciphertext_str, sizeof(ciphertext_str), &nwritten, ct);
    _gcry_mpi_release(ct);
    /*if(nwritten != KYBER_CIPHERTEXTBYTES*2+1)
      {
      printf("%u = nwritten != KYBER_CIPHERTEXTBYTES = %u\n", nwritten, KYBER_CIPHERTEXTBYTES);
      goto leave;
      }*/
    //printf("kyber ciphertext to decrypt: %s\n", ciphertext_str);


    _gcry_mpi_print(GCRYMPI_FMT_USG, private_key, sizeof(private_key), &nwritten, sk);
    if(nwritten != KYBER_SECRETKEYBYTES)
    {
        printf("nwritten != KYBER_SECRETKEYBYTES\n");
    }

    _gcry_mpi_print(GCRYMPI_FMT_HEX, private_key_str, sizeof(private_key_str), &nwritten, sk);
    /*if(nwritten != KYBER_SECRETKEYBYTES*2+1)
      {
      printf("nwritten != KYBER_SECRETKEYBYTES*2+1\n");
      }*/
    //printf("kyber private_key used to decrypt: %s\n", private_key_str);
    _gcry_mpi_release(sk);


    // ========== perform the decryption ===============
    if((ec = crypto_kem_dec(shared_secret, ciphertext, private_key, &param)))
    {
        goto leave;
    }

    ec = sexp_build (r_plain, NULL, "(value %b)", (int)KYBER_SSBYTES, shared_secret);
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
