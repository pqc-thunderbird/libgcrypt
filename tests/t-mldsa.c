/* t-mldsa.c - Test the Crystals-ML-DSA Signature algorithm
 * Copyright (C) 2011 Free Software Foundation, Inc.
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


#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "gcrypt.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>


#define PGM "t-mldsa"
#include "t-common.h"

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>

#define pass()                                                                                                         \
  do                                                                                                                   \
    {                                                                                                                  \
      ;                                                                                                                \
    }                                                                                                                  \
  while (0)


/* Prepend FNAME with the srcdir environment variable's value and
 * return an allocated filename.  */
char *prepend_srcdir (const char *fname)
{
  static const char *srcdir;
  char *result;

  if (!srcdir && !(srcdir = getenv ("srcdir")))
    srcdir = ".";

  result = xmalloc (strlen (srcdir) + 1 + strlen (fname) + 1);
  strcpy (result, srcdir);
  strcat (result, "/");
  strcat (result, fname);
  return result;
}

/* Read next line but skip over empty and comment lines.  Caller must
   xfree the result.  */
static char *read_textline (FILE *fp, int *lineno)
{
  char line[40000];
  char *p;

  do
    {
      if (!fgets (line, sizeof line, fp))
        {
          if (feof (fp))
            return NULL;
          die ("error reading input line: %s\n", strerror (errno));
        }
      ++*lineno;
      p = strchr (line, '\n');
      if (!p)
        die ("input line %d not terminated or too long\n", *lineno);
      *p = 0;
      for (p--; p > line && my_isascii (*p) && isspace (*p); p--)
        *p = 0;
    }
  while (!*line || *line == '#');
  /* if (debug) */
  /*   info ("read line: '%s'\n", line); */
  return xstrdup (line);
}

/**
 * Convert STRING consisting of hex characters into its binary
 * representation and return it as an allocated buffer.
 *
 * @param string in hex string to convert. The string is delimited by end of string.
 * @param r_length out pointer to the resulting (returned) buffer length.
 *
 * @return pointer to hex decoded binary. The function returns NULL on error.
 **/
static void *hex2buffer (const char *string, size_t *r_length)
{
  const char *s;
  unsigned char *buffer;
  size_t length;
  size_t str_len = strlen (string);
  *r_length      = 0;
  if (str_len % 2)
    {
      return NULL;
    }
  buffer = xmalloc (strlen (string) / 2 + 1);
  length = 0;
  for (s = string; *s; s += 2)
    {
      if (!hexdigitp (s) || !hexdigitp (s + 1))
        {
          xfree (buffer);
          return NULL; /* Invalid hex digits. */
        }
      ((unsigned char *)buffer)[length++] = xtoi_2 (s);
    }
  *r_length = length;
  return buffer;
}

/* Copy the data after the tag to BUFFER.  BUFFER will be allocated as
   needed.  */
static unsigned char *fill_bin_buf_from_hex_line (size_t *r_length, const char tag_char, const char *line, int lineno)
{
  const char *s;


  s = strchr (line, tag_char);
  if (!s)
    {
      fail ("syntax error at input line %d", lineno);
      return NULL;
    }
  s++;
  while (strlen (s) && s[0] == ' ')
    {
      s++;
    }
  /*for (s++; my_isascii (*s) && isspace (*s); s++)
    ;
  *buffer = xstrdup (s);*/
  return hex2buffer (s, r_length);
}


const char MLDSA_MESSAGE_TMPL[] = "(data (flags raw_opaque) (value %b))";

static int check_mldsa_roundtrip (size_t n_tests)
{
  const char *mldsa_name[] = {"ML-DSA-44", "ML-DSA-65", "ML-DSA-87"};
  unsigned mldsa_nbits[]   = {10496, 15616, 20736};

  int rc;

  for (size_t iteration = 0; iteration < n_tests; iteration++)
    for (int i = 0; i < sizeof (mldsa_name) / sizeof (mldsa_name[0]); i++)
      {
        gcry_sexp_t skey    = NULL;
        gcry_sexp_t pkey    = NULL;
        gcry_sexp_t keyparm = NULL;
        gcry_sexp_t key     = NULL;
        gcry_sexp_t l       = NULL;

        gcry_sexp_t r_sig        = NULL;
        gcry_sexp_t s_data       = NULL;
        gcry_sexp_t s_data_wrong = NULL;

        unsigned char *msg = NULL;
        unsigned msg_len;

        if (verbose)
          info ("creating %s key\n", mldsa_name[i]);

        rc = gcry_sexp_build (&keyparm, NULL, "(genkey (mldsa-ipd (nbits%u)))", mldsa_nbits[i], NULL);

        if (rc)
          die ("error creating S-expression: %s\n", gpg_strerror (rc));
        rc = gcry_pk_genkey (&key, keyparm);

        if (rc)
          die ("error generating ML-DSA key: %s\n", gpg_strerror (rc));


        pkey = gcry_sexp_find_token (key, "public-key", 0);
        if (!pkey)
          {
            die ("public part missing in return value\n");
          }

        skey = gcry_sexp_find_token (key, "private-key", 0);
        if (!skey)
          die ("private part missing in return value\n");


        /* sign random message of length 1..16384 */
        gcry_randomize (&msg_len, sizeof (unsigned), GCRY_WEAK_RANDOM);
        msg_len = 1 + (msg_len % 16384);
        msg     = xmalloc (msg_len);
        if (!msg)
          {
            die ("error allocating msg buf");
          }
        gcry_randomize (msg, msg_len, GCRY_WEAK_RANDOM);

        rc = gcry_sexp_build (&s_data, NULL, MLDSA_MESSAGE_TMPL, msg_len, msg, NULL);
        if (rc)
          {
            die ("error generating data sexp");
          }

        rc = gcry_pk_sign (&r_sig, s_data, skey);
        if (rc)
          die ("sign failed\n");

        printf ("verifying correct %s-signature, iteration %ld/%ld\n", mldsa_name[i], iteration + 1, n_tests);
        rc = gcry_pk_verify (r_sig, s_data, pkey);
        if (rc)
          die ("verify failed\n");
        printf ("... ok!\n");

        /* now verify against a wrong msg */
        msg[0]--;
        printf ("verifying wrong signature\n");
        rc = gcry_sexp_build (&s_data_wrong, NULL, MLDSA_MESSAGE_TMPL, msg_len, msg, NULL);
        if (rc)
          {
            die ("error generating data sexp");
          }

        rc = gcry_pk_verify (r_sig, s_data_wrong, pkey);
        if (!rc)
          die ("verify succesful for wrong data\n");
        printf ("... ok!\n");
        rc = 0;

        gcry_sexp_release (skey);
        gcry_sexp_release (pkey);
        gcry_sexp_release (keyparm);
        gcry_sexp_release (key);
        gcry_sexp_release (l);
        xfree (msg);

        gcry_sexp_release (r_sig);
        gcry_sexp_release (s_data);
        gcry_sexp_release (s_data_wrong);
      }

  return rc;
}

typedef struct
{
  const char *index;
  unsigned char *result_buf;
  size_t result_buf_len;
} test_vec_desc_entry;

int check_test_vec_verify (
    unsigned char *pk, unsigned pk_len, unsigned char *m, unsigned m_len, unsigned char *sig, unsigned sig_len)
{
  gcry_err_code_t err;
  gcry_sexp_t public_key_sx;
  gcry_sexp_t signature_sx;
  gcry_sexp_t data_sx;

  err = gcry_sexp_build (
      &public_key_sx, NULL, "(public-key (mldsa-ipd (p %b) (nbits%u) ))", pk_len, pk, pk_len * 8, NULL);
  if (err)
    {
      fail ("error building public key SEXP: %s", gpg_strerror (err));
      goto leave;
    }

  err = gcry_sexp_build (&data_sx, NULL, MLDSA_MESSAGE_TMPL, m_len, m, NULL);

  if (err)
    {
      fail ("error building msg SEXP: %s", gpg_strerror (err));
      goto leave;
    }

  err = gcry_sexp_build (&signature_sx, NULL, "(sig-val(mldsa-ipd(a %b)))", sig_len, sig, NULL);

  if (err)
    {
      fail ("error building msg SEXP: %s", gpg_strerror (err));
      goto leave;
    }

  err = gcry_pk_verify (signature_sx, data_sx, public_key_sx);

leave:
  gcry_sexp_release (public_key_sx);
  gcry_sexp_release (signature_sx);
  gcry_sexp_release (data_sx);
  if (err)
    return 1;
  return 0;
}

static void check_mldsa_kat (const char *fname)
{
  const size_t nb_kat_tests = 0; /* zero means all */
  FILE *fp;
  int lineno = 0;
  char *line;

  enum
  {
    public_key_idx = 0,
    privat_key_idx = 1,
    signature_idx  = 2,
    msg_idx        = 3
  };

  test_vec_desc_entry test_vec[] = {/*{
                                        "count:",
                                        NULL,
                                        0,
                                    },*/
                                    {
                                        "seed",
                                        NULL,
                                        0,
                                    }, /*
                                     {
                                         "mlen:",
                                         NULL,
                                         0,
                                     },*/
                                    {
                                        "msg",
                                        NULL,
                                        0,
                                    },
                                    {
                                        "pk",
                                        NULL,
                                        0,
                                    },
                                    {
                                        "sk",
                                        NULL,
                                        0,
                                    }, /*
                                     {
                                         "smlen:",
                                         NULL,
                                         0,
                                     },*/
                                    {
                                        "sm",
                                        NULL,
                                        0,
                                    }};
  size_t test_count = 0;

  info ("Checking Kyber KAT.\n");

  fname = prepend_srcdir (fname);
  fp    = fopen (fname, "r");
  if (!fp)
    die ("error opening '%s': %s\n", fname, strerror (errno));
  xfree ((void *)fname);

  while ((line = read_textline (fp, &lineno)) && !(nb_kat_tests && nb_kat_tests <= test_count))
    {
      int rc;
      int is_complete = 1;
      unsigned i;
      unsigned random;
      unsigned char *sig;
      unsigned sig_len;
      test_vec_desc_entry *pk;
      test_vec_desc_entry *msg;


      /* read in test vec */
      for (i = 0; i < sizeof (test_vec) / sizeof (test_vec[0]); i++)
        {
          test_vec_desc_entry *e = &test_vec[i];
          if (!strncmp (line, "#", 1) || !strncmp (line, "\n", 1) || !strncmp (line, "count", 5)
              || !strncmp (line, "mlen", 4) || !strncmp (line, "smlen", 5))
            {
              continue;
            }
          else if (!strncmp (line, e->index, strlen (e->index)))
            {
              if (e->result_buf != NULL)
                {
                  fail ("trying to set test vector element twice");
                }
              e->result_buf = fill_bin_buf_from_hex_line (&e->result_buf_len, '=', line, lineno);
              break;
            }
        }

      /* check if we completed one test vector: */
      for (i = 0; i < sizeof (test_vec) / sizeof (test_vec[0]); i++)
        {
          is_complete &= (test_vec[i].result_buf != NULL);
        }
      if (!is_complete)
        {
          xfree (line);
          continue;
        }
      test_count++;

      /* NOTE: sm = (sig | m) since the reference implementation uses the "signed-message" interface -> we extract only
       * the signature */
      sig     = test_vec[4].result_buf;
      sig_len = test_vec[4].result_buf_len - test_vec[1].result_buf_len;
      pk      = &test_vec[2];
      msg     = &test_vec[1];
      rc      = check_test_vec_verify (
          pk->result_buf, pk->result_buf_len, msg->result_buf, msg->result_buf_len, sig, sig_len);
      if (rc)
        die ("Failed to verify KAT test vector");

      /* check that changing m, sig, or pk results in failure*/
      gcry_randomize (&random, sizeof (unsigned), GCRY_WEAK_RANDOM);

      pk->result_buf[random % pk->result_buf_len]--;
      rc = check_test_vec_verify (
          pk->result_buf, pk->result_buf_len, msg->result_buf, msg->result_buf_len, sig, sig_len);
      if (!rc)
        die ("modified KAT test vector should not be verifiable");
      pk->result_buf[random % pk->result_buf_len]++;

      sig[random % sig_len]--;
      rc = check_test_vec_verify (
          pk->result_buf, pk->result_buf_len, msg->result_buf, msg->result_buf_len, sig, sig_len);
      if (!rc)
        die ("modified KAT test vector should not be verifiable");
      sig[random % sig_len]++;

      msg->result_buf[random % msg->result_buf_len]--;
      rc = check_test_vec_verify (
          pk->result_buf, pk->result_buf_len, msg->result_buf, msg->result_buf_len, sig, sig_len);
      if (!rc)
        die ("modified KAT test vector should not be verifiable");
      msg->result_buf[random % msg->result_buf_len]++;

      sig_len--;
      rc = check_test_vec_verify (
          pk->result_buf, pk->result_buf_len, msg->result_buf, msg->result_buf_len, sig, sig_len);
      if (!rc)
        die ("modified KAT test vector should not be verifiable");
      sig_len++;

      pk->result_buf_len--;
      rc = check_test_vec_verify (
          pk->result_buf, pk->result_buf_len, msg->result_buf, msg->result_buf_len, sig, sig_len);
      if (!rc)
        die ("modified KAT test vector should not be verifiable");
      pk->result_buf_len++;

      msg->result_buf_len--;
      rc = check_test_vec_verify (
          pk->result_buf, pk->result_buf_len, msg->result_buf, msg->result_buf_len, sig, sig_len);
      if (!rc)
        die ("modified KAT test vector should not be verifiable");
      msg->result_buf_len++;


      /* cleanup */
      xfree (line);
      for (i = 0; i < sizeof (test_vec) / sizeof (test_vec[0]); i++)
        {
          test_vec_desc_entry *e = &test_vec[i];
          if (e->result_buf)
            {
              xfree (e->result_buf);
            }
          e->result_buf     = NULL;
          e->result_buf_len = 0;
        }

      printf ("Test vector %ld successfully verified\n", test_count);
    }

  printf ("\n");
  xfree (line);
}

int main (int argc, char **argv)
{
  int last_argc = -1;
  char *fname   = NULL;
  if (argc)
    {
      argc--;
      argv++;
    }

  while (argc && last_argc != argc)
    {
      last_argc = argc;
      if (!strcmp (*argv, "--"))
        {
          argc--;
          argv++;
          break;
        }
      else if (!strcmp (*argv, "--help"))
        {
          fputs ("usage: " PGM " [options]\n"
                 "Options:\n"
                 "  --verbose       print timings etc.\n"
                 "  --debug         flyswatter\n"
                 "  --data FNAME    take test data from file FNAME\n",
                 stdout);
          exit (0);
        }
      else if (!strcmp (*argv, "--verbose"))
        {
          verbose++;
          argc--;
          argv++;
        }
      else if (!strcmp (*argv, "--debug"))
        {
          verbose += 2;
          debug++;
          argc--;
          argv++;
        }
      else if (!strcmp (*argv, "--data"))
        {
          argc--;
          argv++;
          if (argc)
            {
              xfree (fname);
              fname = xstrdup (*argv);
              argc--;
              argv++;
            }
        }
      else if (!strncmp (*argv, "--", 2))
        die ("unknown option '%s'", *argv);
    }


  if (fname)
    {
      check_mldsa_kat (fname);
      xfree (fname);
    }
  else
    {
      if (check_mldsa_roundtrip (1000))
        {
          fail ("check_mldsa_roundtrip() yielded an error, aborting");
        }
    }

  printf ("Success.\n");
  return 0;
}
