/* kyber-test.c - Test the Crystals-Kyber KEM algorithm
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

#include "gcrypt.h"
#ifdef HAVE_CONFIG_H
# include <config.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>


#if 0
#ifdef _GCRYPT_IN_LIBGCRYPT
# include "../src/gcrypt-int.h"
#else
# include <gcrypt.h>
#endif
#endif


#define PGM "kyber-test"
#include "t-common.h"
//#define N_TESTS 120

// test-utils.h must be included after t-common.h
#include "test-utils.h"

static void test_hex_decoding()
{
  const char* hex1 = "value = FF00a0";
  const char* hex2 = "value=FF00a0";
  const char* hex_arr[] = {hex1, hex2};
  const unsigned char exp_result[] = { 255, 0, 160 };
  size_t bin_len;

  for(unsigned i = 0; i < 2; i++)
  {
    unsigned char * buffer = fill_bin_buf_from_hex_line(&bin_len, '=', hex_arr[i], 0);
    if(bin_len != sizeof(exp_result) || memcmp(exp_result, buffer, bin_len))
    {
      fail("error with kyber hex decoding test");
    }
    xfree(buffer);

  }
  info ("success: kyber hex decoding test\n");
}

typedef struct {
  const char* index;
  unsigned char* result_buf;
  size_t result_buf_len;
} test_vec_desc_entry;

//static void read_test_vector()

static void check_kyber_kat(const char * fname)
{
  const size_t nb_kat_tests = 1;
  FILE *fp;
  int lineno = 0;
  char *line;
  //unsigned char* public_key = NULL, *private_key = , *ciphertext, *shared_secret;
  //size_t public_key_len, private_key_len, ciphertext_len, shared_secret_len;

  info ("Checking Kyber KAT.\n");

  fp = fopen (fname, "r");
  if (!fp)
    die ("error opening '%s': %s\n", fname, strerror (errno));

  enum {
    public_key_idx = 0,
    privat_key_idx = 1,
    ciphertext_idx = 2,
    shared_secret_idx = 3
  } ;
  test_vec_desc_entry test_vec[] =
  {
    {
      "Public Key:",
      NULL,
      0,
    },
    {
      "Secret Key:",
      NULL,
      0,
    },
    {
      "Ciphertext:",
      NULL,
      0,
    },
    {
      "Shared Secret A:",
      NULL,
      0,
    }
  };

 size_t test_count = 0;
  gcry_sexp_t public_key_sx = NULL, private_key_sx = NULL, ciphertext_sx = NULL, shared_secret_expected_sx = NULL, shared_secret_sx = NULL;
  while ((line = read_textline (fp, &lineno)) && !(nb_kat_tests && nb_kat_tests <= test_count ))
  {
      gcry_sexp_t l;
      gcry_mpi_t ss_expected, ss;
      int have_flags;
      int rc;
      for(unsigned i = 0; i < sizeof(test_vec)/sizeof(test_vec[0]); i++)
      {
          test_vec_desc_entry *e = &test_vec[i];
          if(!strncmp (line, e->index, strlen(e->index)))
          {
              if(e->result_buf != NULL)
              {
                  fail("trying to set test vector element twice");
              }
              e->result_buf = fill_bin_buf_from_hex_line(&e->result_buf_len, ':', line, lineno);
              break;
          }
          else if(!strncmp (line, "#", 1) || !strncmp(line, "Shared Secret B:", 15))
          {
              continue;
          }
          /*else // cannot fail here because kyber test vectors as generated by reference implementation contain random seeds without prefix
            {
            fail ("unknown tag at input line %d", lineno);
            }*/
      }

      // check if we completed one test vector:
      int is_complete = 1;
      for(unsigned i = 0; i < sizeof(test_vec)/sizeof(test_vec[0]); i++)
      {
          is_complete &= (test_vec[i].result_buf != NULL);
      }
      if(!is_complete)
      {
          printf("line '%s' does NOT complete a test vector\n", line);
          xfree (line);
          continue;
      }
      else
      {
          printf("line '%s' COMPLETES a test vector\n", line);
      }
      test_count++;
      gcry_error_t err;
      err = gcry_sexp_build (&private_key_sx, NULL,
              "(private-key (kyber (s %b)))",
              (int)test_vec[privat_key_idx].result_buf_len, test_vec[privat_key_idx].result_buf
              );
      if (err)
      {
          fail ("error building private key SEXP for test, %s: %s",
                  "sk", gpg_strerror (err));
          goto leave;
      }
      printf("private key sx directly after building:\n");
      gcry_sexp_dump(private_key_sx);
      char print_buf[100000];
      gcry_sexp_sprint(private_key_sx, GCRYSEXP_FMT_ADVANCED, print_buf, sizeof(print_buf)-1);
      printf("private_key_sx: %s", print_buf);
#if 0
      err = gcry_sexp_build (&public_key_sx, NULL,
              "(public-key (kyber(p %b)))",
              (int)test_vec[public_key_idx].result_buf_len, test_vec[public_key_idx].result_buf
              );
      if (err)
      {
          fail ("error building public key SEXP for test, %s: %s",
                  "pk", gpg_strerror (err));
          goto leave;
      }
#endif


      err = gcry_sexp_build (&shared_secret_expected_sx, NULL,
              "(data (value %b))",
              (int)test_vec[shared_secret_idx].result_buf_len, test_vec[shared_secret_idx].result_buf
              );
      if (err)
      {
          fail ("error building expected shared secret SEXP for test, %s: %s",
                  "pk", gpg_strerror (err));
          goto leave;
      }

      l = gcry_sexp_find_token (shared_secret_expected_sx, "value", 0);
      ss_expected = gcry_sexp_nth_mpi (l, 1, GCRYMPI_FMT_USG);
      gcry_sexp_release (l);

      err = gcry_sexp_build (&ciphertext_sx, NULL,
              "(ciphertext (kyber(c %b)))",
              (int)test_vec[ciphertext_idx].result_buf_len, test_vec[ciphertext_idx].result_buf
              );
      if (err)
      {
          fail ("error building ciphertext SEXP for test, %s: %s",
                  "pk", gpg_strerror (err));
          goto leave;
      }

      l = gcry_sexp_find_token (ciphertext_sx, "flags", 0);
      have_flags = !!l;
      gcry_sexp_release (l);


      l = gcry_sexp_find_token (ciphertext_sx, "flags", 0);
      rc = gcry_pk_decrypt(&shared_secret_sx, ciphertext_sx, private_key_sx);
      if(rc)
      {
        die ("decryption failed: %s\n", gcry_strerror (rc));
      }

      l = gcry_sexp_find_token (shared_secret_sx, "value", 0);
      if (l)
      {
          if (!have_flags)
          {
              printf("compatibility mode of pk_decrypt broken: !have_flags\n");
              //die ("compatibility mode of pk_decrypt broken: !have_flags\n");
          }
          ss = gcry_sexp_nth_mpi (l, 1, GCRYMPI_FMT_USG);
          gcry_sexp_release (l);
      }
      else
      {
          if (have_flags)
              die ("compatibility mode of pk_decrypt broken: have_flags is true\n");
          ss = gcry_sexp_nth_mpi (shared_secret_sx, 0, GCRYMPI_FMT_USG);
      }
      if(!ss)
      {
        die("ss = NULL\n");
      }
      if(!ss_expected)
      {
        die("ss_expected = NULL\n");
      }

      /* Compare.  */
      if (gcry_mpi_cmp (ss_expected, ss))
      {
          die ("error with decryption result\n");
      }
      printf("decryption correct\n");


      xfree (line);
      for(unsigned i = 0; i < sizeof(test_vec)/sizeof(test_vec[0]); i++)
      {
          test_vec_desc_entry *e = &test_vec[i];
          if(e->result_buf)
          {
            xfree(e->result_buf);
          }
          e->result_buf = NULL;
          e->result_buf_len = 0;
      }

      gcry_sexp_release(public_key_sx);
      public_key_sx = NULL;
      gcry_sexp_release(private_key_sx);
      private_key_sx = NULL;
      gcry_sexp_release(ciphertext_sx);
      ciphertext_sx = NULL;
      gcry_sexp_release(shared_secret_sx);
      shared_secret_sx = NULL;
      gcry_sexp_release(shared_secret_expected_sx);
      shared_secret_expected_sx = NULL;
      gcry_mpi_release(ss_expected);
      ss_expected = NULL;
      gcry_mpi_release(ss);
      ss = NULL;


  }
  xfree (line);
leave:
  line = line;
  /*gcry_sexp_release(public_key_sx);
  gcry_sexp_release(private_key_sx);
  gcry_sexp_release(ciphertext_sx);
  gcry_sexp_release(shared_secret_sx);*/
}

int
main (int argc, char **argv)
{

    int last_argc = -1;
    char *fname = NULL;

    if (argc)
    { argc--; argv++; }

    while (argc && last_argc != argc )
    {
        last_argc = argc;
        if (!strcmp (*argv, "--"))
        {
            argc--; argv++;
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
            argc--; argv++;
        }
        else if (!strcmp (*argv, "--debug"))
        {
            verbose += 2;
            debug++;
            argc--; argv++;
        }
        else if (!strcmp (*argv, "--data"))
        {
            argc--; argv++;
            if (argc)
            {
                xfree (fname);
                fname = xstrdup (*argv);
                argc--; argv++;
            }
        }
        else if (!strncmp (*argv, "--", 2))
            die ("unknown option '%s'", *argv);

    }

    if (!fname)
        fname = prepend_srcdir("kyber768_ref.inp");

    test_hex_decoding();
    check_kyber_kat(fname);
    xfree(fname);
}
