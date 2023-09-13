/* cshake.c  -  cSHAKE xof hash regression tests
 * Copyright (C) 2001, 2002, 2003, 2005, 2008,
 *               2009 Free Software Foundation, Inc.
 * Copyright (C) 2013 g10 Code GmbH
 * Copyright (C) 2023 MTG AG
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <assert.h>
#ifdef HAVE_STDINT_H
# include <stdint.h> /* uintptr_t */
#elif defined(HAVE_INTTYPES_H)
# include <inttypes.h>
#else
/* In this case, uintptr_t is provided by config.h. */
#endif

//#include "../src/gcrypt-int.h"
//#include "../src/gcrypt-testapi.h"

#define PGM "cSHAKE"
#include "t-common.h"
#include "gcrypt.h"

#if __GNUC__ >= 4
#  define ALWAYS_INLINE __attribute__((always_inline))
#else
#  define ALWAYS_INLINE
#endif

typedef struct {

  enum gcry_md_algos algo;
  const char* data_hex;
  const char* n;
  const char* s;
  unsigned output_size_bytes;
  const char* expected_output_hex;

} test_vec_t;

/* from https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/cSHAKE_samples.pdf */
test_vec_t test_vecs[] = {

    {GCRY_MD_CSHAKE128, "00010203", "", "Email Signature", 32, "C1C36925B6409A04F1B504FCBCA9D82B4017277CB5ED2B2065FC1D3814D5AAF5"},

};


static void *
hex2buffer (const char *string, size_t *r_length)
{
  const char *s;
  unsigned char *buffer;
  size_t length;

  buffer = xmalloc (strlen(string)/2+1);
  length = 0;
  for (s=string; *s; s +=2 )
    {
      if (!hexdigitp (s) || !hexdigitp (s+1))
        die ("invalid hex digits in \"%s\"\n", string);
      ((unsigned char*)buffer)[length++] = xtoi_2 (s);
    }
  *r_length = length;
  return buffer;
}


int
main (int argc, char **argv)
{
  gpg_error_t err = GPG_ERR_NO_ERROR;
  int last_argc   = -1;

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
      else if (!strcmp (*argv, "--verbose"))
        {
          verbose++;
          argc--;
          argv++;
        }
      else if (!strcmp (*argv, "--debug"))
        {
          verbose = debug = 1;
          argc--;
          argv++;
        }
    }
  for (unsigned i = 0; i < DIM (test_vecs); i++)
    {
      gcry_md_hd_t hd;
      enum gcry_md_algos algo = test_vecs[i].algo;
      test_vec_t *test        = &test_vecs[i];
      unsigned char result_buf[256];
      // unsigned char compare_buf[256];
      void *compare_buf, *data_buf;
      size_t compare_len, data_len;

      err = gcry_md_open (&hd, algo, 0);
      if (err)
        {
          fail (
              "algo %d, gcry_md_open failed: %s\n", algo, gpg_strerror (err));
          goto leave;
        }
      if (strlen (test->n))
        {
          err = gcry_md_set_add_input (
              hd, GCRY_MD_ADDIN_CSHAKE_N, test->n, strlen (test->n));
          if (err)
            {
              fail ("algo %d, gcry_md_set_add_input (N) failed: %s\n",
                    algo,
                    gpg_strerror (err));
              goto leave;
            }
        }
      if (strlen (test->s))
        {
          err = gcry_md_set_add_input (
              hd, GCRY_MD_ADDIN_CSHAKE_S, test->s, strlen (test->s));
          if (err)
            {
              fail ("algo %d, gcry_md_set_add_input (S) failed: %s\n",
                    algo,
                    gpg_strerror (err));
              goto leave;
            }
        }
      data_buf = hex2buffer(test->data_hex, &data_len);
      gcry_md_write (hd, data_buf, data_len);
      gcry_md_extract (hd, algo, result_buf, test->output_size_bytes);
      compare_buf = hex2buffer (test->expected_output_hex, &compare_len);
      if (compare_len != test->output_size_bytes)
        {
          fail ("algo %d, internal problem with test data lengths\n", algo);
          goto leave;
        }
      if (memcmp (compare_buf, result_buf, test->output_size_bytes))
        {

          fail ("algo %d, result comparison failed in test\n", algo);
          error_count++;
        }
      xfree(compare_buf);
      xfree(data_buf);
      gcry_md_close(hd);
    }


  if (verbose)
    fprintf (stderr, "\nAll tests completed. Errors: %i\n", error_count);
leave:
  return err;
}
