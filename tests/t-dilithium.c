/* t-dilithium.c - Test the Crystals-Dilithium Signature algorithm
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


#define PGM "t-dilithium"
#include "t-common.h"
//#define N_TESTS 120

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>


//#define PGM "test-utils"
//#include "t-common.h"

#define digitp(p)     (*(p) >= '0' && *(p) <= '9')
#define hexdigitp(a)  (digitp (a)                     \
                       || (*(a) >= 'A' && *(a) <= 'F')  \
                       || (*(a) >= 'a' && *(a) <= 'f'))
#define xtoi_1(p)     (*(p) <= '9'? (*(p)- '0'): \
                       *(p) <= 'F'? (*(p)-'A'+10):(*(p)-'a'+10))
#define xtoi_2(p)     ((xtoi_1(p) * 16) + xtoi_1((p)+1))
#define xmalloc(a)    gcry_xmalloc ((a))
#define xcalloc(a,b)  gcry_xcalloc ((a),(b))
#define xstrdup(a)    gcry_xstrdup ((a))
#define xfree(a)      gcry_free ((a))
#define pass()        do { ; } while (0)


/* Prepend FNAME with the srcdir environment variable's value and
 * return an allocated filename.  */
char *
prepend_srcdir (const char *fname)
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
static char *
read_textline (FILE *fp, int *lineno)
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
      for (p--;p > line && my_isascii (*p) && isspace (*p); p--)
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
static void *
hex2buffer (const char *string, size_t *r_length)
{
  const char *s;
  unsigned char *buffer;
  size_t length;
  size_t str_len = strlen(string);
  *r_length = 0;
  if(str_len % 2)
  {
    return NULL;
  }
  buffer = xmalloc (strlen(string)/2+1);
  length = 0;
  for (s=string; *s; s +=2 )
    {
      if (!hexdigitp (s) || !hexdigitp (s+1))
        {
          xfree (buffer);
          return NULL;           /* Invalid hex digits. */
        }
      ((unsigned char*)buffer)[length++] = xtoi_2 (s);
    }
  *r_length = length;
  return buffer;
}

/* Copy the data after the tag to BUFFER.  BUFFER will be allocated as
   needed.  */
static unsigned char*
fill_bin_buf_from_hex_line(size_t* r_length, const char tag_char, const char *line, int lineno)
{
  const char *s;


  s = strchr (line, tag_char);
  if (!s)
    {
      fail ("syntax error at input line %d", lineno);
      return NULL;
    }
  s++;
  while(strlen(s) && s[0] == ' ')
  {
    s++;
  }
  /*for (s++; my_isascii (*s) && isspace (*s); s++)
    ;
  *buffer = xstrdup (s);*/
  return hex2buffer(s, r_length);
}



/*
* TODO: include test-utils.h when merging with kyber branch
*/


#define GCRY_DILITHIUM2_NBITS (1312 * 8) 10496
#define GCRY_DILITHIUM3_NBITS (1952 * 8) 15616
#define GCRY_DILITHIUM5_NBITS (2592 * 8) 20736

static int check_dilithium_roundtrip()
{
  char *dilithium_name[] = {"Dilithium2", "Dilithium3", "Dilithium5"};
  unsigned dilithium_nbits[] = {10496, 15616, 20736};

  int rc;

  for (int i = 0; i < sizeof(dilithium_name)/sizeof(dilithium_name[0]); i++)
  {
    gcry_sexp_t skey = NULL;
    gcry_sexp_t pkey = NULL;
    gcry_sexp_t keyparm = NULL;
    gcry_sexp_t key = NULL;
    gcry_sexp_t l = NULL;

    gcry_sexp_t r_sig = NULL;
    gcry_sexp_t s_data = NULL;
    gcry_sexp_t s_data_wrong = NULL;

    if (verbose)
      info ("creating %s key\n", dilithium_name[i]);

    rc = gcry_sexp_build(&keyparm,
                        NULL,
                        "(genkey (dilithium (nbits%u)))",
                        dilithium_nbits[i],
                        NULL);

    if (rc)
      die ("error creating S-expression: %s\n", gpg_strerror (rc));
    rc = gcry_pk_genkey (&key, keyparm);

    if (rc)
      die ("error generating Dilithium key: %s\n", gpg_strerror (rc));


    pkey = gcry_sexp_find_token (key, "public-key", 0);
    if (!pkey)
    {
      die("public part missing in return value\n");
    }

    skey = gcry_sexp_find_token (key, "private-key", 0);
    if (!skey)
      die("private part missing in return value\n");




    rc = gcry_sexp_new (&s_data,
      "(data (flags raw)"
      " (hash-algo sha256)"
      " (value 7:message))", 0, 1);
    if(rc)
      die("gcry_sexp_build failed\n");

    rc = gcry_pk_sign (&r_sig, s_data, skey);
    if(rc)
      die("sign failed\n");

    printf("verifying correct signature\n");
    rc = gcry_pk_verify (r_sig, s_data, pkey);
    if(rc)
      die("verify failed\n");
    printf("... ok!\n");

    printf("verifying wrong signature\n");
    rc = gcry_sexp_new (&s_data_wrong,
      "(data (flags raw)"
      " (hash-algo sha256)"
      " (value 8:message2))", 0, 1);

    rc = gcry_pk_verify (r_sig, s_data_wrong, pkey);
    if(!rc)
      die("verify succesful for wrong data\n");
    printf("... ok!\n");
    rc = 0;

    gcry_sexp_release(skey);
    gcry_sexp_release(pkey);
    gcry_sexp_release(keyparm);
    gcry_sexp_release(key);
    gcry_sexp_release(l);

    gcry_sexp_release(r_sig);
    gcry_sexp_release(s_data);
    gcry_sexp_release(s_data_wrong);
  }

  return rc;
}



#if 0
static void check_kyber_kat(const char *fname, unsigned kyber_bits)
{
  const size_t nb_kat_tests = 0; /* zero means all */
  FILE *fp;
  int lineno = 0;
  char *line;

  enum
  {
    public_key_idx    = 0,
    privat_key_idx    = 1,
    ciphertext_idx    = 2,
    shared_secret_idx = 3
  };

  test_vec_desc_entry test_vec[] = {{
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
                                    }};
  size_t test_count              = 0;
  gcry_sexp_t public_key_sx = NULL, private_key_sx = NULL,
              ciphertext_sx = NULL, shared_secret_expected_sx = NULL,
              shared_secret_sx = NULL;

  // unsigned char* public_key = NULL, *private_key = , *ciphertext,
  // *shared_secret; size_t public_key_len, private_key_len, ciphertext_len,
  // shared_secret_len;

  info("Checking Kyber KAT.\n");

  fp = fopen(fname, "r");
  if (!fp)
    die("error opening '%s': %s\n", fname, strerror(errno));


  while ((line = read_textline(fp, &lineno))
         && !(nb_kat_tests && nb_kat_tests <= test_count))
    {
      gcry_sexp_t l;
      gcry_mpi_t ss_expected, ss;
      int have_flags;
      int rc;
      int is_complete = 1;
      gcry_error_t err;
      unsigned i;
      for (i = 0; i < sizeof(test_vec) / sizeof(test_vec[0]); i++)
        {
          test_vec_desc_entry *e = &test_vec[i];
          if (!strncmp(line, e->index, strlen(e->index)))
            {
              if (e->result_buf != NULL)
                {
                  fail("trying to set test vector element twice");
                }
              e->result_buf = fill_bin_buf_from_hex_line(
                  &e->result_buf_len, ':', line, lineno);
              break;
            }
          else if (!strncmp(line, "#", 1)
                   || !strncmp(line, "Shared Secret B:", 15))
            {
              continue;
            }
          /*else // cannot fail here because kyber test vectors as generated by
            reference implementation contain random seeds without prefix
            {
            fail ("unknown tag at input line %d", lineno);
            }*/
        }

      // check if we completed one test vector:
      for (i = 0; i < sizeof(test_vec) / sizeof(test_vec[0]); i++)
        {
          is_complete &= (test_vec[i].result_buf != NULL);
        }
      if (!is_complete)
        {
          // printf("line '%s' does NOT complete a test vector\n", line);
          xfree(line);
          continue;
        }
      else
        {
          // printf("line '%s' COMPLETES a test vector\n", line);
        }
      test_count++;
      err = gcry_sexp_build(&private_key_sx,
                            NULL,
                            "(private-key (kyber (s %b) (nbits%u) ))",
                            (int)test_vec[privat_key_idx].result_buf_len,
                            test_vec[privat_key_idx].result_buf,
                            kyber_bits,
                            NULL);
      if (err)
        {
          fail("error building private key SEXP for test, %s: %s",
               "sk",
               gpg_strerror(err));
          goto leave;
        }
#if 0
        printf("private key sx directly after building:\n");
        gcry_sexp_dump(private_key_sx);
        char print_buf[100000];
        gcry_sexp_sprint(private_key_sx, GCRYSEXP_FMT_ADVANCED, print_buf, sizeof(print_buf)-1);
        printf("private_key_sx: %s", print_buf);
#endif

      err = gcry_sexp_build(&shared_secret_expected_sx,
                            NULL,
                            "(data (value %b))",
                            (int)test_vec[shared_secret_idx].result_buf_len,
                            test_vec[shared_secret_idx].result_buf);
      if (err)
        {
          fail("error building expected shared secret SEXP for test, %s: %s",
               "pk",
               gpg_strerror(err));
          goto leave;
        }

      l = gcry_sexp_find_token(shared_secret_expected_sx, "value", 0);
      ss_expected = gcry_sexp_nth_mpi(l, 1, GCRYMPI_FMT_USG);
      gcry_sexp_release(l);

      err = gcry_sexp_build(&ciphertext_sx,
                            NULL,
                            "(ciphertext (kyber(c %b)))",
                            (int)test_vec[ciphertext_idx].result_buf_len,
                            test_vec[ciphertext_idx].result_buf);
      if (err)
        {
          fail("error building ciphertext SEXP for test, %s: %s",
               "pk",
               gpg_strerror(err));
          goto leave;
        }

      l          = gcry_sexp_find_token(ciphertext_sx, "flags", 0);
      have_flags = !!l;
      gcry_sexp_release(l);


      // l = gcry_sexp_find_token (ciphertext_sx, "flags", 0); // why no leak
      // when this was in?
      rc = gcry_pk_decrypt(&shared_secret_sx, ciphertext_sx, private_key_sx);
      if (rc)
        {
          die("decryption failed: %s\n", gcry_strerror(rc));
        }

      l = gcry_sexp_find_token(shared_secret_sx, "value", 0);
      if (l)
        {
          if (!have_flags)
            {
              // printf("compatibility mode of pk_decrypt broken:
              // !have_flags\n"); die ("compatibility mode of pk_decrypt broken:
              // !have_flags\n");
            }
          ss = gcry_sexp_nth_mpi(l, 1, GCRYMPI_FMT_USG);
          gcry_sexp_release(l);
        }
      else
        {
          if (have_flags)
            // die ("compatibility mode of pk_decrypt broken: have_flags is
            // true\n");
            ss = gcry_sexp_nth_mpi(shared_secret_sx, 0, GCRYMPI_FMT_USG);
        }
      if (!ss)
        {
          die("ss = NULL\n");
        }
      if (!ss_expected)
        {
          die("ss_expected = NULL\n");
        }

      /* Compare.  */
      if (gcry_mpi_cmp(ss_expected, ss))
        {
          die("error with decryption result\n");
        }
      printf(".");


      xfree(line);
      for (i = 0; i < sizeof(test_vec) / sizeof(test_vec[0]); i++)
        {
          test_vec_desc_entry *e = &test_vec[i];
          if (e->result_buf)
            {
              xfree(e->result_buf);
            }
          e->result_buf     = NULL;
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

  printf("\n");
  xfree(line);
leave:
  line = line;
  /*gcry_sexp_release(public_key_sx);
    gcry_sexp_release(private_key_sx);
    gcry_sexp_release(ciphertext_sx);
    gcry_sexp_release(shared_secret_sx);*/
}
#endif


int
main (int argc, char **argv)
{

int last_argc = -1;
  char *fname   = NULL;
  unsigned i;
  if (argc)
    {
      argc--;
      argv++;
    }

  while (argc && last_argc != argc)
    {
      last_argc = argc;
      if (!strcmp(*argv, "--"))
        {
          argc--;
          argv++;
          break;
        }
      else if (!strcmp(*argv, "--help"))
        {
          fputs("usage: " PGM " [options]\n"
                "Options:\n"
                "  --verbose       print timings etc.\n"
                "  --debug         flyswatter\n"
                "  --data FNAME    take test data from file FNAME\n",
                stdout);
          exit(0);
        }
      else if (!strcmp(*argv, "--verbose"))
        {
          verbose++;
          argc--;
          argv++;
        }
      else if (!strcmp(*argv, "--debug"))
        {
          verbose += 2;
          debug++;
          argc--;
          argv++;
        }
      else if (!strcmp(*argv, "--data"))
        {
          argc--;
          argv++;
          if (argc)
            {
              xfree(fname);
              fname = xstrdup(*argv);
              argc--;
              argv++;
            }
        }
      else if (!strncmp(*argv, "--", 2))
        die("unknown option '%s'", *argv);
    }


    if(fname)
    {
        //check_dilithium_kat(dilithium_kat_files[i], dilithium_bits[i]);
    }
    else
    {
      if(check_dilithium_roundtrip())
      {
          fail("check_dilithium_roundtrip() yielded an error, aborting");
      }

     //check_dilithium_kat(fname, kyber_bits[i]);
    }

    printf("Success.\n");
}
