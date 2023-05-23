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


static int check_dilithium_roundtrip()
{

  gcry_sexp_t skey, pkey;
  gcry_sexp_t keyparm, key, l;

  int rc;

  if (verbose)
    info ("creating Dilithium5 key\n");
  rc = gcry_sexp_new (&keyparm,
                      "(genkey\n"
                      " (dilithium\n"
                      "  (nbits 4:2592)\n"
                      " ))", 0, 1);
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

  gcry_sexp_t r_sig;
  gcry_sexp_t s_data;
  gcry_sexp_t s_data_wrong;


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
  rc = gcry_sexp_new (&s_data,
    "(data (flags raw)"
    " (hash-algo sha256)"
    " (value 8:message2))", 0, 1);

  rc = gcry_pk_verify (r_sig, s_data, pkey);
  if(!rc)
    die("verify succesful for wrong data\n");
  printf("... ok!\n");
  rc = 0;



#if 0
  rc = gcry_pk_encap(&ct, &shared_secret, pkey);
  if(rc)
  {
      printf("error when calling gcry_pk_encap\n");
      goto leave;
  }
  rc = gcry_pk_decrypt(&shared_secret2, ct, skey);
  if(rc)
  {
      printf("error when calling gcry_pk_decrypt\n");
      goto leave;
  }

   l = gcry_sexp_find_token (shared_secret, "value", 0);
   if(!l)
   {
       die("could not extract shared secret from encapsulation");
   }
   ss = gcry_sexp_nth_mpi (l, 1, GCRYMPI_FMT_USG);
   gcry_sexp_release (l);

   l = gcry_sexp_find_token (shared_secret2, "value", 0);
   if(!l)
   {
       die("could not extract shared secret from encapsulation");
   }
   ss2 = gcry_sexp_nth_mpi (l, 1, GCRYMPI_FMT_USG);
    gcry_sexp_release(l);
   if(!ss)
   {
       die("ss = NULL\n");
   }
   if(!ss2)
   {
       die("ss2 = NULL\n");
   }

   /* Compare.  */
   if (gcry_mpi_cmp (ss, ss2))
   {
       printf("decryption result incorrect\n");
       die ("check_kyber_gen_enc_dec test: error with decryption result\n");
   }
   gcry_mpi_release(ss);
   gcry_mpi_release(ss2);
   gcry_sexp_release(keyparm);
   gcry_sexp_release(key);
   gcry_sexp_release(ct);
   gcry_sexp_release(shared_secret);
   gcry_sexp_release(shared_secret2);
   gcry_sexp_release(skey);
   gcry_sexp_release(pkey);
   printf("check_kyber_gen_enc_dec: decryption correct... \n");
#endif


leave:
  return rc;
}

int
main (int argc, char **argv)
{

    int last_argc = -1;

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
                    "  --debug         flyswatter\n",
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
        else if (!strncmp (*argv, "--", 2))
            die ("unknown option '%s'", *argv);

    }

    if(check_dilithium_roundtrip())
    {
        // must not happen:
        fail("check_dilithium_roundtrip() yielded an error, aborting");
    }

    printf("Dilithium test successful.\n");
}
