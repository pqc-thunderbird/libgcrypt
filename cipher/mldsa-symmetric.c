#include <config.h>
#include "types.h"
#include "mldsa-params.h"
#include "mldsa-symmetric.h"

gcry_err_code_t _gcry_mldsa_shake128_stream_init(gcry_md_hd_t *md, const byte seed[GCRY_MLDSA_SEEDBYTES], u16 nonce)
{
  gcry_err_code_t ec = 0;
  byte t[2];
  t[0] = nonce;
  t[1] = nonce >> 8;

  _gcry_md_open (md, GCRY_MD_SHAKE128, GCRY_MD_FLAG_SECURE);
  if (ec)
    goto leave;
  _gcry_md_write(*md, seed, GCRY_MLDSA_SEEDBYTES);
  _gcry_md_write(*md, t, 2);

leave:
  return ec;
}

gcry_err_code_t _gcry_mldsa_shake256_stream_init(gcry_md_hd_t *md, const byte seed[GCRY_MLDSA_CRHBYTES], u16 nonce)
{
  gcry_err_code_t ec = 0;
  byte t[2];
  t[0] = nonce;
  t[1] = nonce >> 8;

  ec = _gcry_md_open (md, GCRY_MD_SHAKE256, GCRY_MD_FLAG_SECURE);
  if (ec)
    goto leave;
  _gcry_md_write(*md, seed, GCRY_MLDSA_CRHBYTES);
  _gcry_md_write(*md, t, 2);

leave:
  return ec;
}

gcry_err_code_t _gcry_mldsa_shake128_squeeze_nblocks(gcry_md_hd_t md, unsigned n, unsigned char *out)
{
  gcry_err_code_t ec = 0;
  for(unsigned i = 0; i < n; i++)
  {
    ec=  _gcry_md_extract(md, GCRY_MD_SHAKE128, out + i * GCRY_SHAKE128_RATE, GCRY_SHAKE128_RATE);
    if (ec)
      goto leave;
  }

leave:
  return ec;
}

gcry_err_code_t _gcry_mldsa_shake256_squeeze_nblocks(gcry_md_hd_t md, unsigned n, unsigned char *out)
{
  gcry_err_code_t ec = 0;
  for(unsigned i = 0; i < n; i++)
  {
    ec = _gcry_md_extract(md, GCRY_MD_SHAKE256, out + i * GCRY_SHAKE256_RATE, GCRY_SHAKE256_RATE);
    if (ec)
      goto leave;
  }

leave:
  return ec;
}


/*
 * takes the two buffers in_buf1, in_buf2 as inputs. The second one can be NULL.
 * The out buffer contains the output of out_len bytes.
 */
gcry_err_code_t _gcry_mldsa_shake256(const unsigned char *in_buf1, unsigned in_buf1_len, const unsigned char *in_buf2, unsigned in_buf2_len, unsigned char *out, unsigned out_len)
{
  gcry_md_hd_t md = NULL;
  gcry_err_code_t ec = 0;

  if(!in_buf1)
  {
    return GPG_ERR_INV_ARG;
  }

  ec = _gcry_md_open (&md, GCRY_MD_SHAKE256, GCRY_MD_FLAG_SECURE);
  if (ec)
    goto leave;
  _gcry_md_write(md, in_buf1, in_buf1_len);
  if(in_buf2) {
    _gcry_md_write(md, in_buf2, in_buf2_len);
  }
  ec = _gcry_md_extract(md, GCRY_MD_SHAKE256, out, out_len);
  if (ec)
    goto leave;

leave:
  _gcry_md_close(md);
  return ec;
}
