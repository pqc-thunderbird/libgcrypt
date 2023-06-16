#include <config.h>
#include <stdint.h>
#include "dilithium-params.h"
#include "dilithium-symmetric.h"

void _gcry_dilithium_shake128_stream_init(gcry_md_hd_t *md, const uint8_t seed[GCRY_DILITHIUM_SEEDBYTES], uint16_t nonce)
{
  uint8_t t[2];
  t[0] = nonce;
  t[1] = nonce >> 8;

  _gcry_md_open (md, GCRY_MD_SHAKE128, GCRY_MD_FLAG_SECURE);
  _gcry_md_write(*md, seed, GCRY_DILITHIUM_SEEDBYTES);
  _gcry_md_write(*md, t, 2);
}

void _gcry_dilithium_shake256_stream_init(gcry_md_hd_t *md, const uint8_t seed[GCRY_DILITHIUM_CRHBYTES], uint16_t nonce)
{
  uint8_t t[2];
  t[0] = nonce;
  t[1] = nonce >> 8;

  _gcry_md_open (md, GCRY_MD_SHAKE256, GCRY_MD_FLAG_SECURE);
  _gcry_md_write(*md, seed, GCRY_DILITHIUM_CRHBYTES);
  _gcry_md_write(*md, t, 2);
}

void _gcry_dilithium_shake128_squeeze_nblocks(gcry_md_hd_t md, unsigned n, unsigned char *out)
{
  for(unsigned i = 0; i < n; i++)
  {
    _gcry_md_extract(md, GCRY_MD_SHAKE128, out + i * SHAKE128_RATE, SHAKE128_RATE);
  }
}

void _gcry_dilithium_shake256_squeeze_nblocks(gcry_md_hd_t md, unsigned n, unsigned char *out)
{
  for(unsigned i = 0; i < n; i++)
  {
    _gcry_md_extract(md, GCRY_MD_SHAKE256, out + i * SHAKE256_RATE, SHAKE256_RATE);
  }
}


/*
 * takes the two buffers in_buf1, in_buf2 as inputs. The second one can be NULL.
 * The out buffer contains the output of out_len bytes.
 */
void _gcry_dilithium_shake256(const unsigned char *in_buf1, unsigned in_buf1_len, const unsigned char *in_buf2, unsigned in_buf2_len, unsigned char *out, unsigned out_len)
{
  if(!in_buf1)
  {
    // TODO error
  }
  gcry_md_hd_t md;

  _gcry_md_open (&md, GCRY_MD_SHAKE256, GCRY_MD_FLAG_SECURE);
  _gcry_md_write(md, in_buf1, in_buf1_len);
  if(in_buf2) {
    _gcry_md_write(md, in_buf2, in_buf2_len);
  }
  _gcry_md_extract(md, GCRY_MD_SHAKE256, out, out_len);
  _gcry_md_close(md);
}
