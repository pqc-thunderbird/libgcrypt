#include <config.h>

#include "g10lib.h"
#include "cipher.h"
#include "mgf.h"

/* Mask generation function for OAEP.  See RFC-3447 B.2.1.  */
gcry_err_code_t
mgf1 (unsigned char *output, size_t outlen, unsigned char *seed, size_t seedlen,
      int algo)
{
  size_t dlen, nbytes, n;
  int idx;
  gcry_md_hd_t hd;
  gcry_err_code_t err;

  err = _gcry_md_open (&hd, algo, 0);
  if (err)
    return err;

  dlen = _gcry_md_get_algo_dlen (algo);

  /* We skip step 1 which would be assert(OUTLEN <= 2^32).  The loop
     in step 3 is merged with step 4 by concatenating no more octets
     than what would fit into OUTPUT.  The ceiling for the counter IDX
     is implemented indirectly.  */
  nbytes = 0;  /* Step 2.  */
  idx = 0;
  while ( nbytes < outlen )
    {
      unsigned char c[4], *digest;

      if (idx)
        _gcry_md_reset (hd);

      c[0] = (idx >> 24) & 0xFF;
      c[1] = (idx >> 16) & 0xFF;
      c[2] = (idx >> 8) & 0xFF;
      c[3] = idx & 0xFF;
      idx++;

      _gcry_md_write (hd, seed, seedlen);
      _gcry_md_write (hd, c, 4);
      digest = _gcry_md_read (hd, 0);

      n = (outlen - nbytes < dlen)? (outlen - nbytes) : dlen;
      memcpy (output+nbytes, digest, n);
      nbytes += n;
    }

  _gcry_md_close (hd);
  return GPG_ERR_NO_ERROR;
}
