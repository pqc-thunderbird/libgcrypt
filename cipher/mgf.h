#ifndef GCRY_MGF_H
#define GCRY_MGF_H

gcry_err_code_t mgf1 (unsigned char *output, size_t outlen, unsigned char *seed, size_t seedlen,
      int algo);


#endif