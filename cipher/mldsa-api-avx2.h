#ifndef API_H
#define API_H

#include <stddef.h>
#include <stdint.h>

gcry_err_code_t _gcry_mldsa_avx2_keypair(gcry_mldsa_param_t *params, byte *pk, byte *sk);

int _gcry_mldsa_avx2_sign(gcry_mldsa_param_t *params, byte *sig, size_t *siglen,
                                        const byte *m, size_t mlen,
                                        const byte *sk);

int _gcry_mldsa_avx2_verify(gcry_mldsa_param_t *params, const byte *sig, size_t siglen,
                                     const byte *m, size_t mlen,
                                     const byte *pk);


#endif
