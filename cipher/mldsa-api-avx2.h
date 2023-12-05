#ifndef API_H
#define API_H

#include <stddef.h>
#include <stdint.h>

#define pqcrystals_dilithium2_PUBLICKEYBYTES 1312
#define pqcrystals_dilithium2_SECRETKEYBYTES 2528
#define pqcrystals_dilithium2_BYTES 2420

#define pqcrystals_dilithium2_avx2_PUBLICKEYBYTES pqcrystals_dilithium2_PUBLICKEYBYTES
#define pqcrystals_dilithium2_avx2_SECRETKEYBYTES pqcrystals_dilithium2_SECRETKEYBYTES
#define pqcrystals_dilithium2_avx2_BYTES pqcrystals_dilithium2_BYTES

gcry_err_code_t _gcry_mldsa_keypair_avx2(gcry_mldsa_param_t *params, byte *pk, byte *sk);

int crypto_sign_signature(gcry_mldsa_param_t *params, byte *sig, size_t *siglen,
                                        const byte *m, size_t mlen,
                                        const byte *sk);

int crypto_sign_verify(gcry_mldsa_param_t *params, const byte *sig, size_t siglen,
                                     const byte *m, size_t mlen,
                                     const byte *pk);


#define pqcrystals_dilithium3_PUBLICKEYBYTES 1952
#define pqcrystals_dilithium3_SECRETKEYBYTES 4000
#define pqcrystals_dilithium3_BYTES 3293

#define pqcrystals_dilithium3_avx2_PUBLICKEYBYTES pqcrystals_dilithium3_PUBLICKEYBYTES
#define pqcrystals_dilithium3_avx2_SECRETKEYBYTES pqcrystals_dilithium3_SECRETKEYBYTES
#define pqcrystals_dilithium3_avx2_BYTES pqcrystals_dilithium3_BYTES

int pqcrystals_dilithium3_avx2_keypair(byte *pk, byte *sk);

int pqcrystals_dilithium3_avx2_signature(byte *sig, size_t *siglen,
                                        const byte *m, size_t mlen,
                                        const byte *sk);

int pqcrystals_dilithium3_avx2(byte *sm, size_t *smlen,
                              const byte *m, size_t mlen,
                              const byte *sk);

int pqcrystals_dilithium3_avx2_verify(const byte *sig, size_t siglen,
                                     const byte *m, size_t mlen,
                                     const byte *pk);

int pqcrystals_dilithium3_avx2_open(byte *m, size_t *mlen,
                                   const byte *sm, size_t smlen,
                                   const byte *pk);


#define pqcrystals_dilithium5_PUBLICKEYBYTES 2592
#define pqcrystals_dilithium5_SECRETKEYBYTES 4864
#define pqcrystals_dilithium5_BYTES 4595

#define pqcrystals_dilithium5_avx2_PUBLICKEYBYTES pqcrystals_dilithium5_PUBLICKEYBYTES
#define pqcrystals_dilithium5_avx2_SECRETKEYBYTES pqcrystals_dilithium5_SECRETKEYBYTES
#define pqcrystals_dilithium5_avx2_BYTES pqcrystals_dilithium5_BYTES

int pqcrystals_dilithium5_avx2_keypair(byte *pk, byte *sk);

int pqcrystals_dilithium5_avx2_signature(byte *sig, size_t *siglen,
                                        const byte *m, size_t mlen,
                                        const byte *sk);

int pqcrystals_dilithium5_avx2(byte *sm, size_t *smlen,
                              const byte *m, size_t mlen,
                              const byte *sk);

int pqcrystals_dilithium5_avx2_verify(const byte *sig, size_t siglen,
                                     const byte *m, size_t mlen,
                                     const byte *pk);

int pqcrystals_dilithium5_avx2_open(byte *m, size_t *mlen,
                                   const byte *sm, size_t smlen,
                                   const byte *pk);


#endif
