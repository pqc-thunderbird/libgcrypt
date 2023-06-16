#ifndef SYMMETRIC_H
#define SYMMETRIC_H

#include "gcrypt-int.h"

#include <stdint.h>
#include "dilithium-params.h"

void _gcry_dilithium_shake128_stream_init(gcry_md_hd_t *md, const uint8_t seed[GCRY_DILITHIUM_SEEDBYTES], uint16_t nonce);

void _gcry_dilithium_shake256_stream_init(gcry_md_hd_t *md, const uint8_t seed[GCRY_DILITHIUM_CRHBYTES], uint16_t nonce);

void _gcry_dilithium_shake128_squeeze_nblocks(gcry_md_hd_t md, unsigned n, unsigned char *out);

void _gcry_dilithium_shake256_squeeze_nblocks(gcry_md_hd_t md, unsigned n, unsigned char *out);


void _gcry_dilithium_shake256(const unsigned char *in_buf1, unsigned in_buf1_len, const unsigned char *in_buf2, unsigned in_buf2_len, unsigned char *out, unsigned out_len);

#define SHAKE128_RATE 168
#define SHAKE256_RATE 136
#define SHA3_256_RATE 136
#define SHA3_512_RATE 72

#define STREAM128_BLOCKBYTES SHAKE128_RATE
#define STREAM256_BLOCKBYTES SHAKE256_RATE



#endif