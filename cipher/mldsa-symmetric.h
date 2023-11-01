#ifndef _GCRY_MLDSA_SYMMETRIC_H
#define _GCRY_MLDSA_SYMMETRIC_H

#include "gcrypt-int.h"

#include "types.h"
#include "mldsa-params.h"

void _gcry_mldsa_shake128_stream_init(gcry_md_hd_t *md, const byte seed[GCRY_MLDSA_SEEDBYTES], u16 nonce);

void _gcry_mldsa_shake256_stream_init(gcry_md_hd_t *md, const byte seed[GCRY_MLDSA_CRHBYTES], u16 nonce);

void _gcry_mldsa_shake128_squeeze_nblocks(gcry_md_hd_t md, unsigned n, unsigned char *out);

void _gcry_mldsa_shake256_squeeze_nblocks(gcry_md_hd_t md, unsigned n, unsigned char *out);


void _gcry_mldsa_shake256(const unsigned char *in_buf1, unsigned in_buf1_len, const unsigned char *in_buf2, unsigned in_buf2_len, unsigned char *out, unsigned out_len);

#define GCRY_SHAKE128_RATE 168
#define GCRY_SHAKE256_RATE 136
#define GCRY_SHA3_256_RATE 136
#define GCRY_SHA3_512_RATE 72

#define GCRY_STREAM128_BLOCKBYTES GCRY_SHAKE128_RATE
#define GCRY_STREAM256_BLOCKBYTES GCRY_SHAKE256_RATE

#endif