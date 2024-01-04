#include <string.h>

#include "slhdsa-sha256x8.h"
#include "slhdsa-utils.h"

#include <stdio.h>
#include <string.h>
#include <stdint.h>

#ifdef USE_AVX2

// Transpose 8 vectors containing 32-bit values
void transpose(u256 s[8])
{
  u256 tmp0[8];
  u256 tmp1[8];
  tmp0[0] = _mm256_unpacklo_epi32(s[0], s[1]);
  tmp0[1] = _mm256_unpackhi_epi32(s[0], s[1]);
  tmp0[2] = _mm256_unpacklo_epi32(s[2], s[3]);
  tmp0[3] = _mm256_unpackhi_epi32(s[2], s[3]);
  tmp0[4] = _mm256_unpacklo_epi32(s[4], s[5]);
  tmp0[5] = _mm256_unpackhi_epi32(s[4], s[5]);
  tmp0[6] = _mm256_unpacklo_epi32(s[6], s[7]);
  tmp0[7] = _mm256_unpackhi_epi32(s[6], s[7]);
  tmp1[0] = _mm256_unpacklo_epi64(tmp0[0], tmp0[2]);
  tmp1[1] = _mm256_unpackhi_epi64(tmp0[0], tmp0[2]);
  tmp1[2] = _mm256_unpacklo_epi64(tmp0[1], tmp0[3]);
  tmp1[3] = _mm256_unpackhi_epi64(tmp0[1], tmp0[3]);
  tmp1[4] = _mm256_unpacklo_epi64(tmp0[4], tmp0[6]);
  tmp1[5] = _mm256_unpackhi_epi64(tmp0[4], tmp0[6]);
  tmp1[6] = _mm256_unpacklo_epi64(tmp0[5], tmp0[7]);
  tmp1[7] = _mm256_unpackhi_epi64(tmp0[5], tmp0[7]);
  s[0]    = _mm256_permute2x128_si256(tmp1[0], tmp1[4], 0x20);
  s[1]    = _mm256_permute2x128_si256(tmp1[1], tmp1[5], 0x20);
  s[2]    = _mm256_permute2x128_si256(tmp1[2], tmp1[6], 0x20);
  s[3]    = _mm256_permute2x128_si256(tmp1[3], tmp1[7], 0x20);
  s[4]    = _mm256_permute2x128_si256(tmp1[0], tmp1[4], 0x31);
  s[5]    = _mm256_permute2x128_si256(tmp1[1], tmp1[5], 0x31);
  s[6]    = _mm256_permute2x128_si256(tmp1[2], tmp1[6], 0x31);
  s[7]    = _mm256_permute2x128_si256(tmp1[3], tmp1[7], 0x31);
}

void sha256_init8x(sha256ctx *ctx)
{
  ctx->s[0] = _mm256_set_epi32(
      0x6a09e667, 0x6a09e667, 0x6a09e667, 0x6a09e667, 0x6a09e667, 0x6a09e667, 0x6a09e667, 0x6a09e667);
  ctx->s[1] = _mm256_set_epi32(
      0xbb67ae85, 0xbb67ae85, 0xbb67ae85, 0xbb67ae85, 0xbb67ae85, 0xbb67ae85, 0xbb67ae85, 0xbb67ae85);
  ctx->s[2] = _mm256_set_epi32(
      0x3c6ef372, 0x3c6ef372, 0x3c6ef372, 0x3c6ef372, 0x3c6ef372, 0x3c6ef372, 0x3c6ef372, 0x3c6ef372);
  ctx->s[3] = _mm256_set_epi32(
      0xa54ff53a, 0xa54ff53a, 0xa54ff53a, 0xa54ff53a, 0xa54ff53a, 0xa54ff53a, 0xa54ff53a, 0xa54ff53a);
  ctx->s[4] = _mm256_set_epi32(
      0x510e527f, 0x510e527f, 0x510e527f, 0x510e527f, 0x510e527f, 0x510e527f, 0x510e527f, 0x510e527f);
  ctx->s[5] = _mm256_set_epi32(
      0x9b05688c, 0x9b05688c, 0x9b05688c, 0x9b05688c, 0x9b05688c, 0x9b05688c, 0x9b05688c, 0x9b05688c);
  ctx->s[6] = _mm256_set_epi32(
      0x1f83d9ab, 0x1f83d9ab, 0x1f83d9ab, 0x1f83d9ab, 0x1f83d9ab, 0x1f83d9ab, 0x1f83d9ab, 0x1f83d9ab);
  ctx->s[7] = _mm256_set_epi32(
      0x5be0cd19, 0x5be0cd19, 0x5be0cd19, 0x5be0cd19, 0x5be0cd19, 0x5be0cd19, 0x5be0cd19, 0x5be0cd19);

  ctx->datalen = 0;
  ctx->msglen  = 0;
}

void sha256_final8x(sha256ctx *ctx,
                    unsigned char *out0,
                    unsigned char *out1,
                    unsigned char *out2,
                    unsigned char *out3,
                    unsigned char *out4,
                    unsigned char *out5,
                    unsigned char *out6,
                    unsigned char *out7)
{
  unsigned int i, curlen;

  // Padding
  if (ctx->datalen < 56)
    {
      for (i = 0; i < 8; ++i)
        {
          curlen                            = ctx->datalen;
          ctx->msgblocks[64 * i + curlen++] = 0x80;
          while (curlen < 64)
            {
              ctx->msgblocks[64 * i + curlen++] = 0x00;
            }
        }
    }
  else
    {
      for (i = 0; i < 8; ++i)
        {
          curlen                            = ctx->datalen;
          ctx->msgblocks[64 * i + curlen++] = 0x80;
          while (curlen < 64)
            {
              ctx->msgblocks[64 * i + curlen++] = 0x00;
            }
        }
      sha256_transform8x(ctx,
                         &ctx->msgblocks[64 * 0],
                         &ctx->msgblocks[64 * 1],
                         &ctx->msgblocks[64 * 2],
                         &ctx->msgblocks[64 * 3],
                         &ctx->msgblocks[64 * 4],
                         &ctx->msgblocks[64 * 5],
                         &ctx->msgblocks[64 * 6],
                         &ctx->msgblocks[64 * 7]);
      memset(ctx->msgblocks, 0, 8 * 64);
    }

  // Add length of the message to each block
  ctx->msglen += ctx->datalen * 8;
  for (i = 0; i < 8; i++)
    {
      ctx->msgblocks[64 * i + 63] = ctx->msglen;
      ctx->msgblocks[64 * i + 62] = ctx->msglen >> 8;
      ctx->msgblocks[64 * i + 61] = ctx->msglen >> 16;
      ctx->msgblocks[64 * i + 60] = ctx->msglen >> 24;
      ctx->msgblocks[64 * i + 59] = ctx->msglen >> 32;
      ctx->msgblocks[64 * i + 58] = ctx->msglen >> 40;
      ctx->msgblocks[64 * i + 57] = ctx->msglen >> 48;
      ctx->msgblocks[64 * i + 56] = ctx->msglen >> 56;
    }
  sha256_transform8x(ctx,
                     &ctx->msgblocks[64 * 0],
                     &ctx->msgblocks[64 * 1],
                     &ctx->msgblocks[64 * 2],
                     &ctx->msgblocks[64 * 3],
                     &ctx->msgblocks[64 * 4],
                     &ctx->msgblocks[64 * 5],
                     &ctx->msgblocks[64 * 6],
                     &ctx->msgblocks[64 * 7]);

  // Compute final hash output
  transpose(ctx->s);

  // Store Hash value
  STORE(out0, BYTESWAP(ctx->s[0]));
  STORE(out1, BYTESWAP(ctx->s[1]));
  STORE(out2, BYTESWAP(ctx->s[2]));
  STORE(out3, BYTESWAP(ctx->s[3]));
  STORE(out4, BYTESWAP(ctx->s[4]));
  STORE(out5, BYTESWAP(ctx->s[5]));
  STORE(out6, BYTESWAP(ctx->s[6]));
  STORE(out7, BYTESWAP(ctx->s[7]));
}

void sha256_transform8x(sha256ctx *ctx,
                        const unsigned char *data0,
                        const unsigned char *data1,
                        const unsigned char *data2,
                        const unsigned char *data3,
                        const unsigned char *data4,
                        const unsigned char *data5,
                        const unsigned char *data6,
                        const unsigned char *data7)
{
  u256 s[8], w[64], T0, T1;

  // Load words and transform data correctly
  w[0]     = BYTESWAP(LOAD(data0));
  w[0 + 8] = BYTESWAP(LOAD(data0 + 32));
  w[1]     = BYTESWAP(LOAD(data1));
  w[1 + 8] = BYTESWAP(LOAD(data1 + 32));
  w[2]     = BYTESWAP(LOAD(data2));
  w[2 + 8] = BYTESWAP(LOAD(data2 + 32));
  w[3]     = BYTESWAP(LOAD(data3));
  w[3 + 8] = BYTESWAP(LOAD(data3 + 32));
  w[4]     = BYTESWAP(LOAD(data4));
  w[4 + 8] = BYTESWAP(LOAD(data4 + 32));
  w[5]     = BYTESWAP(LOAD(data5));
  w[5 + 8] = BYTESWAP(LOAD(data5 + 32));
  w[6]     = BYTESWAP(LOAD(data6));
  w[6 + 8] = BYTESWAP(LOAD(data6 + 32));
  w[7]     = BYTESWAP(LOAD(data7));
  w[7 + 8] = BYTESWAP(LOAD(data7 + 32));

  transpose(w);
  transpose(w + 8);

  // Initial State
  s[0] = ctx->s[0];
  s[1] = ctx->s[1];
  s[2] = ctx->s[2];
  s[3] = ctx->s[3];
  s[4] = ctx->s[4];
  s[5] = ctx->s[5];
  s[6] = ctx->s[6];
  s[7] = ctx->s[7];

  SHA256ROUND_AVX(s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7], 0, w[0]);
  SHA256ROUND_AVX(s[7], s[0], s[1], s[2], s[3], s[4], s[5], s[6], 1, w[1]);
  SHA256ROUND_AVX(s[6], s[7], s[0], s[1], s[2], s[3], s[4], s[5], 2, w[2]);
  SHA256ROUND_AVX(s[5], s[6], s[7], s[0], s[1], s[2], s[3], s[4], 3, w[3]);
  SHA256ROUND_AVX(s[4], s[5], s[6], s[7], s[0], s[1], s[2], s[3], 4, w[4]);
  SHA256ROUND_AVX(s[3], s[4], s[5], s[6], s[7], s[0], s[1], s[2], 5, w[5]);
  SHA256ROUND_AVX(s[2], s[3], s[4], s[5], s[6], s[7], s[0], s[1], 6, w[6]);
  SHA256ROUND_AVX(s[1], s[2], s[3], s[4], s[5], s[6], s[7], s[0], 7, w[7]);
  SHA256ROUND_AVX(s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7], 8, w[8]);
  SHA256ROUND_AVX(s[7], s[0], s[1], s[2], s[3], s[4], s[5], s[6], 9, w[9]);
  SHA256ROUND_AVX(s[6], s[7], s[0], s[1], s[2], s[3], s[4], s[5], 10, w[10]);
  SHA256ROUND_AVX(s[5], s[6], s[7], s[0], s[1], s[2], s[3], s[4], 11, w[11]);
  SHA256ROUND_AVX(s[4], s[5], s[6], s[7], s[0], s[1], s[2], s[3], 12, w[12]);
  SHA256ROUND_AVX(s[3], s[4], s[5], s[6], s[7], s[0], s[1], s[2], 13, w[13]);
  SHA256ROUND_AVX(s[2], s[3], s[4], s[5], s[6], s[7], s[0], s[1], 14, w[14]);
  SHA256ROUND_AVX(s[1], s[2], s[3], s[4], s[5], s[6], s[7], s[0], 15, w[15]);
  w[16] = ADD4_32(WSIGMA1_AVX(w[14]), w[0], w[9], WSIGMA0_AVX(w[1]));
  SHA256ROUND_AVX(s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7], 16, w[16]);
  w[17] = ADD4_32(WSIGMA1_AVX(w[15]), w[1], w[10], WSIGMA0_AVX(w[2]));
  SHA256ROUND_AVX(s[7], s[0], s[1], s[2], s[3], s[4], s[5], s[6], 17, w[17]);
  w[18] = ADD4_32(WSIGMA1_AVX(w[16]), w[2], w[11], WSIGMA0_AVX(w[3]));
  SHA256ROUND_AVX(s[6], s[7], s[0], s[1], s[2], s[3], s[4], s[5], 18, w[18]);
  w[19] = ADD4_32(WSIGMA1_AVX(w[17]), w[3], w[12], WSIGMA0_AVX(w[4]));
  SHA256ROUND_AVX(s[5], s[6], s[7], s[0], s[1], s[2], s[3], s[4], 19, w[19]);
  w[20] = ADD4_32(WSIGMA1_AVX(w[18]), w[4], w[13], WSIGMA0_AVX(w[5]));
  SHA256ROUND_AVX(s[4], s[5], s[6], s[7], s[0], s[1], s[2], s[3], 20, w[20]);
  w[21] = ADD4_32(WSIGMA1_AVX(w[19]), w[5], w[14], WSIGMA0_AVX(w[6]));
  SHA256ROUND_AVX(s[3], s[4], s[5], s[6], s[7], s[0], s[1], s[2], 21, w[21]);
  w[22] = ADD4_32(WSIGMA1_AVX(w[20]), w[6], w[15], WSIGMA0_AVX(w[7]));
  SHA256ROUND_AVX(s[2], s[3], s[4], s[5], s[6], s[7], s[0], s[1], 22, w[22]);
  w[23] = ADD4_32(WSIGMA1_AVX(w[21]), w[7], w[16], WSIGMA0_AVX(w[8]));
  SHA256ROUND_AVX(s[1], s[2], s[3], s[4], s[5], s[6], s[7], s[0], 23, w[23]);
  w[24] = ADD4_32(WSIGMA1_AVX(w[22]), w[8], w[17], WSIGMA0_AVX(w[9]));
  SHA256ROUND_AVX(s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7], 24, w[24]);
  w[25] = ADD4_32(WSIGMA1_AVX(w[23]), w[9], w[18], WSIGMA0_AVX(w[10]));
  SHA256ROUND_AVX(s[7], s[0], s[1], s[2], s[3], s[4], s[5], s[6], 25, w[25]);
  w[26] = ADD4_32(WSIGMA1_AVX(w[24]), w[10], w[19], WSIGMA0_AVX(w[11]));
  SHA256ROUND_AVX(s[6], s[7], s[0], s[1], s[2], s[3], s[4], s[5], 26, w[26]);
  w[27] = ADD4_32(WSIGMA1_AVX(w[25]), w[11], w[20], WSIGMA0_AVX(w[12]));
  SHA256ROUND_AVX(s[5], s[6], s[7], s[0], s[1], s[2], s[3], s[4], 27, w[27]);
  w[28] = ADD4_32(WSIGMA1_AVX(w[26]), w[12], w[21], WSIGMA0_AVX(w[13]));
  SHA256ROUND_AVX(s[4], s[5], s[6], s[7], s[0], s[1], s[2], s[3], 28, w[28]);
  w[29] = ADD4_32(WSIGMA1_AVX(w[27]), w[13], w[22], WSIGMA0_AVX(w[14]));
  SHA256ROUND_AVX(s[3], s[4], s[5], s[6], s[7], s[0], s[1], s[2], 29, w[29]);
  w[30] = ADD4_32(WSIGMA1_AVX(w[28]), w[14], w[23], WSIGMA0_AVX(w[15]));
  SHA256ROUND_AVX(s[2], s[3], s[4], s[5], s[6], s[7], s[0], s[1], 30, w[30]);
  w[31] = ADD4_32(WSIGMA1_AVX(w[29]), w[15], w[24], WSIGMA0_AVX(w[16]));
  SHA256ROUND_AVX(s[1], s[2], s[3], s[4], s[5], s[6], s[7], s[0], 31, w[31]);
  w[32] = ADD4_32(WSIGMA1_AVX(w[30]), w[16], w[25], WSIGMA0_AVX(w[17]));
  SHA256ROUND_AVX(s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7], 32, w[32]);
  w[33] = ADD4_32(WSIGMA1_AVX(w[31]), w[17], w[26], WSIGMA0_AVX(w[18]));
  SHA256ROUND_AVX(s[7], s[0], s[1], s[2], s[3], s[4], s[5], s[6], 33, w[33]);
  w[34] = ADD4_32(WSIGMA1_AVX(w[32]), w[18], w[27], WSIGMA0_AVX(w[19]));
  SHA256ROUND_AVX(s[6], s[7], s[0], s[1], s[2], s[3], s[4], s[5], 34, w[34]);
  w[35] = ADD4_32(WSIGMA1_AVX(w[33]), w[19], w[28], WSIGMA0_AVX(w[20]));
  SHA256ROUND_AVX(s[5], s[6], s[7], s[0], s[1], s[2], s[3], s[4], 35, w[35]);
  w[36] = ADD4_32(WSIGMA1_AVX(w[34]), w[20], w[29], WSIGMA0_AVX(w[21]));
  SHA256ROUND_AVX(s[4], s[5], s[6], s[7], s[0], s[1], s[2], s[3], 36, w[36]);
  w[37] = ADD4_32(WSIGMA1_AVX(w[35]), w[21], w[30], WSIGMA0_AVX(w[22]));
  SHA256ROUND_AVX(s[3], s[4], s[5], s[6], s[7], s[0], s[1], s[2], 37, w[37]);
  w[38] = ADD4_32(WSIGMA1_AVX(w[36]), w[22], w[31], WSIGMA0_AVX(w[23]));
  SHA256ROUND_AVX(s[2], s[3], s[4], s[5], s[6], s[7], s[0], s[1], 38, w[38]);
  w[39] = ADD4_32(WSIGMA1_AVX(w[37]), w[23], w[32], WSIGMA0_AVX(w[24]));
  SHA256ROUND_AVX(s[1], s[2], s[3], s[4], s[5], s[6], s[7], s[0], 39, w[39]);
  w[40] = ADD4_32(WSIGMA1_AVX(w[38]), w[24], w[33], WSIGMA0_AVX(w[25]));
  SHA256ROUND_AVX(s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7], 40, w[40]);
  w[41] = ADD4_32(WSIGMA1_AVX(w[39]), w[25], w[34], WSIGMA0_AVX(w[26]));
  SHA256ROUND_AVX(s[7], s[0], s[1], s[2], s[3], s[4], s[5], s[6], 41, w[41]);
  w[42] = ADD4_32(WSIGMA1_AVX(w[40]), w[26], w[35], WSIGMA0_AVX(w[27]));
  SHA256ROUND_AVX(s[6], s[7], s[0], s[1], s[2], s[3], s[4], s[5], 42, w[42]);
  w[43] = ADD4_32(WSIGMA1_AVX(w[41]), w[27], w[36], WSIGMA0_AVX(w[28]));
  SHA256ROUND_AVX(s[5], s[6], s[7], s[0], s[1], s[2], s[3], s[4], 43, w[43]);
  w[44] = ADD4_32(WSIGMA1_AVX(w[42]), w[28], w[37], WSIGMA0_AVX(w[29]));
  SHA256ROUND_AVX(s[4], s[5], s[6], s[7], s[0], s[1], s[2], s[3], 44, w[44]);
  w[45] = ADD4_32(WSIGMA1_AVX(w[43]), w[29], w[38], WSIGMA0_AVX(w[30]));
  SHA256ROUND_AVX(s[3], s[4], s[5], s[6], s[7], s[0], s[1], s[2], 45, w[45]);
  w[46] = ADD4_32(WSIGMA1_AVX(w[44]), w[30], w[39], WSIGMA0_AVX(w[31]));
  SHA256ROUND_AVX(s[2], s[3], s[4], s[5], s[6], s[7], s[0], s[1], 46, w[46]);
  w[47] = ADD4_32(WSIGMA1_AVX(w[45]), w[31], w[40], WSIGMA0_AVX(w[32]));
  SHA256ROUND_AVX(s[1], s[2], s[3], s[4], s[5], s[6], s[7], s[0], 47, w[47]);
  w[48] = ADD4_32(WSIGMA1_AVX(w[46]), w[32], w[41], WSIGMA0_AVX(w[33]));
  SHA256ROUND_AVX(s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7], 48, w[48]);
  w[49] = ADD4_32(WSIGMA1_AVX(w[47]), w[33], w[42], WSIGMA0_AVX(w[34]));
  SHA256ROUND_AVX(s[7], s[0], s[1], s[2], s[3], s[4], s[5], s[6], 49, w[49]);
  w[50] = ADD4_32(WSIGMA1_AVX(w[48]), w[34], w[43], WSIGMA0_AVX(w[35]));
  SHA256ROUND_AVX(s[6], s[7], s[0], s[1], s[2], s[3], s[4], s[5], 50, w[50]);
  w[51] = ADD4_32(WSIGMA1_AVX(w[49]), w[35], w[44], WSIGMA0_AVX(w[36]));
  SHA256ROUND_AVX(s[5], s[6], s[7], s[0], s[1], s[2], s[3], s[4], 51, w[51]);
  w[52] = ADD4_32(WSIGMA1_AVX(w[50]), w[36], w[45], WSIGMA0_AVX(w[37]));
  SHA256ROUND_AVX(s[4], s[5], s[6], s[7], s[0], s[1], s[2], s[3], 52, w[52]);
  w[53] = ADD4_32(WSIGMA1_AVX(w[51]), w[37], w[46], WSIGMA0_AVX(w[38]));
  SHA256ROUND_AVX(s[3], s[4], s[5], s[6], s[7], s[0], s[1], s[2], 53, w[53]);
  w[54] = ADD4_32(WSIGMA1_AVX(w[52]), w[38], w[47], WSIGMA0_AVX(w[39]));
  SHA256ROUND_AVX(s[2], s[3], s[4], s[5], s[6], s[7], s[0], s[1], 54, w[54]);
  w[55] = ADD4_32(WSIGMA1_AVX(w[53]), w[39], w[48], WSIGMA0_AVX(w[40]));
  SHA256ROUND_AVX(s[1], s[2], s[3], s[4], s[5], s[6], s[7], s[0], 55, w[55]);
  w[56] = ADD4_32(WSIGMA1_AVX(w[54]), w[40], w[49], WSIGMA0_AVX(w[41]));
  SHA256ROUND_AVX(s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7], 56, w[56]);
  w[57] = ADD4_32(WSIGMA1_AVX(w[55]), w[41], w[50], WSIGMA0_AVX(w[42]));
  SHA256ROUND_AVX(s[7], s[0], s[1], s[2], s[3], s[4], s[5], s[6], 57, w[57]);
  w[58] = ADD4_32(WSIGMA1_AVX(w[56]), w[42], w[51], WSIGMA0_AVX(w[43]));
  SHA256ROUND_AVX(s[6], s[7], s[0], s[1], s[2], s[3], s[4], s[5], 58, w[58]);
  w[59] = ADD4_32(WSIGMA1_AVX(w[57]), w[43], w[52], WSIGMA0_AVX(w[44]));
  SHA256ROUND_AVX(s[5], s[6], s[7], s[0], s[1], s[2], s[3], s[4], 59, w[59]);
  w[60] = ADD4_32(WSIGMA1_AVX(w[58]), w[44], w[53], WSIGMA0_AVX(w[45]));
  SHA256ROUND_AVX(s[4], s[5], s[6], s[7], s[0], s[1], s[2], s[3], 60, w[60]);
  w[61] = ADD4_32(WSIGMA1_AVX(w[59]), w[45], w[54], WSIGMA0_AVX(w[46]));
  SHA256ROUND_AVX(s[3], s[4], s[5], s[6], s[7], s[0], s[1], s[2], 61, w[61]);
  w[62] = ADD4_32(WSIGMA1_AVX(w[60]), w[46], w[55], WSIGMA0_AVX(w[47]));
  SHA256ROUND_AVX(s[2], s[3], s[4], s[5], s[6], s[7], s[0], s[1], 62, w[62]);
  w[63] = ADD4_32(WSIGMA1_AVX(w[61]), w[47], w[56], WSIGMA0_AVX(w[48]));
  SHA256ROUND_AVX(s[1], s[2], s[3], s[4], s[5], s[6], s[7], s[0], 63, w[63]);

  // Feed Forward
  ctx->s[0] = ADD32(s[0], ctx->s[0]);
  ctx->s[1] = ADD32(s[1], ctx->s[1]);
  ctx->s[2] = ADD32(s[2], ctx->s[2]);
  ctx->s[3] = ADD32(s[3], ctx->s[3]);
  ctx->s[4] = ADD32(s[4], ctx->s[4]);
  ctx->s[5] = ADD32(s[5], ctx->s[5]);
  ctx->s[6] = ADD32(s[6], ctx->s[6]);
  ctx->s[7] = ADD32(s[7], ctx->s[7]);
}


static uint32_t load_bigendian_32(const uint8_t *x)
{
  return (uint32_t)(x[3]) | (((uint32_t)(x[2])) << 8) | (((uint32_t)(x[1])) << 16) | (((uint32_t)(x[0])) << 24);
}

// Performs sha256x8 on an initialized (and perhaps seeded) state.
static void _sha256x8(sha256ctx *ctx,
                      unsigned char *out0,
                      unsigned char *out1,
                      unsigned char *out2,
                      unsigned char *out3,
                      unsigned char *out4,
                      unsigned char *out5,
                      unsigned char *out6,
                      unsigned char *out7,
                      const unsigned char *in0,
                      const unsigned char *in1,
                      const unsigned char *in2,
                      const unsigned char *in3,
                      const unsigned char *in4,
                      const unsigned char *in5,
                      const unsigned char *in6,
                      const unsigned char *in7,
                      unsigned long long inlen)
{
  unsigned long long i = 0;
  int bytes_to_copy;
  while (inlen - i >= 64)
    {
      sha256_transform8x(ctx, in0 + i, in1 + i, in2 + i, in3 + i, in4 + i, in5 + i, in6 + i, in7 + i);
      i += 64;
      ctx->msglen += 512;
    }

  bytes_to_copy = inlen - i;
  memcpy(&ctx->msgblocks[64 * 0], in0 + i, bytes_to_copy);
  memcpy(&ctx->msgblocks[64 * 1], in1 + i, bytes_to_copy);
  memcpy(&ctx->msgblocks[64 * 2], in2 + i, bytes_to_copy);
  memcpy(&ctx->msgblocks[64 * 3], in3 + i, bytes_to_copy);
  memcpy(&ctx->msgblocks[64 * 4], in4 + i, bytes_to_copy);
  memcpy(&ctx->msgblocks[64 * 5], in5 + i, bytes_to_copy);
  memcpy(&ctx->msgblocks[64 * 6], in6 + i, bytes_to_copy);
  memcpy(&ctx->msgblocks[64 * 7], in7 + i, bytes_to_copy);
  ctx->datalen = bytes_to_copy;

  sha256_final8x(ctx, out0, out1, out2, out3, out4, out5, out6, out7);
}

void sha256x8_seeded(unsigned char *out0,
                     unsigned char *out1,
                     unsigned char *out2,
                     unsigned char *out3,
                     unsigned char *out4,
                     unsigned char *out5,
                     unsigned char *out6,
                     unsigned char *out7,
                     const unsigned char *seed,
                     unsigned long long seedlen,
                     const unsigned char *in0,
                     const unsigned char *in1,
                     const unsigned char *in2,
                     const unsigned char *in3,
                     const unsigned char *in4,
                     const unsigned char *in5,
                     const unsigned char *in6,
                     const unsigned char *in7,
                     unsigned long long inlen)
{
  uint32_t t;

  sha256ctx ctx;

  for (size_t i = 0; i < 8; i++)
    {
      t        = load_bigendian_32(seed + 4 * i);
      ctx.s[i] = _mm256_set_epi32(t, t, t, t, t, t, t, t);
    }

  ctx.datalen = 0;
  ctx.msglen  = seedlen;

  _sha256x8(&ctx, out0, out1, out2, out3, out4, out5, out6, out7, in0, in1, in2, in3, in4, in5, in6, in7, inlen);
}

/* This provides a wrapper around the internals of 8x parallel SHA256 */
void sha256x8(unsigned char *out0,
              unsigned char *out1,
              unsigned char *out2,
              unsigned char *out3,
              unsigned char *out4,
              unsigned char *out5,
              unsigned char *out6,
              unsigned char *out7,
              const unsigned char *in0,
              const unsigned char *in1,
              const unsigned char *in2,
              const unsigned char *in3,
              const unsigned char *in4,
              const unsigned char *in5,
              const unsigned char *in6,
              const unsigned char *in7,
              unsigned long long inlen)
{
  sha256ctx ctx;
  sha256_init8x(&ctx);

  _sha256x8(&ctx, out0, out1, out2, out3, out4, out5, out6, out7, in0, in1, in2, in3, in4, in5, in6, in7, inlen);
}


/* the following functions are required for initializing the hash with the public seed */

#define SHR(x, c) ((x) >> (c))
#define ROTR_32(x, c) (((x) >> (c)) | ((x) << (32 - (c))))
#define ROTR_64(x, c) (((x) >> (c)) | ((x) << (64 - (c))))
#define Ch(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define Maj(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define Sigma0_32(x) (ROTR_32(x, 2) ^ ROTR_32(x, 13) ^ ROTR_32(x, 22))
#define Sigma1_32(x) (ROTR_32(x, 6) ^ ROTR_32(x, 11) ^ ROTR_32(x, 25))
#define sigma0_32(x) (ROTR_32(x, 7) ^ ROTR_32(x, 18) ^ SHR(x, 3))
#define sigma1_32(x) (ROTR_32(x, 17) ^ ROTR_32(x, 19) ^ SHR(x, 10))
#define M_32(w0, w14, w9, w1) w0 = sigma1_32(w14) + (w9) + sigma0_32(w1) + (w0);

#define EXPAND_32                                                                                                      \
  M_32(w0, w14, w9, w1)                                                                                                \
  M_32(w1, w15, w10, w2)                                                                                               \
  M_32(w2, w0, w11, w3)                                                                                                \
  M_32(w3, w1, w12, w4)                                                                                                \
  M_32(w4, w2, w13, w5)                                                                                                \
  M_32(w5, w3, w14, w6)                                                                                                \
  M_32(w6, w4, w15, w7)                                                                                                \
  M_32(w7, w5, w0, w8)                                                                                                 \
  M_32(w8, w6, w1, w9)                                                                                                 \
  M_32(w9, w7, w2, w10)                                                                                                \
  M_32(w10, w8, w3, w11)                                                                                               \
  M_32(w11, w9, w4, w12)                                                                                               \
  M_32(w12, w10, w5, w13)                                                                                              \
  M_32(w13, w11, w6, w14)                                                                                              \
  M_32(w14, w12, w7, w15)                                                                                              \
  M_32(w15, w13, w8, w0)

#define F_32(w, k)                                                                                                     \
  T1 = h + Sigma1_32(e) + Ch(e, f, g) + (k) + (w);                                                                     \
  T2 = Sigma0_32(a) + Maj(a, b, c);                                                                                    \
  h  = g;                                                                                                              \
  g  = f;                                                                                                              \
  f  = e;                                                                                                              \
  e  = d + T1;                                                                                                         \
  d  = c;                                                                                                              \
  c  = b;                                                                                                              \
  b  = a;                                                                                                              \
  a  = T1 + T2;

static uint64_t load_bigendian_64(const uint8_t *x)
{
  return (uint64_t)(x[7]) | (((uint64_t)(x[6])) << 8) | (((uint64_t)(x[5])) << 16) | (((uint64_t)(x[4])) << 24)
         | (((uint64_t)(x[3])) << 32) | (((uint64_t)(x[2])) << 40) | (((uint64_t)(x[1])) << 48)
         | (((uint64_t)(x[0])) << 56);
}

static void store_bigendian_32(uint8_t *x, uint64_t u)
{
  x[3] = (uint8_t)u;
  u >>= 8;
  x[2] = (uint8_t)u;
  u >>= 8;
  x[1] = (uint8_t)u;
  u >>= 8;
  x[0] = (uint8_t)u;
}

static void store_bigendian_64(uint8_t *x, uint64_t u)
{
  x[7] = (uint8_t)u;
  u >>= 8;
  x[6] = (uint8_t)u;
  u >>= 8;
  x[5] = (uint8_t)u;
  u >>= 8;
  x[4] = (uint8_t)u;
  u >>= 8;
  x[3] = (uint8_t)u;
  u >>= 8;
  x[2] = (uint8_t)u;
  u >>= 8;
  x[1] = (uint8_t)u;
  u >>= 8;
  x[0] = (uint8_t)u;
}

static const uint8_t iv_256[32]
    = {0x6a, 0x09, 0xe6, 0x67, 0xbb, 0x67, 0xae, 0x85, 0x3c, 0x6e, 0xf3, 0x72, 0xa5, 0x4f, 0xf5, 0x3a,
       0x51, 0x0e, 0x52, 0x7f, 0x9b, 0x05, 0x68, 0x8c, 0x1f, 0x83, 0xd9, 0xab, 0x5b, 0xe0, 0xcd, 0x19};

static size_t crypto_hashblocks_sha256(uint8_t *statebytes, const uint8_t *in, size_t inlen)
{
  uint32_t state[8];
  uint32_t a;
  uint32_t b;
  uint32_t c;
  uint32_t d;
  uint32_t e;
  uint32_t f;
  uint32_t g;
  uint32_t h;
  uint32_t T1;
  uint32_t T2;

  a        = load_bigendian_32(statebytes + 0);
  state[0] = a;
  b        = load_bigendian_32(statebytes + 4);
  state[1] = b;
  c        = load_bigendian_32(statebytes + 8);
  state[2] = c;
  d        = load_bigendian_32(statebytes + 12);
  state[3] = d;
  e        = load_bigendian_32(statebytes + 16);
  state[4] = e;
  f        = load_bigendian_32(statebytes + 20);
  state[5] = f;
  g        = load_bigendian_32(statebytes + 24);
  state[6] = g;
  h        = load_bigendian_32(statebytes + 28);
  state[7] = h;

  while (inlen >= 64)
    {
      uint32_t w0  = load_bigendian_32(in + 0);
      uint32_t w1  = load_bigendian_32(in + 4);
      uint32_t w2  = load_bigendian_32(in + 8);
      uint32_t w3  = load_bigendian_32(in + 12);
      uint32_t w4  = load_bigendian_32(in + 16);
      uint32_t w5  = load_bigendian_32(in + 20);
      uint32_t w6  = load_bigendian_32(in + 24);
      uint32_t w7  = load_bigendian_32(in + 28);
      uint32_t w8  = load_bigendian_32(in + 32);
      uint32_t w9  = load_bigendian_32(in + 36);
      uint32_t w10 = load_bigendian_32(in + 40);
      uint32_t w11 = load_bigendian_32(in + 44);
      uint32_t w12 = load_bigendian_32(in + 48);
      uint32_t w13 = load_bigendian_32(in + 52);
      uint32_t w14 = load_bigendian_32(in + 56);
      uint32_t w15 = load_bigendian_32(in + 60);

      F_32(w0, 0x428a2f98)
      F_32(w1, 0x71374491)
      F_32(w2, 0xb5c0fbcf)
      F_32(w3, 0xe9b5dba5)
      F_32(w4, 0x3956c25b)
      F_32(w5, 0x59f111f1)
      F_32(w6, 0x923f82a4)
      F_32(w7, 0xab1c5ed5)
      F_32(w8, 0xd807aa98)
      F_32(w9, 0x12835b01)
      F_32(w10, 0x243185be)
      F_32(w11, 0x550c7dc3)
      F_32(w12, 0x72be5d74)
      F_32(w13, 0x80deb1fe)
      F_32(w14, 0x9bdc06a7)
      F_32(w15, 0xc19bf174)

      EXPAND_32

      F_32(w0, 0xe49b69c1)
      F_32(w1, 0xefbe4786)
      F_32(w2, 0x0fc19dc6)
      F_32(w3, 0x240ca1cc)
      F_32(w4, 0x2de92c6f)
      F_32(w5, 0x4a7484aa)
      F_32(w6, 0x5cb0a9dc)
      F_32(w7, 0x76f988da)
      F_32(w8, 0x983e5152)
      F_32(w9, 0xa831c66d)
      F_32(w10, 0xb00327c8)
      F_32(w11, 0xbf597fc7)
      F_32(w12, 0xc6e00bf3)
      F_32(w13, 0xd5a79147)
      F_32(w14, 0x06ca6351)
      F_32(w15, 0x14292967)

      EXPAND_32

      F_32(w0, 0x27b70a85)
      F_32(w1, 0x2e1b2138)
      F_32(w2, 0x4d2c6dfc)
      F_32(w3, 0x53380d13)
      F_32(w4, 0x650a7354)
      F_32(w5, 0x766a0abb)
      F_32(w6, 0x81c2c92e)
      F_32(w7, 0x92722c85)
      F_32(w8, 0xa2bfe8a1)
      F_32(w9, 0xa81a664b)
      F_32(w10, 0xc24b8b70)
      F_32(w11, 0xc76c51a3)
      F_32(w12, 0xd192e819)
      F_32(w13, 0xd6990624)
      F_32(w14, 0xf40e3585)
      F_32(w15, 0x106aa070)

      EXPAND_32

      F_32(w0, 0x19a4c116)
      F_32(w1, 0x1e376c08)
      F_32(w2, 0x2748774c)
      F_32(w3, 0x34b0bcb5)
      F_32(w4, 0x391c0cb3)
      F_32(w5, 0x4ed8aa4a)
      F_32(w6, 0x5b9cca4f)
      F_32(w7, 0x682e6ff3)
      F_32(w8, 0x748f82ee)
      F_32(w9, 0x78a5636f)
      F_32(w10, 0x84c87814)
      F_32(w11, 0x8cc70208)
      F_32(w12, 0x90befffa)
      F_32(w13, 0xa4506ceb)
      F_32(w14, 0xbef9a3f7)
      F_32(w15, 0xc67178f2)

      a += state[0];
      b += state[1];
      c += state[2];
      d += state[3];
      e += state[4];
      f += state[5];
      g += state[6];
      h += state[7];

      state[0] = a;
      state[1] = b;
      state[2] = c;
      state[3] = d;
      state[4] = e;
      state[5] = f;
      state[6] = g;
      state[7] = h;

      in += 64;
      inlen -= 64;
    }

  store_bigendian_32(statebytes + 0, state[0]);
  store_bigendian_32(statebytes + 4, state[1]);
  store_bigendian_32(statebytes + 8, state[2]);
  store_bigendian_32(statebytes + 12, state[3]);
  store_bigendian_32(statebytes + 16, state[4]);
  store_bigendian_32(statebytes + 20, state[5]);
  store_bigendian_32(statebytes + 24, state[6]);
  store_bigendian_32(statebytes + 28, state[7]);

  return inlen;
}

void sha256_inc_init(uint8_t *state)
{
  for (size_t i = 0; i < 32; ++i)
    {
      state[i] = iv_256[i];
    }
  for (size_t i = 32; i < 40; ++i)
    {
      state[i] = 0;
    }
}

void sha256_inc_blocks(uint8_t *state, const uint8_t *in, size_t inblocks)
{
  uint64_t bytes = load_bigendian_64(state + 32);

  crypto_hashblocks_sha256(state, in, 64 * inblocks);
  bytes += 64 * inblocks;

  store_bigendian_64(state + 32, bytes);
}


#endif
