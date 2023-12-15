#include <config.h>

#include "types.h"
#include <string.h>

#include "slhdsa-thash-avx2.h"
#ifdef USE_AVX2

#include "slhdsa-hash.h"
#include "slhdsa-sha512x4.h"
#include "slhdsa-sha256x8.h"
#include "slhdsa-address.h"
#include "slhdsa-utils.h"

#include "g10lib.h"


static gcry_err_code_t thashx8_512(unsigned char *out0,
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
                                   unsigned int inblocks,
                                   const _gcry_slhdsa_param_t *ctx,
                                   uint32_t addrx8[8 * 8]);

/**
 * 8-way parallel version of thash; takes 8x as much input and output
 */
gcry_err_code_t gcry_slhdsa_thash_sha2_avx2(unsigned char *out0,
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
                                            unsigned int inblocks,
                                            const _gcry_slhdsa_param_t *ctx,
                                            uint32_t addrx8[8 * 8])
{
  gcry_err_code_t ec = 0;
  unsigned char bufx8[8 * (ctx->addr_bytes + inblocks * ctx->n)]; // TODO
  unsigned char outbufx8[8 * SLHDSA_SHA256_OUTPUT_BYTES];         // TODO
  unsigned int i;

  if (ctx->do_use_sha512)
    {
      if (inblocks > 1)
        {
          thashx8_512(out0,
                      out1,
                      out2,
                      out3,
                      out4,
                      out5,
                      out6,
                      out7,
                      in0,
                      in1,
                      in2,
                      in3,
                      in4,
                      in5,
                      in6,
                      in7,
                      inblocks,
                      ctx,
                      addrx8);
          goto leave;
        }
    }

  for (i = 0; i < 8; i++)
    {
      memcpy(bufx8 + i * (ctx->addr_bytes + inblocks * ctx->n), addrx8 + i * 8, ctx->addr_bytes);
    }

  memcpy(bufx8 + ctx->addr_bytes + 0 * (ctx->addr_bytes + inblocks * ctx->n), in0, inblocks * ctx->n);
  memcpy(bufx8 + ctx->addr_bytes + 1 * (ctx->addr_bytes + inblocks * ctx->n), in1, inblocks * ctx->n);
  memcpy(bufx8 + ctx->addr_bytes + 2 * (ctx->addr_bytes + inblocks * ctx->n), in2, inblocks * ctx->n);
  memcpy(bufx8 + ctx->addr_bytes + 3 * (ctx->addr_bytes + inblocks * ctx->n), in3, inblocks * ctx->n);
  memcpy(bufx8 + ctx->addr_bytes + 4 * (ctx->addr_bytes + inblocks * ctx->n), in4, inblocks * ctx->n);
  memcpy(bufx8 + ctx->addr_bytes + 5 * (ctx->addr_bytes + inblocks * ctx->n), in5, inblocks * ctx->n);
  memcpy(bufx8 + ctx->addr_bytes + 6 * (ctx->addr_bytes + inblocks * ctx->n), in6, inblocks * ctx->n);
  memcpy(bufx8 + ctx->addr_bytes + 7 * (ctx->addr_bytes + inblocks * ctx->n), in7, inblocks * ctx->n);

  sha256x8_seeded(
      /* out */
      outbufx8 + 0 * SLHDSA_SHA256_OUTPUT_BYTES,
      outbufx8 + 1 * SLHDSA_SHA256_OUTPUT_BYTES,
      outbufx8 + 2 * SLHDSA_SHA256_OUTPUT_BYTES,
      outbufx8 + 3 * SLHDSA_SHA256_OUTPUT_BYTES,
      outbufx8 + 4 * SLHDSA_SHA256_OUTPUT_BYTES,
      outbufx8 + 5 * SLHDSA_SHA256_OUTPUT_BYTES,
      outbufx8 + 6 * SLHDSA_SHA256_OUTPUT_BYTES,
      outbufx8 + 7 * SLHDSA_SHA256_OUTPUT_BYTES,

      /* seed */
      ctx->state_seeded_avx2,
      512,

      /* in */
      bufx8 + 0 * (ctx->addr_bytes + inblocks * ctx->n),
      bufx8 + 1 * (ctx->addr_bytes + inblocks * ctx->n),
      bufx8 + 2 * (ctx->addr_bytes + inblocks * ctx->n),
      bufx8 + 3 * (ctx->addr_bytes + inblocks * ctx->n),
      bufx8 + 4 * (ctx->addr_bytes + inblocks * ctx->n),
      bufx8 + 5 * (ctx->addr_bytes + inblocks * ctx->n),
      bufx8 + 6 * (ctx->addr_bytes + inblocks * ctx->n),
      bufx8 + 7 * (ctx->addr_bytes + inblocks * ctx->n),
      ctx->addr_bytes + inblocks * ctx->n /* len */
  );

  memcpy(out0, outbufx8 + 0 * SLHDSA_SHA256_OUTPUT_BYTES, ctx->n);
  memcpy(out1, outbufx8 + 1 * SLHDSA_SHA256_OUTPUT_BYTES, ctx->n);
  memcpy(out2, outbufx8 + 2 * SLHDSA_SHA256_OUTPUT_BYTES, ctx->n);
  memcpy(out3, outbufx8 + 3 * SLHDSA_SHA256_OUTPUT_BYTES, ctx->n);
  memcpy(out4, outbufx8 + 4 * SLHDSA_SHA256_OUTPUT_BYTES, ctx->n);
  memcpy(out5, outbufx8 + 5 * SLHDSA_SHA256_OUTPUT_BYTES, ctx->n);
  memcpy(out6, outbufx8 + 6 * SLHDSA_SHA256_OUTPUT_BYTES, ctx->n);
  memcpy(out7, outbufx8 + 7 * SLHDSA_SHA256_OUTPUT_BYTES, ctx->n);

leave:
  return ec;
}

/**
 * 2x4-way parallel version of thash; this is for the uses of thash that are
 * based on SHA-512
 */
gcry_err_code_t thashx8_512(unsigned char *out0,
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
                            unsigned int inblocks,
                            const _gcry_slhdsa_param_t *ctx,
                            uint32_t addrx8[8 * 8])
{
  gcry_err_code_t ec = 0;
  unsigned char bufx8[8 * (ctx->addr_bytes + inblocks * ctx->n)]; // TODO
  unsigned char outbuf[4 * SLHDSA_SHA512_OUTPUT_BYTES];           // TODO
  unsigned int i;

  for (i = 0; i < 8; i++)
    {
      memcpy(bufx8 + i * (ctx->addr_bytes + inblocks * ctx->n), addrx8 + i * 8, ctx->addr_bytes);
    }

  memcpy(bufx8 + ctx->addr_bytes + 0 * (ctx->addr_bytes + inblocks * ctx->n), in0, inblocks * ctx->n);
  memcpy(bufx8 + ctx->addr_bytes + 1 * (ctx->addr_bytes + inblocks * ctx->n), in1, inblocks * ctx->n);
  memcpy(bufx8 + ctx->addr_bytes + 2 * (ctx->addr_bytes + inblocks * ctx->n), in2, inblocks * ctx->n);
  memcpy(bufx8 + ctx->addr_bytes + 3 * (ctx->addr_bytes + inblocks * ctx->n), in3, inblocks * ctx->n);
  memcpy(bufx8 + ctx->addr_bytes + 4 * (ctx->addr_bytes + inblocks * ctx->n), in4, inblocks * ctx->n);
  memcpy(bufx8 + ctx->addr_bytes + 5 * (ctx->addr_bytes + inblocks * ctx->n), in5, inblocks * ctx->n);
  memcpy(bufx8 + ctx->addr_bytes + 6 * (ctx->addr_bytes + inblocks * ctx->n), in6, inblocks * ctx->n);
  memcpy(bufx8 + ctx->addr_bytes + 7 * (ctx->addr_bytes + inblocks * ctx->n), in7, inblocks * ctx->n);

  sha512x4_seeded(outbuf + 0 * SLHDSA_SHA512_OUTPUT_BYTES,
                  outbuf + 1 * SLHDSA_SHA512_OUTPUT_BYTES,
                  outbuf + 2 * SLHDSA_SHA512_OUTPUT_BYTES,
                  outbuf + 3 * SLHDSA_SHA512_OUTPUT_BYTES,
                  ctx->state_seeded_512_avx2,                        /* seed */
                  1024,                                              /* seed length */
                  bufx8 + 0 * (ctx->addr_bytes + inblocks * ctx->n), /* in */
                  bufx8 + 1 * (ctx->addr_bytes + inblocks * ctx->n),
                  bufx8 + 2 * (ctx->addr_bytes + inblocks * ctx->n),
                  bufx8 + 3 * (ctx->addr_bytes + inblocks * ctx->n),
                  ctx->addr_bytes + inblocks * ctx->n /* len */
  );

  memcpy(out0, outbuf + 0 * SLHDSA_SHA512_OUTPUT_BYTES, ctx->n);
  memcpy(out1, outbuf + 1 * SLHDSA_SHA512_OUTPUT_BYTES, ctx->n);
  memcpy(out2, outbuf + 2 * SLHDSA_SHA512_OUTPUT_BYTES, ctx->n);
  memcpy(out3, outbuf + 3 * SLHDSA_SHA512_OUTPUT_BYTES, ctx->n);

  sha512x4_seeded(outbuf + 0 * SLHDSA_SHA512_OUTPUT_BYTES,
                  outbuf + 1 * SLHDSA_SHA512_OUTPUT_BYTES,
                  outbuf + 2 * SLHDSA_SHA512_OUTPUT_BYTES,
                  outbuf + 3 * SLHDSA_SHA512_OUTPUT_BYTES,
                  ctx->state_seeded_512_avx2,                        /* seed */
                  1024,                                              /* seed length */
                  bufx8 + 4 * (ctx->addr_bytes + inblocks * ctx->n), /* in */
                  bufx8 + 5 * (ctx->addr_bytes + inblocks * ctx->n),
                  bufx8 + 6 * (ctx->addr_bytes + inblocks * ctx->n),
                  bufx8 + 7 * (ctx->addr_bytes + inblocks * ctx->n),
                  ctx->addr_bytes + inblocks * ctx->n /* len */
  );

  memcpy(out4, outbuf + 0 * SLHDSA_SHA512_OUTPUT_BYTES, ctx->n);
  memcpy(out5, outbuf + 1 * SLHDSA_SHA512_OUTPUT_BYTES, ctx->n);
  memcpy(out6, outbuf + 2 * SLHDSA_SHA512_OUTPUT_BYTES, ctx->n);
  memcpy(out7, outbuf + 3 * SLHDSA_SHA512_OUTPUT_BYTES, ctx->n);

leave:
  return ec;
}
#endif