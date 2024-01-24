#include <stdint.h>
#include <immintrin.h>
#include <string.h>
#include "mlkem-polyvec-avx2.h"
#include "mlkem-poly-avx2.h"
#include "mlkem-ntt-avx2.h"
#include "mlkem-consts-avx2.h"

/* the following functions are for allocating 32-byte aligned memory */
gcry_err_code_t
_gcry_mlkem_polybuf_al_create (gcry_mlkem_polybuf_al *buf,
                               size_t num_elems,
                               size_t size_elems,
                               int secure)
{
  const size_t alloc_size = num_elems * size_elems + /*align*/ 32;
  if (secure)
    buf->alloc_addr = xtrymalloc_secure (alloc_size);
  else
    buf->alloc_addr = xtrymalloc (alloc_size);

  if (!buf->alloc_addr)
    {
      buf->buf = NULL;
      return gpg_error_from_syserror ();
    }
  buf->buf = (byte *)((uintptr_t)buf->alloc_addr
                      + (32 - ((uintptr_t)buf->alloc_addr % 32)));

  memset (buf->alloc_addr, 0, alloc_size);
  return 0;
}

void
_gcry_mlkem_polybuf_al_destroy (gcry_mlkem_polybuf_al *buf)
{
  if (buf->alloc_addr)
    {
      xfree (buf->alloc_addr);
    }
  buf->buf        = NULL;
  buf->alloc_addr = NULL;
}

gcry_err_code_t
_gcry_mlkem_buf_al_create (gcry_mlkem_buf_al *buf, size_t size, int secure)
{
  const size_t alloc_size = size + /*align*/ 32;
  if (secure)
    buf->alloc_addr = xtrymalloc_secure (alloc_size);
  else
    buf->alloc_addr = xtrymalloc (alloc_size);

  if (!buf->alloc_addr)
    {
      buf->buf = NULL;
      return gpg_error_from_syserror ();
    }
  buf->buf = (byte *)((uintptr_t)buf->alloc_addr
                      + (32 - ((uintptr_t)buf->alloc_addr % 32)));

  memset (buf->alloc_addr, 0, alloc_size);
  return 0;
}

void
_gcry_mlkem_buf_al_destroy (gcry_mlkem_buf_al *buf)
{
  if (buf->alloc_addr)
    {
      xfree (buf->alloc_addr);
    }
  buf->buf        = NULL;
  buf->alloc_addr = NULL;
}

static void
poly_compress10 (uint8_t r[320], const gcry_mlkem_poly *restrict a)
{
  unsigned int i;
  __m256i f0, f1, f2;
  __m128i t0, t1;
  const __m256i v      = _mm256_load_si256 (&qdata.vec[_16XV / 16]);
  const __m256i v8     = _mm256_slli_epi16 (v, 3);
  const __m256i off    = _mm256_set1_epi16 (15);
  const __m256i shift1 = _mm256_set1_epi16 (1 << 12);
  const __m256i mask   = _mm256_set1_epi16 (1023);
  const __m256i shift2
      = _mm256_set1_epi64x ((1024LL << 48) + (1LL << 32) + (1024 << 16) + 1);
  const __m256i sllvdidx = _mm256_set1_epi64x (12);
  const __m256i shufbidx = _mm256_set_epi8 (8,
                                            4,
                                            3,
                                            2,
                                            1,
                                            0,
                                            -1,
                                            -1,
                                            -1,
                                            -1,
                                            -1,
                                            -1,
                                            12,
                                            11,
                                            10,
                                            9,
                                            -1,
                                            -1,
                                            -1,
                                            -1,
                                            -1,
                                            -1,
                                            12,
                                            11,
                                            10,
                                            9,
                                            8,
                                            4,
                                            3,
                                            2,
                                            1,
                                            0);

  for (i = 0; i < GCRY_MLKEM_N / 16; i++)
    {
      f0 = _mm256_load_si256 (&a->vec[i]);
      f1 = _mm256_mullo_epi16 (f0, v8);
      f2 = _mm256_add_epi16 (f0, off);
      f0 = _mm256_slli_epi16 (f0, 3);
      f0 = _mm256_mulhi_epi16 (f0, v);
      f2 = _mm256_sub_epi16 (f1, f2);
      f1 = _mm256_andnot_si256 (f1, f2);
      f1 = _mm256_srli_epi16 (f1, 15);
      f0 = _mm256_sub_epi16 (f0, f1);
      f0 = _mm256_mulhrs_epi16 (f0, shift1);
      f0 = _mm256_and_si256 (f0, mask);
      f0 = _mm256_madd_epi16 (f0, shift2);
      f0 = _mm256_sllv_epi32 (f0, sllvdidx);
      f0 = _mm256_srli_epi64 (f0, 12);
      f0 = _mm256_shuffle_epi8 (f0, shufbidx);
      t0 = _mm256_castsi256_si128 (f0);
      t1 = _mm256_extracti128_si256 (f0, 1);
      t0 = _mm_blend_epi16 (t0, t1, 0xE0);
      _mm_storeu_si128 ((__m128i *)&r[20 * i + 0], t0);
      memcpy (&r[20 * i + 16], &t1, 4);
    }
}

static void
poly_decompress10 (gcry_mlkem_poly *restrict r, const uint8_t a[320 + 12])
{
  unsigned int i;
  __m256i f;
  const __m256i q
      = _mm256_set1_epi32 ((GCRY_MLKEM_Q << 16) + 4 * GCRY_MLKEM_Q);
  const __m256i shufbidx = _mm256_set_epi8 (11,
                                            10,
                                            10,
                                            9,
                                            9,
                                            8,
                                            8,
                                            7,
                                            6,
                                            5,
                                            5,
                                            4,
                                            4,
                                            3,
                                            3,
                                            2,
                                            9,
                                            8,
                                            8,
                                            7,
                                            7,
                                            6,
                                            6,
                                            5,
                                            4,
                                            3,
                                            3,
                                            2,
                                            2,
                                            1,
                                            1,
                                            0);
  const __m256i sllvdidx = _mm256_set1_epi64x (4);
  const __m256i mask     = _mm256_set1_epi32 ((32736 << 16) + 8184);

  for (i = 0; i < GCRY_MLKEM_N / 16; i++)
    {
      f = _mm256_loadu_si256 ((__m256i *)&a[20 * i]);
      f = _mm256_permute4x64_epi64 (f, 0x94);
      f = _mm256_shuffle_epi8 (f, shufbidx);
      f = _mm256_sllv_epi32 (f, sllvdidx);
      f = _mm256_srli_epi16 (f, 1);
      f = _mm256_and_si256 (f, mask);
      f = _mm256_mulhrs_epi16 (f, q);
      _mm256_store_si256 (&r->vec[i], f);
    }
}

static void
poly_compress11 (uint8_t r[352 + 2], const gcry_mlkem_poly *restrict a)
{
  unsigned int i;
  __m256i f0, f1, f2;
  __m128i t0, t1;
  const __m256i v      = _mm256_load_si256 (&qdata.vec[_16XV / 16]);
  const __m256i v8     = _mm256_slli_epi16 (v, 3);
  const __m256i off    = _mm256_set1_epi16 (36);
  const __m256i shift1 = _mm256_set1_epi16 (1 << 13);
  const __m256i mask   = _mm256_set1_epi16 (2047);
  const __m256i shift2
      = _mm256_set1_epi64x ((2048LL << 48) + (1LL << 32) + (2048 << 16) + 1);
  const __m256i sllvdidx = _mm256_set1_epi64x (10);
  const __m256i srlvqidx = _mm256_set_epi64x (30, 10, 30, 10);
  const __m256i shufbidx = _mm256_set_epi8 (4,
                                            3,
                                            2,
                                            1,
                                            0,
                                            0,
                                            -1,
                                            -1,
                                            -1,
                                            -1,
                                            10,
                                            9,
                                            8,
                                            7,
                                            6,
                                            5,
                                            -1,
                                            -1,
                                            -1,
                                            -1,
                                            -1,
                                            10,
                                            9,
                                            8,
                                            7,
                                            6,
                                            5,
                                            4,
                                            3,
                                            2,
                                            1,
                                            0);

  for (i = 0; i < GCRY_MLKEM_N / 16; i++)
    {
      f0 = _mm256_load_si256 (&a->vec[i]);
      f1 = _mm256_mullo_epi16 (f0, v8);
      f2 = _mm256_add_epi16 (f0, off);
      f0 = _mm256_slli_epi16 (f0, 3);
      f0 = _mm256_mulhi_epi16 (f0, v);
      f2 = _mm256_sub_epi16 (f1, f2);
      f1 = _mm256_andnot_si256 (f1, f2);
      f1 = _mm256_srli_epi16 (f1, 15);
      f0 = _mm256_sub_epi16 (f0, f1);
      f0 = _mm256_mulhrs_epi16 (f0, shift1);
      f0 = _mm256_and_si256 (f0, mask);
      f0 = _mm256_madd_epi16 (f0, shift2);
      f0 = _mm256_sllv_epi32 (f0, sllvdidx);
      f1 = _mm256_bsrli_epi128 (f0, 8);
      f0 = _mm256_srlv_epi64 (f0, srlvqidx);
      f1 = _mm256_slli_epi64 (f1, 34);
      f0 = _mm256_add_epi64 (f0, f1);
      f0 = _mm256_shuffle_epi8 (f0, shufbidx);
      t0 = _mm256_castsi256_si128 (f0);
      t1 = _mm256_extracti128_si256 (f0, 1);
      t0 = _mm_blendv_epi8 (t0, t1, _mm256_castsi256_si128 (shufbidx));
      _mm_storeu_si128 ((__m128i *)&r[22 * i + 0], t0);
      _mm_storel_epi64 ((__m128i *)&r[22 * i + 16], t1);
    }
}

static void
poly_decompress11 (gcry_mlkem_poly *restrict r, const uint8_t a[352 + 10])
{
  unsigned int i;
  __m256i f;
  const __m256i q        = _mm256_load_si256 (&qdata.vec[_16XQ / 16]);
  const __m256i shufbidx = _mm256_set_epi8 (13,
                                            12,
                                            12,
                                            11,
                                            10,
                                            9,
                                            9,
                                            8,
                                            8,
                                            7,
                                            6,
                                            5,
                                            5,
                                            4,
                                            4,
                                            3,
                                            10,
                                            9,
                                            9,
                                            8,
                                            7,
                                            6,
                                            6,
                                            5,
                                            5,
                                            4,
                                            3,
                                            2,
                                            2,
                                            1,
                                            1,
                                            0);
  const __m256i srlvdidx = _mm256_set_epi32 (0, 0, 1, 0, 0, 0, 1, 0);
  const __m256i srlvqidx = _mm256_set_epi64x (2, 0, 2, 0);
  const __m256i shift    = _mm256_set_epi16 (
      4, 32, 1, 8, 32, 1, 4, 32, 4, 32, 1, 8, 32, 1, 4, 32);
  const __m256i mask = _mm256_set1_epi16 (32752);

  for (i = 0; i < GCRY_MLKEM_N / 16; i++)
    {
      f = _mm256_loadu_si256 ((__m256i *)&a[22 * i]);
      f = _mm256_permute4x64_epi64 (f, 0x94);
      f = _mm256_shuffle_epi8 (f, shufbidx);
      f = _mm256_srlv_epi32 (f, srlvdidx);
      f = _mm256_srlv_epi64 (f, srlvqidx);
      f = _mm256_mullo_epi16 (f, shift);
      f = _mm256_srli_epi16 (f, 1);
      f = _mm256_and_si256 (f, mask);
      f = _mm256_mulhrs_epi16 (f, q);
      _mm256_store_si256 (&r->vec[i], f);
    }
}

/*************************************************
 * Name:        _gcry_mlkem_avx2_polyvec_compress
 *
 * Description: Compress and serialize vector of polynomials
 *
 * Arguments:   - uint8_t *r: pointer to output byte array
 *              - polyvec *a: pointer to input vector of polynomials
 **************************************************/
void
_gcry_mlkem_avx2_polyvec_compress (uint8_t *r,
                                   const gcry_mlkem_poly *a,
                                   const gcry_mlkem_param_t *param)
{
  unsigned int i;

  if (param->polyvec_compressed_bytes == param->k * 320)
    {
      for (i = 0; i < param->k; i++)
        poly_compress10 (&r[320 * i], &a[i]);
    }
  else if (param->polyvec_compressed_bytes == (param->k * 352))
    {
      for (i = 0; i < param->k; i++)
        poly_compress11 (&r[352 * i], &a[i]);
    }
}

/*************************************************
 * Name:        _gcry_mlkem_avx2_polyvec_decompress
 *
 * Description: De-serialize and decompress vector of polynomials;
 *              approximate inverse of _gcry_mlkem_avx2_polyvec_compress
 *
 * Arguments:   - gcry_mlkem_poly *r: pointer to output vector of polynomials
 *              - const uint8_t *a: pointer to input byte array
 **************************************************/
void
_gcry_mlkem_avx2_polyvec_decompress (gcry_mlkem_poly *r,
                                     const uint8_t *a,
                                     const gcry_mlkem_param_t *param)
{
  unsigned int i;

  if (param->polyvec_compressed_bytes == param->k * 320)
    {
      for (i = 0; i < param->k; i++)
        poly_decompress10 (&r[i], &a[320 * i]);
    }
  else if (param->polyvec_compressed_bytes == (param->k * 352))
    {
      for (i = 0; i < param->k; i++)
        poly_decompress11 (&r[i], &a[352 * i]);
    }
}

/*************************************************
 * Name:        _gcry_mlkem_avx2_polyvec_tobytes
 *
 * Description: Serialize vector of polynomials
 *
 * Arguments:   - uint8_t *r: pointer to output byte array
 *                            (needs space for GCRY_MLKEM_POLYVECBYTES)
 *              - gcry_mlkem_poly *a: pointer to input vector of polynomials
 **************************************************/
void
_gcry_mlkem_avx2_polyvec_tobytes (uint8_t *r,
                                  const gcry_mlkem_poly *a,
                                  const gcry_mlkem_param_t *param)
{
  unsigned int i;
  for (i = 0; i < param->k; i++)
    _gcry_mlkem_avx2_poly_tobytes (r + i * GCRY_MLKEM_POLYBYTES, &a[i]);
}

/*************************************************
 * Name:        _gcry_mlkem_avx2_polyvec_frombytes
 *
 * Description: De-serialize vector of polynomials;
 *              inverse of _gcry_mlkem_avx2_polyvec_tobytes
 *
 * Arguments:   - uint8_t *r: pointer to output byte array
 *              - const polyvec *a: pointer to input vector of polynomials
 *                                  (of length GCRY_MLKEM_POLYVECBYTES)
 **************************************************/
void
_gcry_mlkem_avx2_polyvec_frombytes (gcry_mlkem_poly *r,
                                    const uint8_t *a,
                                    const gcry_mlkem_param_t *param)
{
  unsigned int i;
  for (i = 0; i < param->k; i++)
    _gcry_mlkem_avx2_poly_frombytes (&r[i], a + i * GCRY_MLKEM_POLYBYTES);
}

/*************************************************
 * Name:        _gcry_mlkem_avx2_polyvec_ntt
 *
 * Description: Apply forward NTT to all elements of a vector of polynomials
 *
 * Arguments:   - gcry_mlkem_poly *r: pointer to in/output vector of polynomials
 **************************************************/
void
_gcry_mlkem_avx2_polyvec_ntt (gcry_mlkem_poly *r,
                              const gcry_mlkem_param_t *param)
{
  unsigned int i;
  for (i = 0; i < param->k; i++)
    _gcry_mlkem_avx2_poly_ntt (&r[i]);
}

/*************************************************
 * Name:        _gcry_mlkem_avx2_polyvec_invntt_tomont
 *
 * Description: Apply inverse NTT to all elements of a vector of polynomials
 *              and multiply by Montgomery factor 2^16
 *
 * Arguments:   - gcry_mlkem_poly *r: pointer to in/output vector of polynomials
 **************************************************/
void
_gcry_mlkem_avx2_polyvec_invntt_tomont (gcry_mlkem_poly *r,
                                        const gcry_mlkem_param_t *param)
{
  unsigned int i;
  for (i = 0; i < param->k; i++)
    _gcry_mlkem_avx2_poly_invntt_tomont (&r[i]);
}

/*************************************************
 * Name:        _gcry_mlkem_avx2_polyvec_basemul_acc_montgomery
 *
 * Description: Multiply elements in a and b in NTT domain, accumulate into r,
 *              and multiply by 2^-16.
 *
 * Arguments: - gcry_mlkem_poly *r: pointer to output polynomial
 *            - const polyvec *a: pointer to first input vector of polynomials
 *            - const polyvec *b: pointer to second input vector of polynomials
 **************************************************/
gcry_err_code_t
_gcry_mlkem_avx2_polyvec_basemul_acc_montgomery (
    gcry_mlkem_poly *r,
    const gcry_mlkem_poly *a,
    const gcry_mlkem_poly *b,
    const gcry_mlkem_param_t *param)
{
  gcry_err_code_t ec = 0;
  unsigned int i;
  gcry_mlkem_buf_al tmp_al = {};
  gcry_mlkem_poly *tmp     = NULL;

  ec = _gcry_mlkem_buf_al_create (&tmp_al, sizeof (gcry_mlkem_poly), 1);
  if (ec)
    {
      goto leave;
    }
  tmp = (gcry_mlkem_poly *)tmp_al.buf;


  _gcry_mlkem_avx2_poly_basemul_montgomery (r, a, b);
  for (i = 1; i < param->k; i++)
    {
      _gcry_mlkem_avx2_poly_basemul_montgomery (tmp, &a[i], &b[i]);
      _gcry_mlkem_avx2_poly_add (r, r, tmp);
    }

leave:
  _gcry_mlkem_buf_al_destroy (&tmp_al);
  return ec;
}

/*************************************************
 * Name:        _gcry_mlkem_avx2_polyvec_reduce
 *
 * Description: Applies Barrett reduction to each coefficient
 *              of each element of a vector of polynomials;
 *              for details of the Barrett reduction see comments in reduce.c
 *
 * Arguments:   - polyvec *r: pointer to input/output polynomial
 **************************************************/
void
_gcry_mlkem_avx2_polyvec_reduce (gcry_mlkem_poly *r,
                                 const gcry_mlkem_param_t *param)
{
  unsigned int i;
  for (i = 0; i < param->k; i++)
    _gcry_mlkem_avx2_poly_reduce (&r[i]);
}

/*************************************************
 * Name:        _gcry_mlkem_avx2_polyvec_add
 *
 * Description: Add vectors of polynomials
 *
 * Arguments: - gcry_mlkem_poly *r:       pointer to output vector of polynomials
 *            - const gcry_mlkem_poly *a: pointer to first input vector of polynomials
 *            - const gcry_mlkem_poly *b: pointer to second input vector of polynomials
 **************************************************/
void
_gcry_mlkem_avx2_polyvec_add (gcry_mlkem_poly *r,
                              const gcry_mlkem_poly *a,
                              const gcry_mlkem_poly *b,
                              const gcry_mlkem_param_t *param)
{
  unsigned int i;
  for (i = 0; i < param->k; i++)
    _gcry_mlkem_avx2_poly_add (&r[i], &a[i], &b[i]);
}
