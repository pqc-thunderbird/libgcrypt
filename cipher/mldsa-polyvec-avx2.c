#include <stdint.h>
#include "config.h"
#include "mldsa-polyvec-avx2.h"
#include "mldsa-polyvec.h"
#include "mldsa-poly-avx2.h"
#include "mldsa-ntt-avx2.h"
#include "mldsa-consts-avx2.h"

gcry_err_code_t _gcry_mldsa_polybuf_al_create(gcry_mldsa_polybuf_al *polybuf, size_t mat_elems, size_t vec_elems)
{
  const size_t alloc_size = mat_elems * vec_elems * sizeof(gcry_mldsa_poly) + /*align*/ 128;
  polybuf->alloc_addr = xtrymalloc_secure(alloc_size);

  if (!polybuf->alloc_addr)
    {
      polybuf->buf = NULL;
      return gpg_error_from_syserror();
    }
  polybuf->buf
      = (byte *)((uintptr_t)polybuf->alloc_addr + (128 - ((uintptr_t)polybuf->alloc_addr % 128))); // aligned memory

  memset(polybuf->alloc_addr, 0, alloc_size);
  return 0;
}

void _gcry_mldsa_polybuf_al_destroy(gcry_mldsa_polybuf_al *polybuf)
{
  if (polybuf->alloc_addr)
    {
      xfree(polybuf->alloc_addr);
    }
  polybuf->buf        = NULL;
  polybuf->alloc_addr = NULL;
}

gcry_err_code_t _gcry_mldsa_buf_al_create(gcry_mldsa_buf_al *buf, size_t size)
{
  const size_t alloc_size =  size + /*align*/ 128;
  buf->alloc_addr = xtrymalloc_secure(alloc_size);

  if (!buf->alloc_addr)
    {
      buf->buf = NULL;
      return gpg_error_from_syserror();
    }
  buf->buf
      = (byte *)((uintptr_t)buf->alloc_addr + (128 - ((uintptr_t)buf->alloc_addr % 128))); // aligned memory

  memset(buf->alloc_addr, 0, alloc_size);
  return 0;
}

void _gcry_mldsa_buf_al_destroy(gcry_mldsa_buf_al *buf)
{
  if (buf->alloc_addr)
    {
      xfree(buf->alloc_addr);
    }
  buf->buf        = NULL;
  buf->alloc_addr = NULL;
}

/*************************************************
 * Name:        expand_mat
 *
 * Description: Implementation of ExpandA. Generates matrix A with uniformly
 *              random coefficients a_{i,j} by performing rejection
 *              sampling on the output stream of SHAKE128(rho|j|i)
 *
 * Arguments:   - polyvecl mat[K]: output matrix
 *              - const byte rho[]: byte array containing seed rho
 **************************************************/

gcry_err_code_t polyvec_matrix_expand(gcry_mldsa_param_t *params, byte *mat, const byte rho[GCRY_MLDSA_SEEDBYTES])
{
  gcry_err_code_t ec = 0;
  const size_t rowsize = sizeof(gcry_mldsa_poly) * params->l;
  gcry_mldsa_buf_al tmp = {};
  if (params->l == 4 && params->k == 4)
    {
      polyvec_matrix_expand_row0(params, &mat[0 * rowsize], NULL, rho);
      polyvec_matrix_expand_row1(params, &mat[1 * rowsize], NULL, rho);
      polyvec_matrix_expand_row2(params, &mat[2 * rowsize], NULL, rho);
      polyvec_matrix_expand_row3(params, &mat[3 * rowsize], NULL, rho);
    }
  else if (params->k == 6 && params->l == 5)
    {
      _gcry_mldsa_buf_al_create(&tmp, rowsize);
      polyvec_matrix_expand_row0(params, &mat[0 * rowsize], &mat[1 * rowsize], rho);
      polyvec_matrix_expand_row1(params, &mat[1 * rowsize], &mat[2 * rowsize], rho);
      polyvec_matrix_expand_row2(params, &mat[2 * rowsize], &mat[3 * rowsize], rho);
      polyvec_matrix_expand_row3(params, &mat[3 * rowsize], NULL, rho);
      polyvec_matrix_expand_row4(params, &mat[4 * rowsize], &mat[5 * rowsize], rho);
      polyvec_matrix_expand_row5(params, &mat[5 * rowsize], tmp.buf, rho);
    }
  else if (params->k == 8 && params->l == 7)
    {
      polyvec_matrix_expand_row0(params, &mat[0 * rowsize], &mat[1 * rowsize], rho);
      polyvec_matrix_expand_row1(params, &mat[1 * rowsize], &mat[2 * rowsize], rho);
      polyvec_matrix_expand_row2(params, &mat[2 * rowsize], &mat[3 * rowsize], rho);
      polyvec_matrix_expand_row3(params, &mat[3 * rowsize], NULL, rho);
      polyvec_matrix_expand_row4(params, &mat[4 * rowsize], &mat[5 * rowsize], rho);
      polyvec_matrix_expand_row5(params, &mat[5 * rowsize], &mat[6 * rowsize], rho);
      polyvec_matrix_expand_row6(params, &mat[6 * rowsize], &mat[7 * rowsize], rho);
      polyvec_matrix_expand_row7(params, &mat[7 * rowsize], NULL, rho);
    }
  else
    {
      ec = GPG_ERR_INV_STATE;
      goto leave;
    }

leave:
  _gcry_mldsa_buf_al_destroy(&tmp);
  return ec;
}

gcry_err_code_t polyvec_matrix_expand_row0(gcry_mldsa_param_t *params,
                                           byte *rowa,
                                           byte *rowb,
                                           const byte rho[GCRY_MLDSA_SEEDBYTES])
{
  const size_t polysize = sizeof(gcry_mldsa_poly);
  if (params->l == 4 && params->k == 4)
    {
      poly_uniform_4x(&rowa[0 * polysize], &rowa[1 * polysize], &rowa[2 * polysize], &rowa[3 * polysize], rho, 0, 1, 2, 3);
      poly_nttunpack(&rowa[0 * polysize]);
      poly_nttunpack(&rowa[1 * polysize]);
      poly_nttunpack(&rowa[2 * polysize]);
      poly_nttunpack(&rowa[3 * polysize]);
    }
  else if (params->k == 6 && params->l == 5)
    {
      poly_uniform_4x(&rowa[0 * polysize], &rowa[1 * polysize], &rowa[2 * polysize], &rowa[3 * polysize], rho, 0, 1, 2, 3);
      poly_uniform_4x(&rowa[4 * polysize], &rowb[0 * polysize], &rowb[1 * polysize], &rowb[2 * polysize], rho, 4, 256, 257, 258);
      poly_nttunpack(&rowa[0 * polysize]);
      poly_nttunpack(&rowa[1 * polysize]);
      poly_nttunpack(&rowa[2 * polysize]);
      poly_nttunpack(&rowa[3 * polysize]);
      poly_nttunpack(&rowa[4 * polysize]);
      poly_nttunpack(&rowb[0 * polysize]);
      poly_nttunpack(&rowb[1 * polysize]);
      poly_nttunpack(&rowb[2 * polysize]);
    }
  else if (params->k == 8 && params->l == 7)
    {
      poly_uniform_4x(&rowa[0 * polysize], &rowa[1 * polysize], &rowa[2 * polysize], &rowa[3 * polysize], rho, 0, 1, 2, 3);
      poly_uniform_4x(&rowa[4 * polysize], &rowa[5 * polysize], &rowa[6 * polysize], &rowb[0 * polysize], rho, 4, 5, 6, 256);
      poly_nttunpack(&rowa[0 * polysize]);
      poly_nttunpack(&rowa[1 * polysize]);
      poly_nttunpack(&rowa[2 * polysize]);
      poly_nttunpack(&rowa[3 * polysize]);
      poly_nttunpack(&rowa[4 * polysize]);
      poly_nttunpack(&rowa[5 * polysize]);
      poly_nttunpack(&rowa[6 * polysize]);
      poly_nttunpack(&rowb[0 * polysize]);
    }
  else
    {
      return GPG_ERR_INV_STATE;
    }
  return 0;
}

gcry_err_code_t polyvec_matrix_expand_row1(gcry_mldsa_param_t *params,
                                           byte *rowa,
                                           byte *rowb,
                                           const byte rho[GCRY_MLDSA_SEEDBYTES])
{
  const size_t polysize = sizeof(gcry_mldsa_poly);
  if (params->l == 4 && params->k == 4)
    {
      poly_uniform_4x(&rowa[0 * polysize], &rowa[1 * polysize], &rowa[2 * polysize], &rowa[3 * polysize], rho, 256, 257, 258, 259);
      poly_nttunpack(&rowa[0 * polysize]);
      poly_nttunpack(&rowa[1 * polysize]);
      poly_nttunpack(&rowa[2 * polysize]);
      poly_nttunpack(&rowa[3 * polysize]);
    }
  else if (params->k == 6 && params->l == 5)
    {
      poly_uniform_4x(&rowa[3 * polysize], &rowa[4 * polysize], &rowb[0 * polysize], &rowb[1 * polysize], rho, 259, 260, 512, 513);
      poly_nttunpack(&rowa[3 * polysize]);
      poly_nttunpack(&rowa[4 * polysize]);
      poly_nttunpack(&rowb[0 * polysize]);
      poly_nttunpack(&rowb[1 * polysize]);
    }
  else if (params->k == 8 && params->l == 7)
    {
      poly_uniform_4x(&rowa[1 * polysize], &rowa[2 * polysize], &rowa[3 * polysize], &rowa[4 * polysize], rho, 257, 258, 259, 260);
      poly_uniform_4x(&rowa[5 * polysize], &rowa[6 * polysize], &rowb[0 * polysize], &rowb[1 * polysize], rho, 261, 262, 512, 513);
      poly_nttunpack(&rowa[1 * polysize]);
      poly_nttunpack(&rowa[2 * polysize]);
      poly_nttunpack(&rowa[3 * polysize]);
      poly_nttunpack(&rowa[4 * polysize]);
      poly_nttunpack(&rowa[5 * polysize]);
      poly_nttunpack(&rowa[6 * polysize]);
      poly_nttunpack(&rowb[0 * polysize]);
      poly_nttunpack(&rowb[1 * polysize]);
    }
  else
    {
      return GPG_ERR_INV_STATE;
    }
  return 0;
}

gcry_err_code_t polyvec_matrix_expand_row2(gcry_mldsa_param_t *params,
                                           byte *rowa,
                                           byte *rowb,
                                           const byte rho[GCRY_MLDSA_SEEDBYTES])
{
  const size_t polysize = sizeof(gcry_mldsa_poly);

  if (params->l == 4 && params->k == 4)
    {
      poly_uniform_4x(&rowa[0 * polysize], &rowa[1 * polysize], &rowa[2 * polysize], &rowa[3 * polysize], rho, 512, 513, 514, 515);
      poly_nttunpack(&rowa[0 * polysize]);
      poly_nttunpack(&rowa[1 * polysize]);
      poly_nttunpack(&rowa[2 * polysize]);
      poly_nttunpack(&rowa[3 * polysize]);
    }
  else if (params->k == 6 && params->l == 5)
    {
      poly_uniform_4x(&rowa[2 * polysize], &rowa[3 * polysize], &rowa[4 * polysize], &rowb[0 * polysize], rho, 514, 515, 516, 768);
      poly_nttunpack(&rowa[2 * polysize]);
      poly_nttunpack(&rowa[3 * polysize]);
      poly_nttunpack(&rowa[4 * polysize]);
      poly_nttunpack(&rowb[0 * polysize]);
    }
  else if (params->k == 8 && params->l == 7)
    {
      poly_uniform_4x(&rowa[2 * polysize], &rowa[3 * polysize], &rowa[4 * polysize], &rowa[5 * polysize], rho, 514, 515, 516, 517);
      poly_uniform_4x(&rowa[6 * polysize], &rowb[0 * polysize], &rowb[1 * polysize], &rowb[2 * polysize], rho, 518, 768, 769, 770);
      poly_nttunpack(&rowa[2 * polysize]);
      poly_nttunpack(&rowa[3 * polysize]);
      poly_nttunpack(&rowa[4 * polysize]);
      poly_nttunpack(&rowa[5 * polysize]);
      poly_nttunpack(&rowa[6 * polysize]);
      poly_nttunpack(&rowb[0 * polysize]);
      poly_nttunpack(&rowb[1 * polysize]);
      poly_nttunpack(&rowb[2 * polysize]);
    }
  else
    {
      return GPG_ERR_INV_STATE;
    }
  return 0;
}

gcry_err_code_t polyvec_matrix_expand_row3(gcry_mldsa_param_t *params,
                                           byte *rowa,
                                           byte *rowb,
                                           const byte rho[GCRY_MLDSA_SEEDBYTES])
{
  const size_t polysize = sizeof(gcry_mldsa_poly);
  if (params->l == 4 && params->k == 4)
    {
      poly_uniform_4x(&rowa[0 * polysize], &rowa[1 * polysize], &rowa[2 * polysize], &rowa[3 * polysize], rho, 768, 769, 770, 771);
      poly_nttunpack(&rowa[0 * polysize]);
      poly_nttunpack(&rowa[1 * polysize]);
      poly_nttunpack(&rowa[2 * polysize]);
      poly_nttunpack(&rowa[3 * polysize]);
    }
  else if (params->k == 6 && params->l == 5)
    {
      poly_uniform_4x(&rowa[1 * polysize], &rowa[2 * polysize], &rowa[3 * polysize], &rowa[4 * polysize], rho, 769, 770, 771, 772);
      poly_nttunpack(&rowa[1 * polysize]);
      poly_nttunpack(&rowa[2 * polysize]);
      poly_nttunpack(&rowa[3 * polysize]);
      poly_nttunpack(&rowa[4 * polysize]);
    }
  else if (params->k == 8 && params->l == 7)
    {
      poly_uniform_4x(&rowa[3 * polysize], &rowa[4 * polysize], &rowa[5 * polysize], &rowa[6 * polysize], rho, 771, 772, 773, 774);
      poly_nttunpack(&rowa[3 * polysize]);
      poly_nttunpack(&rowa[4 * polysize]);
      poly_nttunpack(&rowa[5 * polysize]);
      poly_nttunpack(&rowa[6 * polysize]);
    }
  else
    {
      return GPG_ERR_INV_STATE;
    }
  return 0;
}


gcry_err_code_t polyvec_matrix_expand_row4(gcry_mldsa_param_t *params,
                                           byte *rowa,
                                           byte *rowb,
                                           const byte rho[GCRY_MLDSA_SEEDBYTES])
{
  const size_t polysize = sizeof(gcry_mldsa_poly);

  if (params->k == 6 && params->l == 5)
    {
      poly_uniform_4x(&rowa[0 * polysize], &rowa[1 * polysize], &rowa[2 * polysize], &rowa[3 * polysize], rho, 1024, 1025, 1026, 1027);
      poly_uniform_4x(&rowa[4 * polysize], &rowb[0 * polysize], &rowb[1 * polysize], &rowb[2 * polysize], rho, 1028, 1280, 1281, 1282);
      poly_nttunpack(&rowa[0 * polysize]);
      poly_nttunpack(&rowa[1 * polysize]);
      poly_nttunpack(&rowa[2 * polysize]);
      poly_nttunpack(&rowa[3 * polysize]);
      poly_nttunpack(&rowa[4 * polysize]);
      poly_nttunpack(&rowb[0 * polysize]);
      poly_nttunpack(&rowb[1 * polysize]);
      poly_nttunpack(&rowb[2 * polysize]);
    }
  else if (params->k == 8 && params->l == 7)
    {
      poly_uniform_4x(&rowa[0 * polysize], &rowa[1 * polysize], &rowa[2 * polysize], &rowa[3 * polysize], rho, 1024, 1025, 1026, 1027);
      poly_uniform_4x(&rowa[4 * polysize], &rowa[5 * polysize], &rowa[6 * polysize], &rowb[0 * polysize], rho, 1028, 1029, 1030, 1280);
      poly_nttunpack(&rowa[0 * polysize]);
      poly_nttunpack(&rowa[1 * polysize]);
      poly_nttunpack(&rowa[2 * polysize]);
      poly_nttunpack(&rowa[3 * polysize]);
      poly_nttunpack(&rowa[4 * polysize]);
      poly_nttunpack(&rowa[5 * polysize]);
      poly_nttunpack(&rowa[6 * polysize]);
      poly_nttunpack(&rowb[0 * polysize]);
    }
  else
    {
      return GPG_ERR_INV_STATE;
    }
  return 0;
}

gcry_err_code_t polyvec_matrix_expand_row5(gcry_mldsa_param_t *params,
                                           byte *rowa,
                                           byte *rowb,
                                           const byte rho[GCRY_MLDSA_SEEDBYTES])
{
  const size_t polysize = sizeof(gcry_mldsa_poly);
  if (params->k == 6 && params->l == 5)
    {
      poly_uniform_4x(&rowa[3 * polysize], &rowa[4 * polysize], &rowb[0 * polysize], &rowb[1 * polysize], rho, 1283, 1284, 1536, 1537);
      poly_nttunpack(&rowa[3 * polysize]);
      poly_nttunpack(&rowa[4 * polysize]);
    }
  else if (params->k == 8 && params->l == 7)
    {
      poly_uniform_4x(&rowa[1 * polysize], &rowa[2 * polysize], &rowa[3 * polysize], &rowa[4 * polysize], rho, 1281, 1282, 1283, 1284);
      poly_uniform_4x(&rowa[5 * polysize], &rowa[6 * polysize], &rowb[0 * polysize], &rowb[1 * polysize], rho, 1285, 1286, 1536, 1537);
      poly_nttunpack(&rowa[1 * polysize]);
      poly_nttunpack(&rowa[2 * polysize]);
      poly_nttunpack(&rowa[3 * polysize]);
      poly_nttunpack(&rowa[4 * polysize]);
      poly_nttunpack(&rowa[5 * polysize]);
      poly_nttunpack(&rowa[6 * polysize]);
      poly_nttunpack(&rowb[0 * polysize]);
      poly_nttunpack(&rowb[1 * polysize]);
    }
  else
    {
      return GPG_ERR_INV_STATE;
    }
  return 0;
}

gcry_err_code_t polyvec_matrix_expand_row6(gcry_mldsa_param_t *params,
                                byte *rowa,
                                byte *rowb,
                                const byte rho[GCRY_MLDSA_SEEDBYTES])
{
  const size_t polysize = sizeof(gcry_mldsa_poly);
  if (params->k == 8 && params->l == 7)
    {
      poly_uniform_4x(&rowa[2 * polysize], &rowa[3 * polysize], &rowa[4 * polysize], &rowa[5 * polysize], rho, 1538, 1539, 1540, 1541);
      poly_uniform_4x(&rowa[6 * polysize], &rowb[0 * polysize], &rowb[1 * polysize], &rowb[2 * polysize], rho, 1542, 1792, 1793, 1794);
      poly_nttunpack(&rowa[2 * polysize]);
      poly_nttunpack(&rowa[3 * polysize]);
      poly_nttunpack(&rowa[4 * polysize]);
      poly_nttunpack(&rowa[5 * polysize]);
      poly_nttunpack(&rowa[6 * polysize]);
      poly_nttunpack(&rowb[0 * polysize]);
      poly_nttunpack(&rowb[1 * polysize]);
      poly_nttunpack(&rowb[2 * polysize]);
    }
  else
    {
      return GPG_ERR_INV_STATE;
    }
  return 0;
}

gcry_err_code_t polyvec_matrix_expand_row7(gcry_mldsa_param_t *params,
                                byte *rowa,
                                byte *rowb,
                                const byte rho[GCRY_MLDSA_SEEDBYTES])
{
  const size_t polysize = sizeof(gcry_mldsa_poly);
  if (params->k == 8 && params->l == 7)
    {
      poly_uniform_4x(&rowa[3 * polysize], &rowa[4 * polysize], &rowa[5 * polysize], &rowa[6 * polysize], rho, 1795, 1796, 1797, 1798);
      poly_nttunpack(&rowa[3 * polysize]);
      poly_nttunpack(&rowa[4 * polysize]);
      poly_nttunpack(&rowa[5 * polysize]);
      poly_nttunpack(&rowa[6 * polysize]);
    }
  else
    {
      return GPG_ERR_INV_STATE;
    }
  return 0;
}

void polyvec_matrix_pointwise_montgomery(gcry_mldsa_param_t *params, byte *t, const byte *mat, const byte *v)
{
  unsigned int i;
  const size_t polysize = sizeof(gcry_mldsa_poly);
  const size_t rowsize = polysize * params->l;

  for (i = 0; i < params->k; ++i)
    polyvecl_pointwise_acc_montgomery(params, (gcry_mldsa_poly*)&t[i * polysize], &mat[i * rowsize], v);
}


/*************************************************
 * Name:        polyvecl_ntt
 *
 * Description: Forward NTT of all polynomials in vector of length L. Output
 *              coefficients can be up to 16*GCRY_MLDSA_Q larger than input coefficients.
 *
 * Arguments:   - polyvecl *v: pointer to input/output vector
 **************************************************/
void polyvecl_ntt(gcry_mldsa_param_t *params, byte *v)
{
  unsigned int i;

  for (i = 0; i < params->l; ++i)
    poly_ntt((gcry_mldsa_poly*)&v[i * sizeof(gcry_mldsa_poly)]);
}



/*************************************************
 * Name:        polyvecl_pointwise_acc_montgomery
 *
 * Description: Pointwise multiply vectors of polynomials of length L, multiply
 *              resulting vector by 2^{-32} and add (accumulate) polynomials
 *              in it. Input/output vectors are in NTT domain representation.
 *
 * Arguments:   - gcry_mldsa_poly *w: output polynomial
 *              - const polyvecl *u: pointer to first input vector
 *              - const polyvecl *v: pointer to second input vector
 **************************************************/
void polyvecl_pointwise_acc_montgomery(gcry_mldsa_param_t *params, gcry_mldsa_poly *w, const byte *u, const byte *v)
{
  if(params->l == 4)
    {
      pointwise_acc_avx_L4(w->vec, (__m256i*)u, (__m256i*)v, qdata.vec);
    }
    else if (params->l == 5)
    {
      pointwise_acc_avx_L5(w->vec, (__m256i*)u, (__m256i*)v, qdata.vec);
    }
    else {
      pointwise_acc_avx_L7(w->vec, (__m256i*)u, (__m256i*)v, qdata.vec);
    }
}




/*************************************************
 * Name:        polyveck_caddq
 *
 * Description: For all coefficients of polynomials in vector of length K
 *              add GCRY_MLDSA_Q if coefficient is negative.
 *
 * Arguments:   - polyveck *v: pointer to input/output vector
 **************************************************/
void polyveck_caddq(gcry_mldsa_param_t *params, byte *v)
{
  unsigned int i;

  for (i = 0; i < params->k; ++i)
    poly_caddq((gcry_mldsa_poly*)&v[i * sizeof(gcry_mldsa_poly)]);
}


/*************************************************
 * Name:        polyveck_ntt
 *
 * Description: Forward NTT of all polynomials in vector of length K. Output
 *              coefficients can be up to 16*GCRY_MLDSA_Q larger than input coefficients.
 *
 * Arguments:   - polyveck *v: pointer to input/output vector
 **************************************************/
void polyveck_ntt(gcry_mldsa_param_t *params, byte *v)
{
  unsigned int i;

  for (i = 0; i < params->k; ++i)
    poly_ntt((gcry_mldsa_poly*)&v[i * sizeof(gcry_mldsa_poly)]);
}

/*************************************************
 * Name:        polyveck_invntt_tomont
 *
 * Description: Inverse NTT and multiplication by 2^{32} of polynomials
 *              in vector of length K. Input coefficients need to be less
 *              than 2*GCRY_MLDSA_Q.
 *
 * Arguments:   - polyveck *v: pointer to input/output vector
 **************************************************/
void polyveck_invntt_tomont(gcry_mldsa_param_t *params, byte *v)
{
  unsigned int i;

  for (i = 0; i < params->k; ++i)
    poly_invntt_tomont((gcry_mldsa_poly*)&v[i * sizeof(gcry_mldsa_poly)]);
}


/*************************************************
 * Name:        polyveck_decompose
 *
 * Description: For all coefficients a of polynomials in vector of length K,
 *              compute high and low bits a0, a1 such a mod^+ GCRY_MLDSA_Q = a1*ALPHA + a0
 *              with -ALPHA/2 < a0 <= ALPHA/2 except a1 = (GCRY_MLDSA_Q-1)/ALPHA where we
 *              set a1 = 0 and -ALPHA/2 <= a0 = a mod GCRY_MLDSA_Q - GCRY_MLDSA_Q < 0.
 *              Assumes coefficients to be standard representatives.
 *
 * Arguments:   - polyveck *v1: pointer to output vector of polynomials with
 *                              coefficients a1
 *              - polyveck *v0: pointer to output vector of polynomials with
 *                              coefficients a0
 *              - const polyveck *v: pointer to input vector
 **************************************************/
void polyveck_decompose(gcry_mldsa_param_t *params, byte *v1, byte *v0, const byte *v)
{
  unsigned int i;
  const size_t polysize = sizeof(gcry_mldsa_poly);

  for (i = 0; i < params->k; ++i)
    poly_decompose(params, (gcry_mldsa_poly*)&v1[i * polysize], (gcry_mldsa_poly*)&v0[i * polysize], (gcry_mldsa_poly*)&v[i * polysize]);
}


void polyveck_pack_w1(gcry_mldsa_param_t *params, byte *r, const byte *w1)
{
  unsigned int i;

  for (i = 0; i < params->k; ++i)
    polyw1_pack(params, &r[i * params->polyw1_packedbytes], (gcry_mldsa_poly*)&w1[i * sizeof(gcry_mldsa_poly)]);
}
