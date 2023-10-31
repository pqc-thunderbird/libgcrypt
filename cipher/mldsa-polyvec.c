#include <config.h>
#include <stdint.h>
#include "mldsa-params.h"
#include "mldsa-polyvec.h"
#include "mldsa-poly.h"

gcry_error_t _gcry_mldsa_polymatrix_create(gcry_mldsa_polyvec **polymat,
                                           unsigned char mat_elems, unsigned char vec_elems)
{
  gcry_error_t ec = 0;
  unsigned i;

  if (!(*polymat = xtrymalloc(sizeof(**polymat) * mat_elems)))
    {
      return gpg_error_from_syserror();
    }
  memset((polymat)[0], 0, sizeof(**polymat) * mat_elems);

  for (i = 0; i < mat_elems; i++)
    {
      if ((ec = _gcry_mldsa_polyvec_create(&(*polymat)[i], vec_elems)))
        {
          ec = gpg_err_code_from_syserror();
          goto end;
        }
    }
end:
  return ec;
}

void _gcry_mldsa_polymatrix_destroy(gcry_mldsa_polyvec **polymat,
                                     unsigned char elems)
{
  unsigned i;
  if (polymat == NULL)
    {
      return;
    }
  for (i = 0; i < elems; i++)
    {
      _gcry_mldsa_polyvec_destroy(&(*polymat)[i]);
    }
  xfree(*polymat);
  *polymat = NULL;
}

gcry_error_t _gcry_mldsa_polyvec_create(gcry_mldsa_polyvec *polyvec,
                                         unsigned char elems)
{
  if (!(polyvec->vec = xtrymalloc_secure(sizeof(*polyvec->vec) * elems)))
    {
      return gpg_err_code_from_syserror();
    }
  return 0;
}

void _gcry_mldsa_polyvec_destroy(gcry_mldsa_polyvec *polyvec)
{
  if(polyvec)
  {
    xfree(polyvec->vec);
  }
  polyvec->vec = NULL;
}

gcry_error_t _gcry_mldsa_polyvec_copy(gcry_mldsa_polyvec *dst, gcry_mldsa_polyvec *src, unsigned char elems)
{
  unsigned i;
  if(!dst || !src)
  {
    return GPG_ERR_INV_ARG;
  }

  for(i = 0; i < elems; i++)
  {
    dst->vec[i] = src->vec[i];
  }

  return GPG_ERR_NO_ERROR;
}

/*************************************************
* Name:        expand_mat
*
* Description: Implementation of ExpandA. Generates matrix A with uniformly
*              random coefficients a_{i,j} by performing rejection
*              sampling on the output stream of SHAKE128(rho|j|i)
*
* Arguments:   - gcry_mldsa_polyvec mat[params->k]: output matrix
*              - const uint8_t rho[]: byte array containing seed rho
**************************************************/
void _gcry_mldsa_polyvec_matrix_expand(gcry_mldsa_param_t *params, gcry_mldsa_polyvec *mat, const uint8_t rho[GCRY_MLDSA_SEEDBYTES]) {
  unsigned int i, j;

  for(i = 0; i < params->k; ++i)
    for(j = 0; j < params->l; ++j)
      _gcry_mldsa_poly_uniform(&mat[i].vec[j], rho, (i << 8) + j);
}

void _gcry_mldsa_polyvec_matrix_pointwise_montgomery(gcry_mldsa_param_t *params, gcry_mldsa_polyvec *t, const gcry_mldsa_polyvec *mat, const gcry_mldsa_polyvec *v) {
  unsigned int i;

  for(i = 0; i < params->k; ++i)
    _gcry_mldsa_polyvecl_pointwise_acc_montgomery(params, &t->vec[i], &mat[i], v);
}

/**************************************************************/
/************ Vectors of polynomials of length params->l **************/
/**************************************************************/

void _gcry_mldsa_polyvecl_uniform_eta(gcry_mldsa_param_t *params, gcry_mldsa_polyvec *v, const uint8_t seed[GCRY_MLDSA_CRHBYTES], uint16_t nonce) {
  unsigned int i;

  for(i = 0; i < params->l; ++i)
    _gcry_mldsa_poly_uniform_eta(params, &v->vec[i], seed, nonce++);
}

void _gcry_mldsa_polyvecl_uniform_gamma1(gcry_mldsa_param_t *params, gcry_mldsa_polyvec *v, const uint8_t seed[GCRY_MLDSA_CRHBYTES], uint16_t nonce) {
  unsigned int i;

  for(i = 0; i < params->l; ++i)
    _gcry_mldsa_poly_uniform_gamma1(params, &v->vec[i], seed, params->l*nonce + i);
}

void _gcry_mldsa_polyvecl_reduce(gcry_mldsa_param_t *params, gcry_mldsa_polyvec *v) {
  unsigned int i;

  for(i = 0; i < params->l; ++i)
    _gcry_mldsa_poly_reduce(&v->vec[i]);
}

/*************************************************
* Name:        _gcry_mldsa_polyvecl_add
*
* Description: Add vectors of polynomials of length params->l.
*              No modular reduction is performed.
*
* Arguments:   - gcry_mldsa_polyvec *w: pointer to output vector
*              - const gcry_mldsa_polyvec *u: pointer to first summand
*              - const gcry_mldsa_polyvec *v: pointer to second summand
**************************************************/
void _gcry_mldsa_polyvecl_add(gcry_mldsa_param_t *params, gcry_mldsa_polyvec *w, const gcry_mldsa_polyvec *u, const gcry_mldsa_polyvec *v) {
  unsigned int i;

  for(i = 0; i < params->l; ++i)
    _gcry_mldsa_poly_add(&w->vec[i], &u->vec[i], &v->vec[i]);
}

/*************************************************
* Name:        _gcry_mldsa_polyvecl_ntt
*
* Description: Forward NTT of all polynomials in vector of length params->l. Output
*              coefficients can be up to 16*GCRY_MLDSA_Q larger than input coefficients.
*
* Arguments:   - gcry_mldsa_polyvec *v: pointer to input/output vector
**************************************************/
void _gcry_mldsa_polyvecl_ntt(gcry_mldsa_param_t *params, gcry_mldsa_polyvec *v) {
  unsigned int i;

  for(i = 0; i < params->l; ++i)
    _gcry_mldsa_poly_ntt(&v->vec[i]);
}

void _gcry_mldsa_polyvecl_invntt_tomont(gcry_mldsa_param_t *params, gcry_mldsa_polyvec *v) {
  unsigned int i;

  for(i = 0; i < params->l; ++i)
    _gcry_mldsa_poly_invntt_tomont(&v->vec[i]);
}

void _gcry_mldsa_polyvecl_pointwise_poly_montgomery(gcry_mldsa_param_t *params, gcry_mldsa_polyvec *r, const gcry_mldsa_poly *a, const gcry_mldsa_polyvec *v) {
  unsigned int i;

  for(i = 0; i < params->l; ++i)
    _gcry_mldsa_poly_pointwise_montgomery(&r->vec[i], a, &v->vec[i]);
}

/*************************************************
* Name:        _gcry_mldsa_polyvecl_pointwise_acc_montgomery
*
* Description: Pointwise multiply vectors of polynomials of length params->l, multiply
*              resulting vector by 2^{-32} and add (accumulate) polynomials
*              in it. Input/output vectors are in NTT domain representation.
*
* Arguments:   - gcry_mldsa_poly *w: output polynomial
*              - const gcry_mldsa_polyvec *u: pointer to first input vector
*              - const gcry_mldsa_polyvec *v: pointer to second input vector
**************************************************/
void _gcry_mldsa_polyvecl_pointwise_acc_montgomery(gcry_mldsa_param_t *params,
                                       gcry_mldsa_poly *w,
                                       const gcry_mldsa_polyvec *u,
                                       const gcry_mldsa_polyvec *v)
{
  unsigned int i;
  gcry_mldsa_poly t;

  _gcry_mldsa_poly_pointwise_montgomery(w, &u->vec[0], &v->vec[0]);
  for(i = 1; i < params->l; ++i) {
    _gcry_mldsa_poly_pointwise_montgomery(&t, &u->vec[i], &v->vec[i]);
    _gcry_mldsa_poly_add(w, w, &t);
  }
}

/*************************************************
* Name:        _gcry_mldsa_polyvecl_chknorm
*
* Description: Check infinity norm of polynomials in vector of length params->l.
*              Assumes input gcry_mldsa_polyvec to be reduced by _gcry_mldsa_polyvecl_reduce().
*
* Arguments:   - const gcry_mldsa_polyvec *v: pointer to vector
*              - int32_t B: norm bound
*
* Returns 0 if norm of all polynomials is strictly smaller than B <= (GCRY_MLDSA_Q-1)/8
* and 1 otherwise.
**************************************************/
int _gcry_mldsa_polyvecl_chknorm(gcry_mldsa_param_t *params, const gcry_mldsa_polyvec *v, int32_t bound)  {
  unsigned int i;

  for(i = 0; i < params->l; ++i)
    if(_gcry_mldsa_poly_chknorm(&v->vec[i], bound))
      return 1;

  return 0;
}

/**************************************************************/
/************ Vectors of polynomials of length params->k **************/
/**************************************************************/

void _gcry_mldsa_polyveck_uniform_eta(gcry_mldsa_param_t *params, gcry_mldsa_polyvec *v, const uint8_t seed[GCRY_MLDSA_CRHBYTES], uint16_t nonce) {
  unsigned int i;

  for(i = 0; i < params->k; ++i)
    _gcry_mldsa_poly_uniform_eta(params, &v->vec[i], seed, nonce++);
}

/*************************************************
* Name:        _gcry_mldsa_polyveck_reduce
*
* Description: Reduce coefficients of polynomials in vector of length params->k
*              to representatives in [-6283009,6283007].
*
* Arguments:   - gcry_mldsa_polyvec *v: pointer to input/output vector
**************************************************/
void _gcry_mldsa_polyveck_reduce(gcry_mldsa_param_t *params, gcry_mldsa_polyvec *v) {
  unsigned int i;

  for(i = 0; i < params->k; ++i)
    _gcry_mldsa_poly_reduce(&v->vec[i]);
}

/*************************************************
* Name:        _gcry_mldsa_polyveck_caddq
*
* Description: For all coefficients of polynomials in vector of length params->k
*              add GCRY_MLDSA_Q if coefficient is negative.
*
* Arguments:   - gcry_mldsa_polyvec *v: pointer to input/output vector
**************************************************/
void _gcry_mldsa_polyveck_caddq(gcry_mldsa_param_t *params, gcry_mldsa_polyvec *v) {
  unsigned int i;

  for(i = 0; i < params->k; ++i)
    _gcry_mldsa_poly_caddq(&v->vec[i]);
}

/*************************************************
* Name:        _gcry_mldsa_polyveck_add
*
* Description: Add vectors of polynomials of length params->k.
*              No modular reduction is performed.
*
* Arguments:   - gcry_mldsa_polyvec *w: pointer to output vector
*              - const gcry_mldsa_polyvec *u: pointer to first summand
*              - const gcry_mldsa_polyvec *v: pointer to second summand
**************************************************/
void _gcry_mldsa_polyveck_add(gcry_mldsa_param_t *params, gcry_mldsa_polyvec *w, const gcry_mldsa_polyvec *u, const gcry_mldsa_polyvec *v) {
  unsigned int i;

  for(i = 0; i < params->k; ++i)
    _gcry_mldsa_poly_add(&w->vec[i], &u->vec[i], &v->vec[i]);
}

/*************************************************
* Name:        _gcry_mldsa_polyveck_sub
*
* Description: Subtract vectors of polynomials of length params->k.
*              No modular reduction is performed.
*
* Arguments:   - gcry_mldsa_polyvec *w: pointer to output vector
*              - const gcry_mldsa_polyvec *u: pointer to first input vector
*              - const gcry_mldsa_polyvec *v: pointer to second input vector to be
*                                   subtracted from first input vector
**************************************************/
void _gcry_mldsa_polyveck_sub(gcry_mldsa_param_t *params, gcry_mldsa_polyvec *w, const gcry_mldsa_polyvec *u, const gcry_mldsa_polyvec *v) {
  unsigned int i;

  for(i = 0; i < params->k; ++i)
    _gcry_mldsa_poly_sub(&w->vec[i], &u->vec[i], &v->vec[i]);
}

/*************************************************
* Name:        _gcry_mldsa_polyveck_shiftl
*
* Description: Multiply vector of polynomials of Length params->k by 2^GCRY_MLDSA_D without modular
*              reduction. Assumes input coefficients to be less than 2^{31-GCRY_MLDSA_D}.
*
* Arguments:   - gcry_mldsa_polyvec *v: pointer to input/output vector
**************************************************/
void _gcry_mldsa_polyveck_shiftl(gcry_mldsa_param_t *params, gcry_mldsa_polyvec *v) {
  unsigned int i;

  for(i = 0; i < params->k; ++i)
    _gcry_mldsa_poly_shiftl(&v->vec[i]);
}

/*************************************************
* Name:        _gcry_mldsa_polyveck_ntt
*
* Description: Forward NTT of all polynomials in vector of length params->k. Output
*              coefficients can be up to 16*GCRY_MLDSA_Q larger than input coefficients.
*
* Arguments:   - gcry_mldsa_polyvec *v: pointer to input/output vector
**************************************************/
void _gcry_mldsa_polyveck_ntt(gcry_mldsa_param_t *params, gcry_mldsa_polyvec *v) {
  unsigned int i;

  for(i = 0; i < params->k; ++i)
    _gcry_mldsa_poly_ntt(&v->vec[i]);
}

/*************************************************
* Name:        _gcry_mldsa_polyveck_invntt_tomont
*
* Description: Inverse NTT and multiplication by 2^{32} of polynomials
*              in vector of length params->k. Input coefficients need to be less
*              than 2*GCRY_MLDSA_Q.
*
* Arguments:   - gcry_mldsa_polyvec *v: pointer to input/output vector
**************************************************/
void _gcry_mldsa_polyveck_invntt_tomont(gcry_mldsa_param_t *params, gcry_mldsa_polyvec *v) {
  unsigned int i;

  for(i = 0; i < params->k; ++i)
    _gcry_mldsa_poly_invntt_tomont(&v->vec[i]);
}

void _gcry_mldsa_polyveck_pointwise_poly_montgomery(gcry_mldsa_param_t *params, gcry_mldsa_polyvec *r, const gcry_mldsa_poly *a, const gcry_mldsa_polyvec *v) {
  unsigned int i;

  for(i = 0; i < params->k; ++i)
    _gcry_mldsa_poly_pointwise_montgomery(&r->vec[i], a, &v->vec[i]);
}


/*************************************************
* Name:        _gcry_mldsa_polyveck_chknorm
*
* Description: Check infinity norm of polynomials in vector of length params->k.
*              Assumes input gcry_mldsa_polyvec to be reduced by _gcry_mldsa_polyveck_reduce().
*
* Arguments:   - const gcry_mldsa_polyvec *v: pointer to vector
*              - int32_t B: norm bound
*
* Returns 0 if norm of all polynomials are strictly smaller than B <= (GCRY_MLDSA_Q-1)/8
* and 1 otherwise.
**************************************************/
int _gcry_mldsa_polyveck_chknorm(gcry_mldsa_param_t *params, const gcry_mldsa_polyvec *v, int32_t bound) {
  unsigned int i;

  for(i = 0; i < params->k; ++i)
    if(_gcry_mldsa_poly_chknorm(&v->vec[i], bound))
      return 1;

  return 0;
}

/*************************************************
* Name:        _gcry_mldsa_polyveck_power2round
*
* Description: For all coefficients a of polynomials in vector of length params->k,
*              compute a0, a1 such that a mod^+ GCRY_MLDSA_Q = a1*2^GCRY_MLDSA_D + a0
*              with -2^{GCRY_MLDSA_D-1} < a0 <= 2^{GCRY_MLDSA_D-1}. Assumes coefficients to be
*              standard representatives.
*
* Arguments:   - gcry_mldsa_polyvec *v1: pointer to output vector of polynomials with
*                              coefficients a1
*              - gcry_mldsa_polyvec *v0: pointer to output vector of polynomials with
*                              coefficients a0
*              - const gcry_mldsa_polyvec *v: pointer to input vector
**************************************************/
void _gcry_mldsa_polyveck_power2round(gcry_mldsa_param_t *params, gcry_mldsa_polyvec *v1, gcry_mldsa_polyvec *v0, const gcry_mldsa_polyvec *v) {
  unsigned int i;

  for(i = 0; i < params->k; ++i)
    _gcry_mldsa_poly_power2round(&v1->vec[i], &v0->vec[i], &v->vec[i]);
}

/*************************************************
* Name:        _gcry_mldsa_polyveck_decompose
*
* Description: For all coefficients a of polynomials in vector of length params->k,
*              compute high and low bits a0, a1 such a mod^+ GCRY_MLDSA_Q = a1*ALPHA + a0
*              with -ALPHA/2 < a0 <= ALPHA/2 except a1 = (GCRY_MLDSA_Q-1)/ALPHA where we
*              set a1 = 0 and -ALPHA/2 <= a0 = a mod GCRY_MLDSA_Q - GCRY_MLDSA_Q < 0.
*              Assumes coefficients to be standard representatives.
*
* Arguments:   - gcry_mldsa_polyvec *v1: pointer to output vector of polynomials with
*                              coefficients a1
*              - gcry_mldsa_polyvec *v0: pointer to output vector of polynomials with
*                              coefficients a0
*              - const gcry_mldsa_polyvec *v: pointer to input vector
**************************************************/
void _gcry_mldsa_polyveck_decompose(gcry_mldsa_param_t *params, gcry_mldsa_polyvec *v1, gcry_mldsa_polyvec *v0, const gcry_mldsa_polyvec *v) {
  unsigned int i;

  for(i = 0; i < params->k; ++i)
    _gcry_mldsa_poly_decompose(params, &v1->vec[i], &v0->vec[i], &v->vec[i]);
}

/*************************************************
* Name:        _gcry_mldsa_polyveck_make_hint
*
* Description: Compute hint vector.
*
* Arguments:   - gcry_mldsa_polyvec *h: pointer to output vector
*              - const gcry_mldsa_polyvec *v0: pointer to low part of input vector
*              - const gcry_mldsa_polyvec *v1: pointer to high part of input vector
*
* Returns number of 1 bits.
**************************************************/
unsigned int _gcry_mldsa_polyveck_make_hint(gcry_mldsa_param_t *params,
                                gcry_mldsa_polyvec *h,
                                const gcry_mldsa_polyvec *v0,
                                const gcry_mldsa_polyvec *v1)
{
  unsigned int i, s = 0;

  for(i = 0; i < params->k; ++i)
    s += _gcry_mldsa_poly_make_hint(params, &h->vec[i], &v0->vec[i], &v1->vec[i]);

  return s;
}

/*************************************************
* Name:        _gcry_mldsa_polyveck_use_hint
*
* Description: Use hint vector to correct the high bits of input vector.
*
* Arguments:   - gcry_mldsa_polyvec *w: pointer to output vector of polynomials with
*                             corrected high bits
*              - const gcry_mldsa_polyvec *u: pointer to input vector
*              - const gcry_mldsa_polyvec *h: pointer to input hint vector
**************************************************/
void _gcry_mldsa_polyveck_use_hint(gcry_mldsa_param_t *params, gcry_mldsa_polyvec *w, const gcry_mldsa_polyvec *u, const gcry_mldsa_polyvec *h) {
  unsigned int i;

  for(i = 0; i < params->k; ++i)
    _gcry_mldsa_poly_use_hint(params, &w->vec[i], &u->vec[i], &h->vec[i]);
}

void _gcry_mldsa_polyveck_pack_w1(gcry_mldsa_param_t *params, uint8_t *r, const gcry_mldsa_polyvec *w1) {
  unsigned int i;

  for(i = 0; i < params->k; ++i)
    _gcry_mldsa_polyw1_pack(params, &r[i*params->polyw1_packedbytes], &w1->vec[i]);
}
