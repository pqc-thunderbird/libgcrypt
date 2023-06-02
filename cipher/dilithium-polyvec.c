#include <stdint.h>
#include "dilithium-params.h"
#include "dilithium-polyvec.h"
#include "dilithium-poly.h"

gcry_error_t _gcry_dilithium_polymatrix_create(gcry_dilithium_polyvec **polymat,
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
      if ((ec = _gcry_dilithium_polyvec_create(&(*polymat)[i], vec_elems)))
        {
          ec = gpg_err_code_from_syserror();
          goto end;
        }
    }
end:
  return ec;
}

void _gcry_dilithium_polymatrix_destroy(gcry_dilithium_polyvec **polymat,
                                     unsigned char elems)
{
  unsigned i;
  if (polymat == NULL)
    {
      return;
    }
  for (i = 0; i < elems; i++)
    {
      _gcry_dilithium_polyvec_destroy(&(*polymat)[i]);
    }
  xfree(*polymat);
  *polymat = NULL;
}

gcry_error_t _gcry_dilithium_polyvec_create(gcry_dilithium_polyvec *polyvec,
                                         unsigned char elems)
{
  // TODO: xtrymalloc_secure ? (seems to be limited; receive no memory error)
  if (!(polyvec->vec = xtrymalloc(sizeof(*polyvec->vec) * elems)))
    {
      return gpg_err_code_from_syserror();
    }
  return 0;
}

void _gcry_dilithium_polyvec_destroy(gcry_dilithium_polyvec *polyvec)
{
  if(polyvec)
  {
    xfree(polyvec->vec);
  }
  polyvec->vec = NULL;
}

gcry_error_t _gcry_dilithium_polyvec_copy(gcry_dilithium_polyvec *dst, gcry_dilithium_polyvec *src, unsigned char elems)
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
* Arguments:   - gcry_dilithium_polyvec mat[params->k]: output matrix
*              - const uint8_t rho[]: byte array containing seed rho
**************************************************/
void polyvec_matrix_expand(gcry_dilithium_param_t *params, gcry_dilithium_polyvec *mat, const uint8_t rho[GCRY_DILITHIUM_SEEDBYTES]) {
  unsigned int i, j;

  for(i = 0; i < params->k; ++i)
    for(j = 0; j < params->l; ++j)
      poly_uniform(&mat[i].vec[j], rho, (i << 8) + j);
}

void polyvec_matrix_pointwise_montgomery(gcry_dilithium_param_t *params, gcry_dilithium_polyvec *t, const gcry_dilithium_polyvec *mat, const gcry_dilithium_polyvec *v) {
  unsigned int i;

  for(i = 0; i < params->k; ++i)
    polyvecl_pointwise_acc_montgomery(params, &t->vec[i], &mat[i], v);
}

/**************************************************************/
/************ Vectors of polynomials of length params->l **************/
/**************************************************************/

void polyvecl_uniform_eta(gcry_dilithium_param_t *params, gcry_dilithium_polyvec *v, const uint8_t seed[GCRY_DILITHIUM_CRHBYTES], uint16_t nonce) {
  unsigned int i;

  for(i = 0; i < params->l; ++i)
    poly_uniform_eta(params, &v->vec[i], seed, nonce++);
}

void polyvecl_uniform_gamma1(gcry_dilithium_param_t *params, gcry_dilithium_polyvec *v, const uint8_t seed[GCRY_DILITHIUM_CRHBYTES], uint16_t nonce) {
  unsigned int i;

  for(i = 0; i < params->l; ++i)
    poly_uniform_gamma1(params, &v->vec[i], seed, params->l*nonce + i);
}

void polyvecl_reduce(gcry_dilithium_param_t *params, gcry_dilithium_polyvec *v) {
  unsigned int i;

  for(i = 0; i < params->l; ++i)
    poly_reduce(&v->vec[i]);
}

/*************************************************
* Name:        polyvecl_add
*
* Description: Add vectors of polynomials of length params->l.
*              No modular reduction is performed.
*
* Arguments:   - gcry_dilithium_polyvec *w: pointer to output vector
*              - const gcry_dilithium_polyvec *u: pointer to first summand
*              - const gcry_dilithium_polyvec *v: pointer to second summand
**************************************************/
void polyvecl_add(gcry_dilithium_param_t *params, gcry_dilithium_polyvec *w, const gcry_dilithium_polyvec *u, const gcry_dilithium_polyvec *v) {
  unsigned int i;

  for(i = 0; i < params->l; ++i)
    poly_add(&w->vec[i], &u->vec[i], &v->vec[i]);
}

/*************************************************
* Name:        polyvecl_ntt
*
* Description: Forward NTT of all polynomials in vector of length params->l. Output
*              coefficients can be up to 16*GCRY_DILITHIUM_Q larger than input coefficients.
*
* Arguments:   - gcry_dilithium_polyvec *v: pointer to input/output vector
**************************************************/
void polyvecl_ntt(gcry_dilithium_param_t *params, gcry_dilithium_polyvec *v) {
  unsigned int i;

  for(i = 0; i < params->l; ++i)
    poly_ntt(&v->vec[i]);
}

void polyvecl_invntt_tomont(gcry_dilithium_param_t *params, gcry_dilithium_polyvec *v) {
  unsigned int i;

  for(i = 0; i < params->l; ++i)
    poly_invntt_tomont(&v->vec[i]);
}

void polyvecl_pointwise_poly_montgomery(gcry_dilithium_param_t *params, gcry_dilithium_polyvec *r, const poly *a, const gcry_dilithium_polyvec *v) {
  unsigned int i;

  for(i = 0; i < params->l; ++i)
    poly_pointwise_montgomery(&r->vec[i], a, &v->vec[i]);
}

/*************************************************
* Name:        polyvecl_pointwise_acc_montgomery
*
* Description: Pointwise multiply vectors of polynomials of length params->l, multiply
*              resulting vector by 2^{-32} and add (accumulate) polynomials
*              in it. Input/output vectors are in NTT domain representation.
*
* Arguments:   - poly *w: output polynomial
*              - const gcry_dilithium_polyvec *u: pointer to first input vector
*              - const gcry_dilithium_polyvec *v: pointer to second input vector
**************************************************/
void polyvecl_pointwise_acc_montgomery(gcry_dilithium_param_t *params,
                                       poly *w,
                                       const gcry_dilithium_polyvec *u,
                                       const gcry_dilithium_polyvec *v)
{
  unsigned int i;
  poly t;

  poly_pointwise_montgomery(w, &u->vec[0], &v->vec[0]);
  for(i = 1; i < params->l; ++i) {
    poly_pointwise_montgomery(&t, &u->vec[i], &v->vec[i]);
    poly_add(w, w, &t);
  }
}

/*************************************************
* Name:        polyvecl_chknorm
*
* Description: Check infinity norm of polynomials in vector of length params->l.
*              Assumes input gcry_dilithium_polyvec to be reduced by polyvecl_reduce().
*
* Arguments:   - const gcry_dilithium_polyvec *v: pointer to vector
*              - int32_t B: norm bound
*
* Returns 0 if norm of all polynomials is strictly smaller than B <= (GCRY_DILITHIUM_Q-1)/8
* and 1 otherwise.
**************************************************/
int polyvecl_chknorm(gcry_dilithium_param_t *params, const gcry_dilithium_polyvec *v, int32_t bound)  {
  unsigned int i;

  for(i = 0; i < params->l; ++i)
    if(poly_chknorm(&v->vec[i], bound))
      return 1;

  return 0;
}

/**************************************************************/
/************ Vectors of polynomials of length params->k **************/
/**************************************************************/

void polyveck_uniform_eta(gcry_dilithium_param_t *params, gcry_dilithium_polyvec *v, const uint8_t seed[GCRY_DILITHIUM_CRHBYTES], uint16_t nonce) {
  unsigned int i;

  for(i = 0; i < params->k; ++i)
    poly_uniform_eta(params, &v->vec[i], seed, nonce++);
}

/*************************************************
* Name:        polyveck_reduce
*
* Description: Reduce coefficients of polynomials in vector of length params->k
*              to representatives in [-6283009,6283007].
*
* Arguments:   - gcry_dilithium_polyvec *v: pointer to input/output vector
**************************************************/
void polyveck_reduce(gcry_dilithium_param_t *params, gcry_dilithium_polyvec *v) {
  unsigned int i;

  for(i = 0; i < params->k; ++i)
    poly_reduce(&v->vec[i]);
}

/*************************************************
* Name:        polyveck_caddq
*
* Description: For all coefficients of polynomials in vector of length params->k
*              add GCRY_DILITHIUM_Q if coefficient is negative.
*
* Arguments:   - gcry_dilithium_polyvec *v: pointer to input/output vector
**************************************************/
void polyveck_caddq(gcry_dilithium_param_t *params, gcry_dilithium_polyvec *v) {
  unsigned int i;

  for(i = 0; i < params->k; ++i)
    poly_caddq(&v->vec[i]);
}

/*************************************************
* Name:        polyveck_add
*
* Description: Add vectors of polynomials of length params->k.
*              No modular reduction is performed.
*
* Arguments:   - gcry_dilithium_polyvec *w: pointer to output vector
*              - const gcry_dilithium_polyvec *u: pointer to first summand
*              - const gcry_dilithium_polyvec *v: pointer to second summand
**************************************************/
void polyveck_add(gcry_dilithium_param_t *params, gcry_dilithium_polyvec *w, const gcry_dilithium_polyvec *u, const gcry_dilithium_polyvec *v) {
  unsigned int i;

  for(i = 0; i < params->k; ++i)
    poly_add(&w->vec[i], &u->vec[i], &v->vec[i]);
}

/*************************************************
* Name:        polyveck_sub
*
* Description: Subtract vectors of polynomials of length params->k.
*              No modular reduction is performed.
*
* Arguments:   - gcry_dilithium_polyvec *w: pointer to output vector
*              - const gcry_dilithium_polyvec *u: pointer to first input vector
*              - const gcry_dilithium_polyvec *v: pointer to second input vector to be
*                                   subtracted from first input vector
**************************************************/
void polyveck_sub(gcry_dilithium_param_t *params, gcry_dilithium_polyvec *w, const gcry_dilithium_polyvec *u, const gcry_dilithium_polyvec *v) {
  unsigned int i;

  for(i = 0; i < params->k; ++i)
    poly_sub(&w->vec[i], &u->vec[i], &v->vec[i]);
}

/*************************************************
* Name:        polyveck_shiftl
*
* Description: Multiply vector of polynomials of Length params->k by 2^GCRY_DILITHIUM_D without modular
*              reduction. Assumes input coefficients to be less than 2^{31-GCRY_DILITHIUM_D}.
*
* Arguments:   - gcry_dilithium_polyvec *v: pointer to input/output vector
**************************************************/
void polyveck_shiftl(gcry_dilithium_param_t *params, gcry_dilithium_polyvec *v) {
  unsigned int i;

  for(i = 0; i < params->k; ++i)
    poly_shiftl(&v->vec[i]);
}

/*************************************************
* Name:        polyveck_ntt
*
* Description: Forward NTT of all polynomials in vector of length params->k. Output
*              coefficients can be up to 16*GCRY_DILITHIUM_Q larger than input coefficients.
*
* Arguments:   - gcry_dilithium_polyvec *v: pointer to input/output vector
**************************************************/
void polyveck_ntt(gcry_dilithium_param_t *params, gcry_dilithium_polyvec *v) {
  unsigned int i;

  for(i = 0; i < params->k; ++i)
    poly_ntt(&v->vec[i]);
}

/*************************************************
* Name:        polyveck_invntt_tomont
*
* Description: Inverse NTT and multiplication by 2^{32} of polynomials
*              in vector of length params->k. Input coefficients need to be less
*              than 2*GCRY_DILITHIUM_Q.
*
* Arguments:   - gcry_dilithium_polyvec *v: pointer to input/output vector
**************************************************/
void polyveck_invntt_tomont(gcry_dilithium_param_t *params, gcry_dilithium_polyvec *v) {
  unsigned int i;

  for(i = 0; i < params->k; ++i)
    poly_invntt_tomont(&v->vec[i]);
}

void polyveck_pointwise_poly_montgomery(gcry_dilithium_param_t *params, gcry_dilithium_polyvec *r, const poly *a, const gcry_dilithium_polyvec *v) {
  unsigned int i;

  for(i = 0; i < params->k; ++i)
    poly_pointwise_montgomery(&r->vec[i], a, &v->vec[i]);
}


/*************************************************
* Name:        polyveck_chknorm
*
* Description: Check infinity norm of polynomials in vector of length params->k.
*              Assumes input gcry_dilithium_polyvec to be reduced by polyveck_reduce().
*
* Arguments:   - const gcry_dilithium_polyvec *v: pointer to vector
*              - int32_t B: norm bound
*
* Returns 0 if norm of all polynomials are strictly smaller than B <= (GCRY_DILITHIUM_Q-1)/8
* and 1 otherwise.
**************************************************/
int polyveck_chknorm(gcry_dilithium_param_t *params, const gcry_dilithium_polyvec *v, int32_t bound) {
  unsigned int i;

  for(i = 0; i < params->k; ++i)
    if(poly_chknorm(&v->vec[i], bound))
      return 1;

  return 0;
}

/*************************************************
* Name:        polyveck_power2round
*
* Description: For all coefficients a of polynomials in vector of length params->k,
*              compute a0, a1 such that a mod^+ GCRY_DILITHIUM_Q = a1*2^GCRY_DILITHIUM_D + a0
*              with -2^{GCRY_DILITHIUM_D-1} < a0 <= 2^{GCRY_DILITHIUM_D-1}. Assumes coefficients to be
*              standard representatives.
*
* Arguments:   - gcry_dilithium_polyvec *v1: pointer to output vector of polynomials with
*                              coefficients a1
*              - gcry_dilithium_polyvec *v0: pointer to output vector of polynomials with
*                              coefficients a0
*              - const gcry_dilithium_polyvec *v: pointer to input vector
**************************************************/
void polyveck_power2round(gcry_dilithium_param_t *params, gcry_dilithium_polyvec *v1, gcry_dilithium_polyvec *v0, const gcry_dilithium_polyvec *v) {
  unsigned int i;

  for(i = 0; i < params->k; ++i)
    poly_power2round(&v1->vec[i], &v0->vec[i], &v->vec[i]);
}

/*************************************************
* Name:        polyveck_decompose
*
* Description: For all coefficients a of polynomials in vector of length params->k,
*              compute high and low bits a0, a1 such a mod^+ GCRY_DILITHIUM_Q = a1*ALPHA + a0
*              with -ALPHA/2 < a0 <= ALPHA/2 except a1 = (GCRY_DILITHIUM_Q-1)/ALPHA where we
*              set a1 = 0 and -ALPHA/2 <= a0 = a mod GCRY_DILITHIUM_Q - GCRY_DILITHIUM_Q < 0.
*              Assumes coefficients to be standard representatives.
*
* Arguments:   - gcry_dilithium_polyvec *v1: pointer to output vector of polynomials with
*                              coefficients a1
*              - gcry_dilithium_polyvec *v0: pointer to output vector of polynomials with
*                              coefficients a0
*              - const gcry_dilithium_polyvec *v: pointer to input vector
**************************************************/
void polyveck_decompose(gcry_dilithium_param_t *params, gcry_dilithium_polyvec *v1, gcry_dilithium_polyvec *v0, const gcry_dilithium_polyvec *v) {
  unsigned int i;

  for(i = 0; i < params->k; ++i)
    poly_decompose(params, &v1->vec[i], &v0->vec[i], &v->vec[i]);
}

/*************************************************
* Name:        polyveck_make_hint
*
* Description: Compute hint vector.
*
* Arguments:   - gcry_dilithium_polyvec *h: pointer to output vector
*              - const gcry_dilithium_polyvec *v0: pointer to low part of input vector
*              - const gcry_dilithium_polyvec *v1: pointer to high part of input vector
*
* Returns number of 1 bits.
**************************************************/
unsigned int polyveck_make_hint(gcry_dilithium_param_t *params,
                                gcry_dilithium_polyvec *h,
                                const gcry_dilithium_polyvec *v0,
                                const gcry_dilithium_polyvec *v1)
{
  unsigned int i, s = 0;

  for(i = 0; i < params->k; ++i)
    s += poly_make_hint(params, &h->vec[i], &v0->vec[i], &v1->vec[i]);

  return s;
}

/*************************************************
* Name:        polyveck_use_hint
*
* Description: Use hint vector to correct the high bits of input vector.
*
* Arguments:   - gcry_dilithium_polyvec *w: pointer to output vector of polynomials with
*                             corrected high bits
*              - const gcry_dilithium_polyvec *u: pointer to input vector
*              - const gcry_dilithium_polyvec *h: pointer to input hint vector
**************************************************/
void polyveck_use_hint(gcry_dilithium_param_t *params, gcry_dilithium_polyvec *w, const gcry_dilithium_polyvec *u, const gcry_dilithium_polyvec *h) {
  unsigned int i;

  for(i = 0; i < params->k; ++i)
    poly_use_hint(params, &w->vec[i], &u->vec[i], &h->vec[i]);
}

void polyveck_pack_w1(gcry_dilithium_param_t *params, uint8_t *r, const gcry_dilithium_polyvec *w1) {
  unsigned int i;

  for(i = 0; i < params->k; ++i)
    polyw1_pack(params, &r[i*params->polyw1_packedbytes], &w1->vec[i]);
}
