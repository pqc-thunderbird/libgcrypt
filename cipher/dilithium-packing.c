#include <config.h>
#include "dilithium-params.h"
#include "dilithium-packing.h"
#include "dilithium-polyvec.h"
#include "dilithium-poly.h"

/*************************************************
* Name:        _gcry_dilithium_pack_pk
*
* Description: Bit-pack public key pk = (rho, t1).
*
* Arguments:   - uint8_t pk[]: output byte array
*              - const uint8_t rho[]: byte array containing rho
*              - const gcry_dilithium_polyvec *t1: pointer to vector t1
**************************************************/
void _gcry_dilithium_pack_pk(gcry_dilithium_param_t *params,
             uint8_t *pk,
             const uint8_t rho[GCRY_DILITHIUM_SEEDBYTES],
             const gcry_dilithium_polyvec *t1)
{
  unsigned int i;

  for(i = 0; i < GCRY_DILITHIUM_SEEDBYTES; ++i)
    pk[i] = rho[i];
  pk += GCRY_DILITHIUM_SEEDBYTES;

  for(i = 0; i < params->k; ++i)
    _gcry_dilithium_polyt1_pack(pk + i*GCRY_DILITHIUM_POLYT1_PACKEDBYTES, &t1->vec[i]);
}

/*************************************************
* Name:        _gcry_dilithium_unpack_pk
*
* Description: Unpack public key pk = (rho, t1).
*
* Arguments:   - const uint8_t rho[]: output byte array for rho
*              - const gcry_dilithium_polyvec *t1: pointer to output vector t1
*              - uint8_t pk[]: byte array containing bit-packed pk
**************************************************/
void _gcry_dilithium_unpack_pk(gcry_dilithium_param_t *params,
               uint8_t rho[GCRY_DILITHIUM_SEEDBYTES],
               gcry_dilithium_polyvec *t1,
               const uint8_t *pk)
{
  unsigned int i;

  for(i = 0; i < GCRY_DILITHIUM_SEEDBYTES; ++i)
    rho[i] = pk[i];
  pk += GCRY_DILITHIUM_SEEDBYTES;

  for(i = 0; i < params->k; ++i)
    _gcry_dilithium_polyt1_unpack(&t1->vec[i], pk + i*GCRY_DILITHIUM_POLYT1_PACKEDBYTES);
}

/*************************************************
* Name:        _gcry_dilithium_pack_sk
*
* Description: Bit-pack secret key sk = (rho, tr, key, t0, s1, s2).
*
* Arguments:   - uint8_t sk[]: output byte array
*              - const uint8_t rho[]: byte array containing rho
*              - const uint8_t tr[]: byte array containing tr
*              - const uint8_t key[]: byte array containing key
*              - const gcry_dilithium_polyvec *t0: pointer to vector t0
*              - const gcry_dilithium_polyvec *s1: pointer to vector s1
*              - const gcry_dilithium_polyvec *s2: pointer to vector s2
**************************************************/
void _gcry_dilithium_pack_sk(gcry_dilithium_param_t *params,
             uint8_t *sk,
             const uint8_t rho[GCRY_DILITHIUM_SEEDBYTES],
             const uint8_t tr[GCRY_DILITHIUM_SEEDBYTES],
             const uint8_t key[GCRY_DILITHIUM_SEEDBYTES],
             const gcry_dilithium_polyvec *t0,
             const gcry_dilithium_polyvec *s1,
             const gcry_dilithium_polyvec *s2)
{
  unsigned int i;

  for(i = 0; i < GCRY_DILITHIUM_SEEDBYTES; ++i)
    sk[i] = rho[i];
  sk += GCRY_DILITHIUM_SEEDBYTES;

  for(i = 0; i < GCRY_DILITHIUM_SEEDBYTES; ++i)
    sk[i] = key[i];
  sk += GCRY_DILITHIUM_SEEDBYTES;

  for(i = 0; i < GCRY_DILITHIUM_SEEDBYTES; ++i)
    sk[i] = tr[i];
  sk += GCRY_DILITHIUM_SEEDBYTES;

  for(i = 0; i < params->l; ++i)
    _gcry_dilithium_polyeta_pack(params, sk + i*params->polyeta_packedbytes, &s1->vec[i]);
  sk += params->l*params->polyeta_packedbytes;

  for(i = 0; i < params->k; ++i)
    _gcry_dilithium_polyeta_pack(params, sk + i*params->polyeta_packedbytes, &s2->vec[i]);
  sk += params->k * params->polyeta_packedbytes;

  for(i = 0; i < params->k; ++i)
    _gcry_dilithium_polyt0_pack(sk + i*GCRY_DILITHIUM_POLYT0_PACKEDBYTES, &t0->vec[i]);
}

/*************************************************
* Name:        _gcry_dilithium_unpack_sk
*
* Description: Unpack secret key sk = (rho, tr, key, t0, s1, s2).
*
* Arguments:   - const uint8_t rho[]: output byte array for rho
*              - const uint8_t tr[]: output byte array for tr
*              - const uint8_t key[]: output byte array for key
*              - const gcry_dilithium_polyvec *t0: pointer to output vector t0
*              - const gcry_dilithium_polyvec *s1: pointer to output vector s1
*              - const gcry_dilithium_polyvec *s2: pointer to output vector s2
*              - uint8_t sk[]: byte array containing bit-packed sk
**************************************************/
void _gcry_dilithium_unpack_sk(gcry_dilithium_param_t *params,
               uint8_t rho[GCRY_DILITHIUM_SEEDBYTES],
               uint8_t tr[GCRY_DILITHIUM_SEEDBYTES],
               uint8_t key[GCRY_DILITHIUM_SEEDBYTES],
               gcry_dilithium_polyvec *t0,
               gcry_dilithium_polyvec *s1,
               gcry_dilithium_polyvec *s2,
               const uint8_t *sk)
{
  unsigned int i;

  for(i = 0; i < GCRY_DILITHIUM_SEEDBYTES; ++i)
    rho[i] = sk[i];
  sk += GCRY_DILITHIUM_SEEDBYTES;

  for(i = 0; i < GCRY_DILITHIUM_SEEDBYTES; ++i)
    key[i] = sk[i];
  sk += GCRY_DILITHIUM_SEEDBYTES;

  for(i = 0; i < GCRY_DILITHIUM_SEEDBYTES; ++i)
    tr[i] = sk[i];
  sk += GCRY_DILITHIUM_SEEDBYTES;

  for(i=0; i < params->l; ++i)
    _gcry_dilithium_polyeta_unpack(params, &s1->vec[i], sk + i*params->polyeta_packedbytes);
  sk += params->l*params->polyeta_packedbytes;

  for(i=0; i < params->k; ++i)
    _gcry_dilithium_polyeta_unpack(params, &s2->vec[i], sk + i*params->polyeta_packedbytes);
  sk += params->k * params->polyeta_packedbytes;

  for(i=0; i < params->k; ++i)
    _gcry_dilithium_polyt0_unpack(&t0->vec[i], sk + i*GCRY_DILITHIUM_POLYT0_PACKEDBYTES);
}

/*************************************************
* Name:        _gcry_dilithium_pack_sig
*
* Description: Bit-pack signature sig = (c, z, h).
*
* Arguments:   - uint8_t sig[]: output byte array
*              - const uint8_t *c: pointer to challenge hash length GCRY_DILITHIUM_SEEDBYTES
*              - const gcry_dilithium_polyvec *z: pointer to vector z
*              - const gcry_dilithium_polyvec *h: pointer to hint vector h
**************************************************/
void _gcry_dilithium_pack_sig(gcry_dilithium_param_t *params,
              uint8_t *sig,
              const uint8_t c[GCRY_DILITHIUM_SEEDBYTES],
              const gcry_dilithium_polyvec *z,
              const gcry_dilithium_polyvec *h)
{
  unsigned int i, j, k;

  for(i=0; i < GCRY_DILITHIUM_SEEDBYTES; ++i)
    sig[i] = c[i];
  sig += GCRY_DILITHIUM_SEEDBYTES;

  for(i = 0; i < params->l; ++i)
    _gcry_dilithium_polyz_pack(params, sig + i*params->polyz_packedbytes, &z->vec[i]);
  sig += params->l*params->polyz_packedbytes;

  /* Encode h */
  for(i = 0; i < params->omega + params->k; ++i)
    sig[i] = 0;

  k = 0;
  for(i = 0; i < params->k; ++i) {
    for(j = 0; j < GCRY_DILITHIUM_N; ++j)
      if(h->vec[i].coeffs[j] != 0)
        sig[k++] = j;

    sig[params->omega + i] = k;
  }
}

/*************************************************
* Name:        _gcry_dilithium_unpack_sig
*
* Description: Unpack signature sig = (c, z, h).
*
* Arguments:   - uint8_t *c: pointer to output challenge hash
*              - gcry_dilithium_polyvec *z: pointer to output vector z
*              - gcry_dilithium_polyvec *h: pointer to output hint vector h
*              - const uint8_t sig[]: byte array containing
*                bit-packed signature
*
* Returns 1 in case of malformed signature; otherwise 0.
**************************************************/
int _gcry_dilithium_unpack_sig(gcry_dilithium_param_t *params,
               uint8_t c[GCRY_DILITHIUM_SEEDBYTES],
               gcry_dilithium_polyvec *z,
               gcry_dilithium_polyvec *h,
               const uint8_t *sig)
{
  unsigned int i, j, k;

  for(i = 0; i < GCRY_DILITHIUM_SEEDBYTES; ++i)
    c[i] = sig[i];
  sig += GCRY_DILITHIUM_SEEDBYTES;

  for(i = 0; i < params->l; ++i)
    _gcry_dilithium_polyz_unpack(params, &z->vec[i], sig + i*params->polyz_packedbytes);
  sig += params->l*params->polyz_packedbytes;

  /* Decode h */
  k = 0;
  for(i = 0; i < params->k; ++i) {
    for(j = 0; j < GCRY_DILITHIUM_N; ++j)
      h->vec[i].coeffs[j] = 0;

    if(sig[params->omega + i] < k || sig[params->omega + i] > params->omega)
      return 1;

    for(j = k; j < sig[params->omega + i]; ++j) {
      /* Coefficients are ordered for strong unforgeability */
      if(j > k && sig[j] <= sig[j-1]) return 1;
      h->vec[i].coeffs[sig[j]] = 1;
    }

    k = sig[params->omega + i];
  }

  /* Extra indices are zero for strong unforgeability */
  for(j = k; j < params->omega; ++j)
    if(sig[j])
      return 1;

  return 0;
}
