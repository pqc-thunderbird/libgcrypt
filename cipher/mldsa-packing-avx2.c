#include "config.h"
#include "mldsa-packing-avx2.h"
#include "mldsa-polyvec-avx2.h"
#include "mldsa-poly-avx2.h"

/*************************************************
* Name:        unpack_sk
*
* Description: Unpack secret key sk = (rho, tr, key, t0, s1, s2).
*
* Arguments:   - const byte rho[]: output byte array for rho
*              - const byte tr[]: output byte array for tr
*              - const byte key[]: output byte array for key
*              - const polyveck *t0: pointer to output vector t0
*              - const polyvecl *s1: pointer to output vector s1
*              - const polyveck *s2: pointer to output vector s2
*              - byte sk[]: byte array containing bit-packed sk
**************************************************/
void unpack_sk(gcry_mldsa_param_t *params, byte rho[GCRY_MLDSA_SEEDBYTES],
               byte tr[GCRY_MLDSA_TRBYTES],
               byte key[GCRY_MLDSA_SEEDBYTES],
               byte *t0,
               byte *s1,
               byte *s2,
               const byte *sk)
{
  unsigned int i;

  for(i = 0; i < GCRY_MLDSA_SEEDBYTES; ++i)
    rho[i] = sk[i];
  sk += GCRY_MLDSA_SEEDBYTES;

  for(i = 0; i < GCRY_MLDSA_SEEDBYTES; ++i)
    key[i] = sk[i];
  sk += GCRY_MLDSA_SEEDBYTES;

  for(i = 0; i < GCRY_MLDSA_TRBYTES; ++i)
    tr[i] = sk[i];
  sk += GCRY_MLDSA_TRBYTES;

  for(i=0; i < params->l; ++i)
    polyeta_unpack(params, (gcry_mldsa_poly*)&s1[i * sizeof(gcry_mldsa_poly)], sk + i*params->polyeta_packedbytes);
  sk += params->l*params->polyeta_packedbytes;

  for(i=0; i < params->k; ++i)
    polyeta_unpack(params, (gcry_mldsa_poly*)&s2[i * sizeof(gcry_mldsa_poly)], sk + i*params->polyeta_packedbytes);
  sk += params->k*params->polyeta_packedbytes;

  for(i=0; i < params->k; ++i)
    polyt0_unpack((gcry_mldsa_poly*)&t0[i * sizeof(gcry_mldsa_poly)], sk + i*GCRY_MLDSA_POLYT0_PACKEDBYTES);
}