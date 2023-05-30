

#include <stdint.h>
//#include "gcrypt.h"
#include "kyber_params.h"
#include "kyber_poly.h"
#include "kyber_polyvec.h"

gcry_error_t gcry_kyber_polymatrix_create(gcry_kyber_polyvec **polymat, gcry_kyber_param_t const* param)
{
    gcry_error_t ec = 0;
   unsigned i;

   if(!(*polymat = xtrymalloc(sizeof(**polymat) * param->k)))
   {
       return gpg_error_from_syserror();
   }
   //memset((polymat)[0], 0, sizeof(**polymat) * param->k);
   for(i = 0; i < param->k; i++)
   {
       (*polymat)[i].vec =  NULL;
   }

   for(i = 0; i < param->k; i++)
   {
       if((ec = gcry_kyber_polyvec_create(&(*polymat)[i], param)))
       {
           ec = gpg_err_code_from_syserror ();
           goto end;
       }
   }
end:
   // TODOmtg: should not be necessary
   if(ec)
   {
       gcry_kyber_polymatrix_destroy(polymat, param);
   }
   return ec;
}


void gcry_kyber_polymatrix_destroy(gcry_kyber_polyvec **polymat, gcry_kyber_param_t const* param)
{
        unsigned i;
        if(polymat == NULL)
        {
            return;
        }
        for(i = 0; i < param->k; i++)
        {
            gcry_kyber_polyvec_destroy(&(*polymat)[i]);
        }
        xfree(*polymat);
        *polymat = NULL;
}

gcry_error_t gcry_kyber_polyvec_create(gcry_kyber_polyvec *polyvec, gcry_kyber_param_t const* param)
{
   if(!(polyvec->vec = xtrymalloc_secure(sizeof(*polyvec->vec) * param->k)))
   {
        return gpg_err_code_from_syserror ();
   }
   return 0;
}

void gcry_kyber_polyvec_destroy(gcry_kyber_polyvec *polyvec)
{
    xfree(polyvec->vec);
}

/*************************************************
* Name:        gcry_kyber_polyvec_compress
*
* Description: Compress and serialize vector of polynomials
*
* Arguments:   - uint8_t *r: pointer to output byte array
*                            (needs space for KYBER_POLYVECCOMPRESSEDBYTES)
*              - const gcry_kyber_polyvec *a: pointer to input vector of polynomials
**************************************************/
void gcry_kyber_polyvec_compress(uint8_t* r, const gcry_kyber_polyvec *a, gcry_kyber_param_t const* param)
{
    unsigned int i,j,k;

    if(param->id == GCRY_KYBER_1024)
    {
        uint16_t t[8];
        for(i=0;i<param->k;i++) {
            for(j=0;j<GCRY_KYBER_N/8;j++) {
                for(k=0;k<8;k++) {
                    t[k]  = a->vec[i].coeffs[8*j+k];
                    t[k] += ((int16_t)t[k] >> 15) & GCRY_KYBER_Q;
                    t[k]  = ((((uint32_t)t[k] << 11) + GCRY_KYBER_Q/2)/GCRY_KYBER_Q) & 0x7ff;
                }

                r[ 0] = (t[0] >>  0);
                r[ 1] = (t[0] >>  8) | (t[1] << 3);
                r[ 2] = (t[1] >>  5) | (t[2] << 6);
                r[ 3] = (t[2] >>  2);
                r[ 4] = (t[2] >> 10) | (t[3] << 1);
                r[ 5] = (t[3] >>  7) | (t[4] << 4);
                r[ 6] = (t[4] >>  4) | (t[5] << 7);
                r[ 7] = (t[5] >>  1);
                r[ 8] = (t[5] >>  9) | (t[6] << 2);
                r[ 9] = (t[6] >>  6) | (t[7] << 5);
                r[10] = (t[7] >>  3);
                r += 11;
            }
        }
    }
    else
    {

        uint16_t t[4];
        for(i=0;i<param->k;i++) {
            for(j=0;j<GCRY_KYBER_N/4;j++) {
                for(k=0;k<4;k++) {
                    t[k]  = a->vec[i].coeffs[4*j+k];
                    t[k] += ((int16_t)t[k] >> 15) & GCRY_KYBER_Q;
                    t[k]  = ((((uint32_t)t[k] << 10) + GCRY_KYBER_Q/2)/ GCRY_KYBER_Q) & 0x3ff;
                }

                r[0] = (t[0] >> 0);
                r[1] = (t[0] >> 8) | (t[1] << 2);
                r[2] = (t[1] >> 6) | (t[2] << 4);
                r[3] = (t[2] >> 4) | (t[3] << 6);
                r[4] = (t[3] >> 2);
                r += 5;
            }
        }
    }
}

/*************************************************
* Name:        gcry_kyber_polyvec_decompress
*
* Description: De-serialize and decompress vector of polynomials;
*              approximate inverse of gcry_kyber_polyvec_compress
*
* Arguments:   - gcry_kyber_polyvec *r:       pointer to output vector of polynomials
*              - const uint8_t *a: pointer to input byte array
*                                  (of length KYBER_POLYVECCOMPRESSEDBYTES)
**************************************************/
void gcry_kyber_polyvec_decompress(gcry_kyber_polyvec *r, const uint8_t* a, gcry_kyber_param_t const* param)
{
    unsigned int i,j,k;

    if(param->id == GCRY_KYBER_1024)
    {
        //#if (KYBER_POLYVECCOMPRESSEDBYTES == (param->k * 352))
        uint16_t t[8];
        for(i=0;i<param->k;i++) {
            for(j=0;j<GCRY_KYBER_N/8;j++) {
                t[0] = (a[0] >> 0) | ((uint16_t)a[ 1] << 8);
                t[1] = (a[1] >> 3) | ((uint16_t)a[ 2] << 5);
                t[2] = (a[2] >> 6) | ((uint16_t)a[ 3] << 2) | ((uint16_t)a[4] << 10);
                t[3] = (a[4] >> 1) | ((uint16_t)a[ 5] << 7);
                t[4] = (a[5] >> 4) | ((uint16_t)a[ 6] << 4);
                t[5] = (a[6] >> 7) | ((uint16_t)a[ 7] << 1) | ((uint16_t)a[8] << 9);
                t[6] = (a[8] >> 2) | ((uint16_t)a[ 9] << 6);
                t[7] = (a[9] >> 5) | ((uint16_t)a[10] << 3);
                a += 11;

                for(k=0;k<8;k++)
                    r->vec[i].coeffs[8*j+k] = ((uint32_t)(t[k] & 0x7FF)*GCRY_KYBER_Q + 1024) >> 11;
            }
        }
    }
    else
    {
        //#elif (KYBER_POLYVECCOMPRESSEDBYTES == (param->k * 320))
        uint16_t t[4];
        for(i=0;i<param->k;i++) {
            for(j=0;j<GCRY_KYBER_N/4;j++) {
                t[0] = (a[0] >> 0) | ((uint16_t)a[1] << 8);
                t[1] = (a[1] >> 2) | ((uint16_t)a[2] << 6);
                t[2] = (a[2] >> 4) | ((uint16_t)a[3] << 4);
                t[3] = (a[3] >> 6) | ((uint16_t)a[4] << 2);
                a += 5;

                for(k=0;k<4;k++)
                    r->vec[i].coeffs[4*j+k] = ((uint32_t)(t[k] & 0x3FF)*GCRY_KYBER_Q + 512) >> 10;
            }
        }
    }
}

/*************************************************
* Name:        gcry_kyber_polyvec_tobytes
*
* Description: Serialize vector of polynomials
*
* Arguments:   - uint8_t *r: pointer to output byte array
*                            (needs space for KYBER_POLYVECBYTES)
*              - const gcry_kyber_polyvec *a: pointer to input vector of polynomials
**************************************************/
void gcry_kyber_polyvec_tobytes(uint8_t* r, const gcry_kyber_polyvec *a, gcry_kyber_param_t const* param)
{
  unsigned int i;
  for(i=0;i<param->k;i++)
  {
    poly_tobytes(r+i*GCRY_KYBER_POLYBYTES, &a->vec[i]);
  }
}

/*************************************************
* Name:        gcry_kyber_polyvec_frombytes
*
* Description: De-serialize vector of polynomials;
*              inverse of gcry_kyber_polyvec_tobytes
*
* Arguments:   - uint8_t *r:       pointer to output byte array
*              - const gcry_kyber_polyvec *a: pointer to input vector of polynomials
*                                  (of length KYBER_POLYVECBYTES)
**************************************************/
void gcry_kyber_polyvec_frombytes(gcry_kyber_polyvec *r, const uint8_t* a, gcry_kyber_param_t const* param)
{
  unsigned int i;
  for(i=0;i<param->k;i++)
    poly_frombytes(&r->vec[i], a+i*GCRY_KYBER_POLYBYTES);
}

/*************************************************
* Name:        gcry_kyber_polyvec_ntt
*
* Description: Apply forward NTT to all elements of a vector of polynomials
*
* Arguments:   - gcry_kyber_polyvec *r: pointer to in/output vector of polynomials
**************************************************/
void gcry_kyber_polyvec_ntt(gcry_kyber_polyvec *r, gcry_kyber_param_t const* param)
{
  unsigned int i;
  for(i=0;i<param->k;i++)
    poly_ntt(&r->vec[i]);
}

/*************************************************
* Name:        gcry_kyber_polyvec_invntt_tomont
*
* Description: Apply inverse NTT to all elements of a vector of polynomials
*              and multiply by Montgomery factor 2^16
*
* Arguments:   - gcry_kyber_polyvec *r: pointer to in/output vector of polynomials
**************************************************/
void gcry_kyber_polyvec_invntt_tomont(gcry_kyber_polyvec *r, gcry_kyber_param_t const* param)
{
  unsigned int i;
  for(i=0;i<param->k;i++)
    poly_invntt_tomont(&r->vec[i]);
}

/*************************************************
* Name:        gcry_kyber_polyvec_basemul_acc_montgomery
*
* Description: Multiply elements of a and b in NTT domain, accumulate into r,
*              and multiply by 2^-16.
*
* Arguments: - poly *r: pointer to output polynomial
*            - const gcry_kyber_polyvec *a: pointer to first input vector of polynomials
*            - const gcry_kyber_polyvec *b: pointer to second input vector of polynomials
**************************************************/
void gcry_kyber_polyvec_basemul_acc_montgomery(poly *r, const gcry_kyber_polyvec *a, const gcry_kyber_polyvec *b, gcry_kyber_param_t const* param)
{
  unsigned int i;
  poly t;

  poly_basemul_montgomery(r, &a->vec[0], &b->vec[0]);
  for(i=1;i<param->k;i++)
  {
    poly_basemul_montgomery(&t, &a->vec[i], &b->vec[i]);
    poly_add(r, r, &t);
  }

  poly_reduce(r);
}

/*************************************************
* Name:        gcry_kyber_polyvec_reduce
*
* Description: Applies Barrett reduction to each coefficient
*              of each element of a vector of polynomials;
*              for details of the Barrett reduction see comments in reduce.c
*
* Arguments:   - gcry_kyber_polyvec *r: pointer to input/output polynomial
**************************************************/
void gcry_kyber_polyvec_reduce(gcry_kyber_polyvec *r, gcry_kyber_param_t const* param)
{
  unsigned int i;
  for(i=0;i<param->k;i++)
  {
    poly_reduce(&r->vec[i]);
  }
}

/*************************************************
* Name:        gcry_kyber_polyvec_add
*
* Description: Add vectors of polynomials
*
* Arguments: - gcry_kyber_polyvec *r: pointer to output vector of polynomials
*            - const gcry_kyber_polyvec *a: pointer to first input vector of polynomials
*            - const gcry_kyber_polyvec *b: pointer to second input vector of polynomials
**************************************************/
void gcry_kyber_polyvec_add(gcry_kyber_polyvec *r, const gcry_kyber_polyvec *a, const gcry_kyber_polyvec *b, gcry_kyber_param_t const* param)
{
  unsigned int i;
  for(i=0;i<param->k;i++)
  {
    poly_add(&r->vec[i], &a->vec[i], &b->vec[i]);
  }
}
