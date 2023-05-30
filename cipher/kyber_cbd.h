#ifndef CBD_H
#define CBD_H

#include <stdint.h>
#include "kyber_params.h"
#include "kyber_poly.h"

/**
 * buf has length KYBER_ETA1*GCRY_KYBER_N/4
 */
void _gcry_kyber_poly_cbd_eta1(gcry_kyber_poly *r, const uint8_t* buf, gcry_kyber_param_t const* param);

void _gcry_kyber_poly_cbd_eta2(gcry_kyber_poly *r, const uint8_t buf[GCRY_KYBER_ETA2*GCRY_KYBER_N/4]);

#endif
