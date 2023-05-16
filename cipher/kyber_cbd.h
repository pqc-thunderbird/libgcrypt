#ifndef CBD_H
#define CBD_H

#include <stdint.h>
#include "kyber_params.h"
#include "kyber_poly.h"

/**
 * buf has length KYBER_ETA1*KYBER_N/4
 */
void poly_cbd_eta1(poly *r, const uint8_t* buf, gcry_kyber_param_t const* param);

void poly_cbd_eta2(poly *r, const uint8_t buf[KYBER_ETA2*KYBER_N/4]);

#endif
