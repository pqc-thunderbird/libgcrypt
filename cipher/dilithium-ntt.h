#ifndef NTT_H
#define NTT_H

#include <stdint.h>
#include "dilithium-params.h"

void ntt(int32_t a[GCRY_DILITHIUM_N]);

void invntt_tomont(int32_t a[GCRY_DILITHIUM_N]);

#endif
