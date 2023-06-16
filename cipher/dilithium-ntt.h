#ifndef _GCRY_DILITHIUM_NTT_H
#define _GCRY_DILITHIUM_NTT_H

#include <stdint.h>
#include "dilithium-params.h"

void _gcry_dilithium_ntt(int32_t a[GCRY_DILITHIUM_N]);

void _gcry_dilithium_invntt_tomont(int32_t a[GCRY_DILITHIUM_N]);

#endif
