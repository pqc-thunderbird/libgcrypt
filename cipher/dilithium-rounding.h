#ifndef ROUNDING_H
#define ROUNDING_H

#include <stdint.h>
#include "dilithium-params.h"

int32_t power2round(int32_t *a0, int32_t a);

int32_t decompose(gcry_dilithium_param_t *params, int32_t *a0, int32_t a);

unsigned int make_hint(gcry_dilithium_param_t *params, int32_t a0, int32_t a1);

int32_t use_hint(gcry_dilithium_param_t *params, int32_t a, unsigned int hint);

#endif
