#ifndef VERIFY_H
#define VERIFY_H

#include <stddef.h>
#include <stdint.h>
#include "kyber_params.h"

int16_t _gcry_kyber_montgomery_reduce(int32_t a);

int16_t _gcry_kyber_barrett_reduce(int16_t a);

#endif
