#ifndef SLHDSA_THASH_H
#define SLHDSA_THASH_H

#include "config.h"

#include "slhdsa-context.h"
#include "slhdsa-params.h"

#include <stdint.h>

#include "g10lib.h"

gcry_err_code_t _gcry_slhdsa_thash(unsigned char *out, const unsigned char *in, unsigned int inblocks,
           const _gcry_slhdsa_param_t *ctx, uint32_t addr[8]);

#endif
