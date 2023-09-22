#ifndef SPX_THASH_H
#define SPX_THASH_H

#include "config.h"

#include "sphincs-context.h"
#include "sphincs-params.h"

#include <stdint.h>

#include "g10lib.h"

gcry_err_code_t _gcry_sphincsplus_thash(unsigned char *out, const unsigned char *in, unsigned int inblocks,
           const _gcry_sphincsplus_param_t *ctx, uint32_t addr[8]);

#endif
