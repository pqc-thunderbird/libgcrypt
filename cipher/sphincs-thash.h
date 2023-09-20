#ifndef SPX_THASH_H
#define SPX_THASH_H

#include "sphincs-context.h"
#include "sphincs-params.h"

#include <stdint.h>

void _gcry_sphincsplus_thash(unsigned char *out, const unsigned char *in, unsigned int inblocks,
           const _gcry_sphincsplus_param_t *ctx, uint32_t addr[8]);

#endif
