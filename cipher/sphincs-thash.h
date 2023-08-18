#ifndef SPX_THASH_H
#define SPX_THASH_H

#include "sphincs-context.h"
#include "sphincs-params.h"

#include <stdint.h>

//#define thash SPX_NAMESPACE(thash)
void thash(unsigned char *out, const unsigned char *in, unsigned int inblocks,
           const spx_ctx *ctx, uint32_t addr[8]);

#endif
