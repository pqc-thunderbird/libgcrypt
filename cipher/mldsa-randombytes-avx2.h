#ifndef RANDOMBYTES_H
#define RANDOMBYTES_H

#include <stddef.h>
#include <stdint.h>
#include "config.h"
#include "types.h"

void randombytes(byte *out, size_t outlen);

#endif
