#ifndef SLHDSA_ADDRESS_H
#define SLHDSA_ADDRESS_H

#include <stdint.h>
#include "slhdsa-context.h"

/* The hash types that are passed to _gcry_slhdsa_set_type */
#define SLHDSA_ADDR_TYPE_WOTS 0
#define SLHDSA_ADDR_TYPE_WOTSPK 1
#define SLHDSA_ADDR_TYPE_HASHTREE 2
#define SLHDSA_ADDR_TYPE_FORSTREE 3
#define SLHDSA_ADDR_TYPE_FORSPK 4
#define SLHDSA_ADDR_TYPE_WOTSPRF 5
#define SLHDSA_ADDR_TYPE_FORSPRF 6

void _gcry_slhdsa_set_layer_addr(const _gcry_slhdsa_param_t *ctx, uint32_t addr[8], uint32_t layer);

void _gcry_slhdsa_set_tree_addr(const _gcry_slhdsa_param_t *ctx, uint32_t addr[8], uint64_t tree);

void _gcry_slhdsa_set_type(const _gcry_slhdsa_param_t *ctx, uint32_t addr[8], uint32_t type);

/* Copies the layer and tree part of one address into the other */
void _gcry_slhdsa_copy_subtree_addr(const _gcry_slhdsa_param_t *ctx, uint32_t out[8], const uint32_t in[8]);

/* These functions are used for WOTS and FORS addresses. */

void _gcry_slhdsa_set_keypair_addr(const _gcry_slhdsa_param_t *ctx, uint32_t addr[8], uint32_t keypair);

void _gcry_slhdsa_set_chain_addr(const _gcry_slhdsa_param_t *ctx, uint32_t addr[8], uint32_t chain);

void _gcry_slhdsa_set_hash_addr(const _gcry_slhdsa_param_t *ctx, uint32_t addr[8], uint32_t hash);

void _gcry_slhdsa_copy_keypair_addr(const _gcry_slhdsa_param_t *ctx, uint32_t out[8], const uint32_t in[8]);

/* These functions are used for all hash tree addresses (including FORS). */

void _gcry_slhdsa_set_tree_height(const _gcry_slhdsa_param_t *ctx, uint32_t addr[8], uint32_t tree_height);

void _gcry_slhdsa_set_tree_index(const _gcry_slhdsa_param_t *ctx, uint32_t addr[8], uint32_t tree_index);

#endif
