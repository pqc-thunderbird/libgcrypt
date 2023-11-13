#include <string.h>
#include <config.h>
#include "types.h"
#include "slhdsa-address.h"
#include "slhdsa-params.h"
#include "slhdsa-utils.h"

/*
 * Specify which level of Merkle tree (the "layer") we're working on
 */
void _gcry_slhdsa_set_layer_addr(const _gcry_slhdsa_param_t *ctx, u32 addr[8], u32 layer)
{
  ((unsigned char *)addr)[ctx->offset_layer] = (unsigned char)layer;
}

/*
 * Specify which Merkle tree within the level (the "tree address") we're working on
 */
void _gcry_slhdsa_set_tree_addr(const _gcry_slhdsa_param_t *ctx, u32 addr[8], u64 tree)
{
  _gcry_slhdsa_ull_to_bytes(&((unsigned char *)addr)[ctx->offset_tree], 8, tree);
}

/*
 * Specify the reason we'll use this address structure for, that is, what
 * hash will we compute with it.  This is used so that unrelated types of
 * hashes don't accidentally get the same address structure.  The type will be
 * one of the SLHDSA_ADDR_TYPE constants
 */
void _gcry_slhdsa_set_type(const _gcry_slhdsa_param_t *ctx, u32 addr[8], u32 type)
{
  ((unsigned char *)addr)[ctx->offset_type] = (unsigned char)type;
}

/*
 * Copy the layer and tree fields of the address structure.  This is used
 * when we're doing multiple types of hashes within the same Merkle tree
 */
void _gcry_slhdsa_copy_subtree_addr(const _gcry_slhdsa_param_t *ctx, u32 out[8], const u32 in[8])
{
  memcpy(out, in, ctx->offset_tree + 8);
}

/* These functions are used for OTS addresses. */

/*
 * Specify which Merkle leaf we're working on; that is, which OTS keypair
 * we're talking about.
 */
void _gcry_slhdsa_set_keypair_addr(const _gcry_slhdsa_param_t *ctx, u32 addr[8], u32 keypair)
{
  if (ctx->full_height / ctx->d > 8)
    {
      /* We have > 256 OTS at the bottom of the Merkle tree; to specify */
      /* which one, we'd need to express it in two bytes */
      ((unsigned char *)addr)[ctx->offset_kp_addr2] = (unsigned char)(keypair >> 8);
    }
  ((unsigned char *)addr)[ctx->offset_kp_addr1] = (unsigned char)keypair;
}

/*
 * Copy the layer, tree and keypair fields of the address structure.  This is
 * used when we're doing multiple things within the same OTS keypair
 */
void _gcry_slhdsa_copy_keypair_addr(const _gcry_slhdsa_param_t *ctx, u32 out[8], const u32 in[8])
{
  memcpy(out, in, ctx->offset_tree + 8);
  if (ctx->full_height / ctx->d > 8)
    {
      ((unsigned char *)out)[ctx->offset_kp_addr2] = ((unsigned char *)in)[ctx->offset_kp_addr2];
    }
  ((unsigned char *)out)[ctx->offset_kp_addr1] = ((unsigned char *)in)[ctx->offset_kp_addr1];
}

/*
 * Specify which Merkle chain within the OTS we're working with
 * (the chain address)
 */
void _gcry_slhdsa_set_chain_addr(const _gcry_slhdsa_param_t *ctx, u32 addr[8], u32 chain)
{
  ((unsigned char *)addr)[ctx->offset_chain_addr] = (unsigned char)chain;
}

/*
 * Specify where in the Merkle chain we are
 * (the hash address)
 */
void _gcry_slhdsa_set_hash_addr(const _gcry_slhdsa_param_t *ctx, u32 addr[8], u32 hash)
{
  ((unsigned char *)addr)[ctx->offset_hash_addr] = (unsigned char)hash;
}

/* These functions are used for all hash tree addresses (including FORS). */

/*
 * Specify the height of the node in the Merkle/FORS tree we are in
 * (the tree height)
 */
void _gcry_slhdsa_set_tree_height(const _gcry_slhdsa_param_t *ctx, u32 addr[8], u32 tree_height)
{
  ((unsigned char *)addr)[ctx->offset_tree_hgt] = (unsigned char)tree_height;
}

/*
 * Specify the distance from the left edge of the node in the Merkle/FORS tree
 * (the tree index)
 */
void _gcry_slhdsa_set_tree_index(const _gcry_slhdsa_param_t *ctx, u32 addr[8], u32 tree_index)
{
  _gcry_slhdsa_u32_to_bytes(&((unsigned char *)addr)[ctx->offset_tree_index], tree_index);
}
