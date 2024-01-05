#include "config.h"

#include <string.h>

#include "slhdsa-utils.h"
#include "slhdsa-treehash.h"
#include "slhdsa-thash.h"
#include "slhdsa-address.h"
#include "avx2-immintrin-support.h"

#include "g10lib.h"

/*
 * Generate the entire Merkle tree, computing the authentication path for
 * leaf_idx, and the resulting root node using Merkle's TreeHash algorithm.
 * Expects the layer and tree parts of the tree_addr to be set, as well as the
 * tree type (i.e. SLHDSA_ADDR_TYPE_HASHTREE or SLHDSA_ADDR_TYPE_FORSTREE)
 *
 * This expects tree_addr to be initialized to the addr structures for the
 * Merkle tree nodes
 *
 * Applies the offset idx_offset to indices before building addresses, so that
 * it is possible to continue counting indices across trees.
 *
 * This works by using the standard Merkle tree building algorithm,
 */
gcry_err_code_t _gcry_slhdsa_treehashx1(unsigned char *root,
                                        unsigned char *auth_path,
                                        const _gcry_slhdsa_param_t *ctx,
                                        u32 leaf_idx,
                                        u32 idx_offset,
                                        u32 tree_height,
                                        gcry_err_code_t (*gen_leaf)(unsigned char * /* Where to write the leaves */,
                                                                    const _gcry_slhdsa_param_t * /* ctx */,
                                                                    u32 idx,
                                                                    void *info),
                                        u32 tree_addr[8],
                                        void *info)
{
  gcry_err_code_t ec = 0;
  u32 idx;
  u32 max_idx = (u32)((1 << tree_height) - 1);

  /* This is where we keep the intermediate nodes */
  byte *stack   = NULL;
  byte *current = NULL;

  stack = xtrymalloc_secure(tree_height * ctx->n);
  if (!stack)
    {
      ec = gpg_err_code_from_syserror();
      goto leave;
    }

  for (idx = 0;; idx++)
    {
      u32 internal_idx_offset = idx_offset;
      u32 internal_idx        = idx;
      u32 internal_leaf       = leaf_idx;
      u32 h; /* The height we are in the Merkle tree */
      /* variable current: Current logical node is at */
      /* index[ctx->n].  We do this to minimize the number of copies */
      /* needed during a _gcry_slhdsa_thash */

      xfree(current); /* free for previous loop iteration */
      current = xtrymalloc_secure(2 * ctx->n);
      if (!current)
        {
          ec = gpg_err_code_from_syserror();
          goto leave;
        }

      ec = gen_leaf(&current[ctx->n], ctx, idx + idx_offset, info);
      if (ec)
        goto leave;

      /* Now combine the freshly generated right node with previously */
      /* generated left ones */
      for (h = 0;; h++, internal_idx >>= 1, internal_leaf >>= 1)
        {
          unsigned char *left;

          /* Check if we hit the top of the tree */
          if (h == tree_height)
            {
              /* We hit the root; return it */
              memcpy(root, &current[ctx->n], ctx->n);
              goto leave;
            }

          /*
           * Check if the node we have is a part of the
           * authentication path; if it is, write it out
           */
          if ((internal_idx ^ internal_leaf) == 0x01)
            {
              memcpy(&auth_path[h * ctx->n], &current[ctx->n], ctx->n);
            }

          /*
           * Check if we're at a left child; if so, stop going up the stack
           * Exception: if we've reached the end of the tree, keep on going
           * (so we combine the last 4 nodes into the one root node in two
           * more iterations)
           */
          if ((internal_idx & 1) == 0 && idx < max_idx)
            {
              break;
            }

          /* Ok, we're at a right node */
          /* Now combine the left and right logical nodes together */

          /* Set the address of the node we're creating. */
          internal_idx_offset >>= 1;
          _gcry_slhdsa_set_tree_height(ctx, tree_addr, h + 1);
          _gcry_slhdsa_set_tree_index(ctx, tree_addr, internal_idx / 2 + internal_idx_offset);

          left = &stack[h * ctx->n];
          memcpy(&current[0], left, ctx->n);
          ec = _gcry_slhdsa_thash(&current[1 * ctx->n], &current[0 * ctx->n], 2, ctx, tree_addr);
          if (ec)
            goto leave;
        }

      /* We've hit a left child; save the current for when we get the */
      /* corresponding right right */
      memcpy(&stack[h * ctx->n], &current[ctx->n], ctx->n);
    }

leave:
  xfree(stack);
  xfree(current);
  return ec;
}


#ifdef USE_AVX2
gcry_err_code_t _gcry_slhdsa_treehashx8(unsigned char *root,
                                        unsigned char *auth_path,
                                        const _gcry_slhdsa_param_t *ctx,
                                        uint32_t leaf_idx,
                                        uint32_t idx_offset,
                                        uint32_t tree_height,
                                        gcry_err_code_t (*gen_leafx8)(unsigned char * /* Where to write the leaves */,
                                                                      const _gcry_slhdsa_param_t *,
                                                                      u32 idx,
                                                                      void *info),
                                        uint32_t tree_addrx8[8 * 8],
                                        void *info)
{
  gcry_err_code_t ec = 0;
  /* This is where we keep the intermediate nodes */
  byte *stackx8     = NULL;
  byte *current     = NULL;
  uint32_t left_adj = 0, prev_left_adj = 0; /* When we're doing the top 3 */
                                            /* levels, the left-most part of the tree isn't at the beginning */
                                            /* of current[].  These give the offset of the actual start */

  uint32_t idx;
  uint32_t max_idx = (1 << (tree_height - 3)) - 1;

  stackx8 = xtrymalloc_secure(8 * tree_height * ctx->n);
  if (!stackx8)
    {
      ec = gpg_err_code_from_syserror();
      goto leave;
    }

  for (idx = 0;; idx++)
    {
      uint32_t internal_idx_offset = idx_offset;
      uint32_t internal_idx        = idx;
      uint32_t internal_leaf       = leaf_idx;
      uint32_t h; /* The height we are in the Merkle tree */

      xfree(current); /* free for previous loop iteration */
      current = xtrymalloc_secure(8 * ctx->n);
      if (!current)
        {
          ec = gpg_err_code_from_syserror();
          goto leave;
        }
      ec = gen_leafx8(current, ctx, 8 * idx + idx_offset, info);
      if (ec)
        goto leave;

      /* Now combine the freshly generated right node with previously */
      /* generated left ones */
      for (h = 0;; h++, internal_idx >>= 1, internal_leaf >>= 1)
        {
          int j;
          unsigned char *left = NULL;
          /* Special processing if we're at the top of the tree */
          if (h >= tree_height - 3)
            {
              if (h == tree_height)
                {
                  /* We hit the root; return it */
                  memcpy(root, &current[7 * ctx->n], ctx->n);
                  goto leave;
                }
              /* The tree indexing logic is a bit off in this case */
              /* Adjust it so that the left-most node of the part of */
              /* the tree that we're processing has index 0 */
              prev_left_adj = left_adj;
              left_adj      = 8 - (1 << (tree_height - h - 1));
            }

          /* Check if we hit the top of the tree */
          if (h == tree_height)
            {
              /* We hit the root; return it */
              memcpy(root, &current[7 * ctx->n], ctx->n);
              goto leave;
            }

          /*
           * Check if one of the nodes we have is a part of the
           * authentication path; if it is, write it out
           */
          if ((((internal_idx << 3) ^ internal_leaf) & ~0x7) == 0)
            {
              memcpy(&auth_path[h * ctx->n], &current[(((internal_leaf & 7) ^ 1) + prev_left_adj) * ctx->n], ctx->n);
            }

          /*
           * Check if we're at a left child; if so, stop going up the stack
           * Exception: if we've reached the end of the tree, keep on going
           * (so we combine the last 8 nodes into the one root node in three
           * more iterations)
           */
          if ((internal_idx & 1) == 0 && idx < max_idx)
            {
              break;
            }

          /* Ok, we're at a right node (or doing the top 3 levels) */
          /* Now combine the left and right logical nodes together */

          /* Set the address of the node we're creating. */
          internal_idx_offset >>= 1;
          for (j = 0; j < 8; j++)
            {
              _gcry_slhdsa_set_tree_height(ctx, tree_addrx8 + j * 8, h + 1);
              _gcry_slhdsa_set_tree_index(
                  ctx, tree_addrx8 + j * 8, (8 / 2) * (internal_idx & ~1) + j - left_adj + internal_idx_offset);
            }
          left = &stackx8[h * 8 * ctx->n];
          _gcry_slhdsa_thash_avx2_sha2(&current[0 * ctx->n],
                                       &current[1 * ctx->n],
                                       &current[2 * ctx->n],
                                       &current[3 * ctx->n],
                                       &current[4 * ctx->n],
                                       &current[5 * ctx->n],
                                       &current[6 * ctx->n],
                                       &current[7 * ctx->n],
                                       &left[0 * ctx->n],
                                       &left[2 * ctx->n],
                                       &left[4 * ctx->n],
                                       &left[6 * ctx->n],
                                       &current[0 * ctx->n],
                                       &current[2 * ctx->n],
                                       &current[4 * ctx->n],
                                       &current[6 * ctx->n],
                                       2,
                                       ctx,
                                       tree_addrx8);
        }

      /* We've hit a left child; save the current for when we get the */
      /* corresponding right right */
      memcpy(&stackx8[h * 8 * ctx->n], current, 8 * ctx->n);
    }

leave:
  xfree(stackx8);
  xfree(current);
  return ec;
}

gcry_err_code_t _gcry_slhdsa_treehashx4(unsigned char *root,
                           unsigned char *auth_path,
                           const _gcry_slhdsa_param_t *ctx,
                           uint32_t leaf_idx,
                           uint32_t idx_offset,
                           uint32_t tree_height,
                           gcry_err_code_t (*gen_leafx4)(unsigned char * /* Where to write the leaves */,
                                                         const _gcry_slhdsa_param_t *,
                                                         u32 idx,
                                                         void *info),
                           uint32_t tree_addrx4[4 * 8],
                           void *info)
{
  gcry_err_code_t ec = 0;
  /* This is where we keep the intermediate nodes */
  byte *stackx4     = NULL;
  byte *current     = NULL;
  uint32_t left_adj = 0, prev_left_adj = 0; /* When we're doing the top 3 */
                                            /* levels, the left-most part of the tree isn't at the beginning */
                                            /* of current[].  These give the offset of the actual start */

  uint32_t idx;
  uint32_t max_idx = (1 << (tree_height - 2)) - 1;

  stackx4 = xtrymalloc_secure(4 * tree_height * ctx->n);
  if (!stackx4)
    {
      ec = gpg_err_code_from_syserror();
      goto leave;
    }


  for (idx = 0;; idx++)
    {

      /* Now combine the freshly generated right node with previously */
      /* generated left ones */
      uint32_t internal_idx_offset = idx_offset;
      uint32_t internal_idx        = idx;
      uint32_t internal_leaf       = leaf_idx;
      uint32_t h; /* The height we are in the Merkle tree */

      xfree(current); /* free for previous loop iteration */
      current = xtrymalloc_secure(4 * ctx->n);
      if (!current)
        {
          ec = gpg_err_code_from_syserror();
          goto leave;
        }
      gen_leafx4(current, ctx, 4 * idx + idx_offset, info);
      for (h = 0;; h++, internal_idx >>= 1, internal_leaf >>= 1)
        {
          unsigned char *left = NULL;
          int j;

          /* Special processing if we're at the top of the tree */
          if (h >= tree_height - 2)
            {
              if (h == tree_height)
                {
                  /* We hit the root; return it */
                  memcpy(root, &current[3 * ctx->n], ctx->n);
                  goto leave;
                }
              /* The tree indexing logic is a bit off in this case */
              /* Adjust it so that the left-most node of the part of */
              /* the tree that we're processing has index 0 */
              prev_left_adj = left_adj;
              left_adj      = 4 - (1 << (tree_height - h - 1));
            }

          /* Check if we hit the top of the tree */
          if (h == tree_height)
            {
              /* We hit the root; return it */
              memcpy(root, &current[3 * ctx->n], ctx->n);
              goto leave;
            }

          /*
           * Check if one of the nodes we have is a part of the
           * authentication path; if it is, write it out
           */
          if ((((internal_idx << 2) ^ internal_leaf) & ~0x3) == 0)
            {
              memcpy(&auth_path[h * ctx->n], &current[(((internal_leaf & 3) ^ 1) + prev_left_adj) * ctx->n], ctx->n);
            }

          /*
           * Check if we're at a left child; if so, stop going up the stack
           * Exception: if we've reached the end of the tree, keep on going
           * (so we combine the last 4 nodes into the one root node in two
           * more iterations)
           */
          if ((internal_idx & 1) == 0 && idx < max_idx)
            {
              break;
            }

          /* Ok, we're at a right node (or doing the top 3 levels) */
          /* Now combine the left and right logical nodes together */

          /* Set the address of the node we're creating. */
          internal_idx_offset >>= 1;
          for (j = 0; j < 4; j++)
            {
              _gcry_slhdsa_set_tree_height(ctx, tree_addrx4 + j * 8, h + 1);
              _gcry_slhdsa_set_tree_index(
                  ctx, tree_addrx4 + j * 8, (4 / 2) * (internal_idx & ~1) + j - left_adj + internal_idx_offset);
            }
          left = &stackx4[h * 4 * ctx->n];
          _gcry_slhdsa_thash_avx2_shake(&current[0 * ctx->n],
                                        &current[1 * ctx->n],
                                        &current[2 * ctx->n],
                                        &current[3 * ctx->n],
                                        &left[0 * ctx->n],
                                        &left[2 * ctx->n],
                                        &current[0 * ctx->n],
                                        &current[2 * ctx->n],
                                        2,
                                        ctx,
                                        tree_addrx4);
        }

      /* We've hit a left child; save the current for when we get the */
      /* corresponding right right */
      memcpy(&stackx4[h * 4 * ctx->n], current, 4 * ctx->n);
    }

leave:
  xfree(stackx4);
  xfree(current);
  return ec;
}
#endif