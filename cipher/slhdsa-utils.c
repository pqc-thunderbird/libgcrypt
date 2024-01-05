#include "config.h"

#include <string.h>

#include "slhdsa-utils.h"
#include "slhdsa-hash.h"
#include "slhdsa-thash.h"
#include "slhdsa-address.h"

#include "g10lib.h"

/**
 * Converts the value of 'in' to 'outlen' bytes in big-endian byte order.
 */
void _gcry_slhdsa_ull_to_bytes(byte *out, unsigned int outlen, unsigned long long in)
{
  int i;

  /* Iterate over out in decreasing order, for big-endianness. */
  for (i = (signed int)outlen - 1; i >= 0; i--)
    {
      out[i] = in & 0xff;
      in     = in >> 8;
    }
}

void _gcry_slhdsa_u32_to_bytes(byte *out, u32 in)
{
  out[0] = (byte)(in >> 24);
  out[1] = (byte)(in >> 16);
  out[2] = (byte)(in >> 8);
  out[3] = (byte)in;
}

/**
 * Converts the inlen bytes in 'in' from big-endian byte order to an integer.
 */
unsigned long long _gcry_slhdsa_bytes_to_ull(const byte *in, unsigned int inlen)
{
  unsigned long long retval = 0;
  unsigned int i;

  for (i = 0; i < inlen; i++)
    {
      retval |= ((unsigned long long)in[i]) << (8 * (inlen - 1 - i));
    }
  return retval;
}

/**
 * Computes a root node given a leaf and an auth path.
 * Expects address to be complete other than the tree_height and tree_index.
 */
gcry_err_code_t _gcry_slhdsa_compute_root(byte *root,
                                          const byte *leaf,
                                          u32 leaf_idx,
                                          u32 idx_offset,
                                          const byte *auth_path,
                                          u32 tree_height,
                                          const _gcry_slhdsa_param_t *ctx,
                                          u32 addr[8])
{
  gcry_err_code_t ec = 0;
  u32 i;
  byte *buffer = NULL;

  buffer = xtrymalloc_secure(2 * ctx->n);
  if (!buffer)
    {
      ec = gpg_err_code_from_syserror();
      goto leave;
    }

  /* If leaf_idx is odd (last bit = 1), current path element is a right child
     and auth_path has to go left. Otherwise it is the other way around. */
  if (leaf_idx & 1)
    {
      memcpy(buffer + ctx->n, leaf, ctx->n);
      memcpy(buffer, auth_path, ctx->n);
    }
  else
    {
      memcpy(buffer, leaf, ctx->n);
      memcpy(buffer + ctx->n, auth_path, ctx->n);
    }
  auth_path += ctx->n;

  for (i = 0; i < tree_height - 1; i++)
    {
      leaf_idx >>= 1;
      idx_offset >>= 1;
      /* Set the address of the node we're creating. */
      _gcry_slhdsa_set_tree_height(ctx, addr, i + 1);
      _gcry_slhdsa_set_tree_index(ctx, addr, leaf_idx + idx_offset);

      /* Pick the right or left neighbor, depending on parity of the node. */
      if (leaf_idx & 1)
        {
          ec = _gcry_slhdsa_thash(buffer + ctx->n, buffer, 2, ctx, addr);
          if (ec)
            goto leave;
          memcpy(buffer, auth_path, ctx->n);
        }
      else
        {
          ec = _gcry_slhdsa_thash(buffer, buffer, 2, ctx, addr);
          if (ec)
            goto leave;
          memcpy(buffer + ctx->n, auth_path, ctx->n);
        }
      auth_path += ctx->n;
    }

  /* The last iteration is exceptional; we do not copy an auth_path node. */
  leaf_idx >>= 1;
  idx_offset >>= 1;
  _gcry_slhdsa_set_tree_height(ctx, addr, tree_height);
  _gcry_slhdsa_set_tree_index(ctx, addr, leaf_idx + idx_offset);
  ec = _gcry_slhdsa_thash(root, buffer, 2, ctx, addr);

leave:
  xfree(buffer);
  return ec;
}
