/* slhdsa-context.h
 * Copyright (C) 2024 MTG AG
 * The code was created based on the reference implementation that is part of the ML-DSA NIST submission.
 *
 * This file is part of Libgcrypt.
 *
 * Libgcrypt is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * Libgcrypt is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#ifndef SLHDSA_CONTEXT_H
#define SLHDSA_CONTEXT_H

#include <config.h>
#include "types.h"
#include "avx2-immintrin-support.h"
#include "g10lib.h"

typedef struct
{
  byte *pub_seed;
  byte *sk_seed;

  /* sha256 state that absorbed pub_seed */
  gcry_md_hd_t state_seeded;

  /* sha512 state that absorbed pub_seed */
  gcry_md_hd_t state_seeded_512;

  byte n;          /* Hash output length in bytes */
  byte seed_bytes; /* seed length */

  /* Hypertree */
  byte tree_height;
  byte full_height;
  byte d;

  /* FORS */
  byte FORS_height;
  byte FORS_trees;
  u16 FORS_msg_bytes;
  u16 FORS_bytes;
  u16 FORS_pk_bytes;

  /* Winternitz parameters */
  byte WOTS_w;
  byte WOTS_logw;
  byte WOTS_len1;
  byte WOTS_len2;
  byte WOTS_len;
  u16 WOTS_bytes;
  u16 WOTS_pk_bytes;

  /* misc */
  byte do_use_sha512; /* Boolean: If zero, use SHA-256 for all hashes */
  byte addr_bytes;    /* Number of address bytes */

  /* sig and key size */
  u16 signature_bytes;
  byte public_key_bytes;
  byte secret_key_bytes;

  /* hash offsets */
  byte offset_layer;      /* The byte used to specify the Merkle tree layer */
  byte offset_tree;       /* The start of the 8 byte field used to specify the tree */
  byte offset_type;       /* The byte used to specify the hash type (reason) */
  byte offset_kp_addr2;   /* The high byte used to specify the key pair (which one-time signature) */
  byte offset_kp_addr1;   /* The low byte used to specify the key pair */
  byte offset_chain_addr; /* The byte used to specify the chain address (which Winternitz chain) */
  byte offset_hash_addr;  /* The byte used to specify the hash address (where in the Winternitz chain) */
  byte offset_tree_hgt;   /* The byte used to specify the height of this node in the FORS or Merkle tree */
  byte offset_tree_index; /* The start of the 4 byte field used to specify the node in the FORS or Merkle tree */

  byte is_sha2; /* Boolean: is a SHA2 parameter set (SHAKE otherwise) */

#ifdef USE_AVX2
  byte use_avx2;

  byte state_seeded_avx2[40];     /* seeded SHA256 state used during avx2 computation */
  byte state_seeded_512_avx2[72]; /* seeded SHA512 state used during avx2 computation */
#endif
} _gcry_slhdsa_param_t;

#endif
