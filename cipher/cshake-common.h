/* cshake-common.h  -  Some helpers for cSHAKE and KMAC
 * Copyright (C) 2012-2017 Jussi Kivilinna <jussi.kivilinna@iki.fi>
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
#ifndef GCRYPT_CSHAKE_COMMON_H
#define GCRYPT_CSHAKE_COMMON_H


#include <config.h>
#include "g10lib.h"
#include <stddef.h>

typedef enum
{
  left  = 1,
  right = 2
} encoded_direction_t;

typedef struct
{
  size_t allocated;
  size_t fill_pos;
  unsigned char *data;

} buffer_t;


size_t _gcry_cshake_bit_len_from_byte_len(size_t byte_length, int *error_flag);

gcry_err_code_t _gcry_cshake_alloc_buffer(buffer_t *buf, size_t reserve, int secure);

/**
 * @brief Append data to a buffer
 *
 * @param buf the buffer to append data to
 * @param data data to append
 * @param len length of the data
 *
 * @return 0 on success, 1 if the buffer is overfilled
 */
int _gcry_cshake_append_to_buffer(buffer_t *buf,
                            const unsigned char *data,
                            size_t len);


int _gcry_cshake_append_byte_to_buffer(buffer_t *buf, const unsigned char byte);


size_t _gcry_cshake_left_encode(size_t s, buffer_t *output_buffer, int *error_flag);


size_t _gcry_cshake_right_encode(size_t s, buffer_t *output_buffer, int *error_flag);

gcry_err_code_t _gcry_cshake_encode_string(const unsigned char input[],
                              size_t input_byte_length,
                              buffer_t *buf,
                              int *error_flag);


gcry_err_code_t _gcry_cshake_byte_pad(unsigned char input[],
                         size_t input_byte_length,
                         size_t w_in_bytes,
                         buffer_t *buf);
#endif
