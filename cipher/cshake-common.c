/* cshake-common.c  -  Some helpers for cSHAKE and KMAC
 * Copyright (C) 2023 MTG AG
 *
 * This file is part of Libgcrypt.
 *
 * Libgcrypt is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser general Public License as
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

#include "cshake-common.h"


gcry_err_code_t _gcry_cshake_alloc_buffer(buffer_t *buf, size_t reserve, int secure)
{
  gcry_err_code_t ec = 0;
  buf->allocated     = 0;
  buf->fill_pos      = 0;
  if (secure)
    {
      buf->data = xtrymalloc_secure (reserve);
    }
  else
    {
      buf->data = xtrymalloc (reserve);
    }
  if (!buf->data)
    {
      ec = gpg_error_from_syserror ();
    }
  else
    {
      buf->allocated = reserve;
    }
  return ec;
}

int _gcry_cshake_append_to_buffer(buffer_t *buf,
                            const unsigned char *data,
                            size_t len)
{
  if (buf->allocated - buf->fill_pos < len)
    {
      return 1;
    }
  memcpy(buf->data+buf->fill_pos, data, len);
  buf->fill_pos += len;
  return 0;
}

int append_byte_to_buffer(buffer_t *buf, const unsigned char b)
{
  return _gcry_cshake_append_to_buffer(buf, &b, 1);
}

static
size_t left_or_right_encode(size_t s,
                            buffer_t *output_buffer,
                            encoded_direction_t dir,
                            int *error_flag)
{
  int i;
  size_t bytes_appended = 0;
  // determine number of octets needed to encode s
  for (i = sizeof(s); i > 0; i--)
    {
      unsigned char t = (s >> ((i - 1) * 8) & (size_t)0xFF);
      if (t != 0)
        {
          break;
        }
    }
  if (i == 0)
    {
      i = 1;
    }
  if (dir == left)
    {
      if (append_byte_to_buffer(output_buffer, i))
        {
          *error_flag = 1;
          return 0;
        }
      bytes_appended++;
    }
  // big endian encoding of s
  for (int j = i; j > 0; j--)
    {
      if (append_byte_to_buffer(output_buffer,
                                s >> (j - 1) * 8 & ((size_t)0xFF)))
        {
          *error_flag = 1;
          return 0;
        }
      bytes_appended++;
    }
  if (dir == right)
    {
      if (append_byte_to_buffer(output_buffer, (unsigned char)i))
        {
          *error_flag = 1;
          return 0;
        }
      bytes_appended++;
    }
  return bytes_appended;
}

size_t _gcry_cshake_left_encode(size_t s, buffer_t *output_buffer, int *error_flag)
{
  return left_or_right_encode(s, output_buffer, left, error_flag);
}

size_t _gcry_cshake_right_encode(size_t s, buffer_t *output_buffer, int *error_flag)
{
  size_t result = left_or_right_encode(s, output_buffer, right, error_flag);
  return result;
}

static size_t byte_len_from_bit_len(size_t bit_length, int *error_flag)
{
  if (bit_length % 8)
    {
      *error_flag = 1;
      return 0;
    }
  return bit_length / 8;
}

size_t _gcry_cshake_bit_len_from_byte_len(size_t byte_length, int *error_flag)
{
  size_t bit_length = 8 * byte_length;
  if (bit_length < byte_length)
    {
      *error_flag = 1;
      return 0;
    }
  return bit_length;
}


gcry_err_code_t _gcry_cshake_encode_string(const unsigned char input[],
                              size_t input_byte_length,
                              buffer_t *buf,
                              int *error_flag)
{

  size_t bit_len = _gcry_cshake_bit_len_from_byte_len(input_byte_length, error_flag);
  if (error_flag)
    {
      return GPG_ERR_INTERNAL;
    }

  _gcry_cshake_left_encode(bit_len, buf, error_flag);
  if (error_flag)
    {
      return GPG_ERR_INTERNAL;
    }
  if (_gcry_cshake_append_to_buffer(buf, input, input_byte_length))
    {
      return GPG_ERR_INTERNAL; // TODO: MEMORY EXHAUSTION (IF REALLOCATING)
    }
  return GPG_ERR_NO_ERROR;
}

#if 0
gcry_err_code_t _gcry_cshake_bytepad(unsigned char input[],
                         size_t input_byte_length,
                         size_t w_in_bytes,
                         buffer_t *buf)
{
  int error_flag       = 0;
  size_t written_bytes = _gcry_cshake_left_encode(w_in_bytes, buf, &error_flag);
  if (error_flag)
    {
      return GPG_ERR_INTERNAL;
    }
  if (_gcry_cshake_append_to_buffer(buf, input, input_byte_length))
    {
      return GPG_ERR_INTERNAL;
    }

  written_bytes += input_byte_length;
  if (w_in_bytes > written_bytes)
    {
      const size_t nb_trail_zeroes = w_in_bytes - written_bytes;
      for (size_t i = 0; i < nb_trail_zeroes; i++)
        {
          if (append_byte_to_buffer(buf, 0))
            {
              return GPG_ERR_INTERNAL;
            }
        }
    }
  return GPG_ERR_NO_ERROR;
}
#endif
