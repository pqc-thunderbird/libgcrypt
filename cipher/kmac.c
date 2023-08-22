
#include "g10lib.h"
#include <config.h>
#include <stddef.h>

typedef struct {
  size_t allocated;
  size_t fill_pos;
  unsigned char *data;

} buffer_t;

static gcry_err_code_t alloc_buffer(buffer_t *buf, size_t reserve, int secure) {
  buf->allocated = 0;
  buf->fill_pos = 0;
  gcry_err_code_t ec = 0;
  if (secure) {
    buf->data = xtrymalloc_secure(reserve);
  } else {
    buf->data = xtrymalloc(reserve);
  }
  if (!buf->data) {
    ec = gpg_error_from_syserror();
  }
  return ec;
}

/**
 * @brief Append data to a buffer
 *
 * @param buf the buffer to append data to
 * @param data data to append
 * @param len length of the data
 *
 * @return 0 on success, 1 if the buffer is overfilled
 */
static int append_to_buffer(buffer_t *buf, const unsigned char *data,
                            size_t len) {
  if (buf->allocated - buf->fill_pos < len) {
    return 1;
  }
  memcpy(buf->data, data, len);
  buf->fill_pos += len;
  return 0;
  return 0;
}

static int append_byte_to_buffer(buffer_t *buf, const unsigned char byte) {
  return append_to_buffer(buf, &byte, 1);
}

size_t left_or_right_encode(size_t s, buffer_t *output_buffer,
                            int IS_LEFT_ENCODE, int *error_flag) {
  int i;
  *error_flag = 0;
  size_t bytes_appended = 0;
  // determine number of octets needed to encode s
  for (i = sizeof(s); i > 0; i--) {
    unsigned char t = (s >> ((i - 1) * 8) & (size_t)0xFF);
    if (t != 0) {
      break;
    }
  }
  if (i == 0) {
    i = 1;
  }
  if (IS_LEFT_ENCODE) {
    // output_container.push_back(static_cast<unsigned char>(i));
    if (append_byte_to_buffer(output_buffer, i)) {
      *error_flag = 1;
      return 0;
    }
    bytes_appended++;
  }
  // big endian encoding of s
  for (int j = i; j > 0; j--) {
    output_container.push_back(s >> (j - 1) * 8 & (static_cast<size_t>(0xFF)));
    bytes_appended++;
  }
  if (!IS_LEFT_ENCODE) {
    output_container.push_back(static_cast<unsigned char>(i));
    bytes_appended++;
  }
  return bytes_appended;
}

template <typename T> size_t left_encode(size_t s, T &output_container) {
  return left_or_right_encode<true>(s, output_container);
}

template <typename T> size_t right_encode(size_t s, T &output_container) {
  size_t result = left_or_right_encode<false>(s, output_container);
  return result;
}

size_t byte_len_from_bit_len(size_t bit_length) {
  if (bit_length % 8) {
    throw Invalid_Argument(
        "cannot convert byte length to bit length that is not a multiple of 8");
  }
  return bit_length / 8;
}

size_t bit_len_from_byte_len(size_t byte_length) {
  size_t bit_length = 8 * byte_length;
  if (bit_length < byte_length) {
    throw Botan::Invalid_Argument(
        "byte length is too large. Only byte lengths of up to " +
        std::to_string(std::numeric_limits<size_t>::max() / 8) +
        " are supported on this platform in this function.");
  }
  return bit_length;
}

template <typename T>
void encode_string(const unsigned char input[], size_t input_byte_length,
                   T &output_container) {
  left_encode(bit_len_from_byte_len(input_byte_length), output_container);
  output_container.insert(output_container.end(), input,
                          &input[input_byte_length]);
}

template <typename T>
void byte_pad(unsigned char input[], size_t input_byte_length,
              size_t w_in_bytes, T &output_container) {
  size_t written_bytes = left_encode(w_in_bytes, output_container);
  output_container.insert(output_container.end(), input,
                          &input[input_byte_length]);
  written_bytes += input_byte_length;
  if (w_in_bytes > written_bytes) {
    size_t nb_trail_zeroes = w_in_bytes - written_bytes;
    std::vector<unsigned char> trailing_zeroes(nb_trail_zeroes, 0);
    output_container.insert(output_container.end(), &trailing_zeroes[0],
                            &trailing_zeroes[trailing_zeroes.size()]);
  }
}
