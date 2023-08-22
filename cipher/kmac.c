
#include "g10lib.h"
#include <config.h>
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

static gcry_err_code_t alloc_buffer(buffer_t *buf, size_t reserve, int secure)
{
  buf->allocated     = 0;
  buf->fill_pos      = 0;
  gcry_err_code_t ec = 0;
  if (secure)
    {
      buf->data = xtrymalloc_secure(reserve);
    }
  else
    {
      buf->data = xtrymalloc(reserve);
    }
  if (!buf->data)
    {
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
static int append_to_buffer(buffer_t *buf,
                            const unsigned char *data,
                            size_t len)
{
  if (buf->allocated - buf->fill_pos < len)
    {
      return 1;
    }
  memcpy(buf->data, data, len);
  buf->fill_pos += len;
  return 0;
}

static int append_byte_to_buffer(buffer_t *buf, const unsigned char byte)
{
  return append_to_buffer(buf, &byte, 1);
}

size_t left_or_right_encode(size_t s,
                            buffer_t *output_buffer,
                            encoded_direction_t dir,
                            int *error_flag)
{
  int i;
  *error_flag           = 0;
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

size_t left_encode(size_t s, buffer_t *output_buffer, int *error_flag)
{
  return left_or_right_encode(s, output_buffer, left, error_flag);
}

size_t right_encode(size_t s, buffer_t *output_buffer, int *error_flag)
{
  size_t result = left_or_right_encode(s, output_buffer, right, error_flag);
  return result;
}

size_t byte_len_from_bit_len(size_t bit_length, int *error_flag)
{
  *error_flag = 0;
  if (bit_length % 8)
    {
      *error_flag = 1;
      return 0;
    }
  return bit_length / 8;
}

size_t bit_len_from_byte_len(size_t byte_length, int *error_flag)
{
  size_t bit_length = 8 * byte_length;
  if (bit_length < byte_length)
    {
      *error_flag = 1;
      return 0;
    }
  return bit_length;
}


gcry_err_code_t encode_string(const unsigned char input[],
                              size_t input_byte_length,
                              buffer_t *buf,
                              int *error_flag)
{

  size_t bit_len = bit_len_from_byte_len(input_byte_length, error_flag);
  if (error_flag)
    {
      return GPG_ERR_INTERNAL;
    }

  left_encode(bit_len, buf, error_flag);
  if (error_flag)
    {
      return GPG_ERR_INTERNAL;
    }
  if (append_to_buffer(buf, input, input_byte_length))
    {
      return GPG_ERR_INTERNAL; // TODO: MEMORY EXHAUSTION (IF REALLOCATING)
    }
  return GPG_ERR_NO_ERROR;
}


gcry_err_code_t byte_pad(unsigned char input[],
                         size_t input_byte_length,
                         size_t w_in_bytes,
                         buffer_t *buf)
{
  int error_flag       = 0;
  size_t written_bytes = left_encode(w_in_bytes, buf, &error_flag);
  if (error_flag)
    {
      return GPG_ERR_INTERNAL;
    }
  if (append_to_buffer(buf, input, input_byte_length))
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

# if 0

void KMAC256::clear() {
   zap(m_key);
   m_key_set = false;
   m_keccak.clear();
}

std::string KMAC256::name() const {
   return std::string("KMAC256(" + std::to_string(m_output_bit_length) + ")");
}

std::unique_ptr<MessageAuthenticationCode> KMAC256::new_object() const {
   return std::make_unique<KMAC256>(m_output_bit_length);
}

size_t KMAC256::output_length() const {
   return m_output_bit_length / 8;
}

Key_Length_Specification KMAC256::key_spec() const {
   // KMAC supports key lengths from zero up to 2²⁰⁴⁰ (2^(2040)) bits:
   // https://nvlpubs.nist.gov/nistpubs/specialpublications/nist.sp.800-185.pdf#page=28
   // However, we restrict the key length to 64 bytes in order to avoid allocation of overly large memory stretches when client code works with the maximal key length.
   return Key_Length_Specification(0, 64);
}

bool KMAC256::has_keying_material() const {
   return m_key_set;
}

void KMAC256::start_msg(const uint8_t nonce[], size_t nonce_len) {
   const uint8_t dom_sep[] = {'K', 'M', 'A', 'C'};
   assert_key_material_set(m_key_set);
   std::vector<uint8_t> t_input;
   encode_string(dom_sep, sizeof(dom_sep), t_input);
   encode_string(nonce, nonce_len, t_input);
   std::vector<uint8_t> t;
   byte_pad(&t_input[0], t_input.size(), m_pad_byte_length, t);
   m_keccak.absorb(std::span(t));
   secure_vector<uint8_t> key_input;
   encode_string(&m_key[0], m_key.size(), key_input);
   secure_vector<uint8_t> newX_head;
   byte_pad(&key_input[0], key_input.size(), m_pad_byte_length, newX_head);
   m_keccak.absorb(std::span(newX_head));
}

KMAC256::KMAC256(size_t output_bit_length) :
      m_output_bit_length(output_bit_length), m_keccak(512, 00, 2), m_pad_byte_length(136) {
   // ensure valid output length
   byte_len_from_bit_len(m_output_bit_length);
}

void KMAC256::add_data(const uint8_t data[], size_t data_len) {
   assert_key_material_set(m_key_set);
   m_keccak.absorb(std::span(data, data_len));
}

void KMAC256::final_result(uint8_t output[]) {
   assert_key_material_set(m_key_set);
   std::vector<uint8_t> tail;
   right_encode(m_output_bit_length, tail);
   m_keccak.absorb(std::span(tail));

   m_keccak.finish();
   m_keccak.squeeze({output, m_output_bit_length / 8});
   m_keccak.clear();
}

void KMAC256::key_schedule(const uint8_t key[], size_t key_length) {
   m_keccak.clear();
   zap(m_key);
   m_key.insert(m_key.end(), &key[0], &key[key_length]);
   m_key_set = true;
}

#endif
