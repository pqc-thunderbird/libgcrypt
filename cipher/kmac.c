
#include "g10lib.h"
#include <config.h>
#include <stddef.h>


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
