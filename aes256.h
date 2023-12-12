#pragma once

#define BLOCK_SIZE 16

class Aes256 {
public:
	static unsigned long decrypt(const unsigned char* key, unsigned char* encrypted, unsigned long encrypted_length);
	static void decrypt(const unsigned char* key, unsigned char* buffer);
private:
	unsigned char m_buffer[3 * BLOCK_SIZE];
	static void expand_enc_key(unsigned char* rkey, unsigned char* rc);
	static void expand_dec_key(unsigned char* rkey, unsigned char* rc);
	static void sub_bytes_inv(unsigned char* buffer);
	static void copy_key(const unsigned char* key, unsigned char* rkey);
	static void add_round_key(unsigned char* rkey, unsigned char* buffer, const unsigned char round);
	static void shift_rows_inv(unsigned char* buffer);
	static void mix_columns_inv(unsigned char* buffer);
};
