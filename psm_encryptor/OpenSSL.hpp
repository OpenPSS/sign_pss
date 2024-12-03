#ifndef _PSM_ENCRYPTOR_OPENSSL_H
#define _PSM_ENCRYPTOR_OPENSSL_H 1

#include <cstdint>
#include "PsmEdata.hpp"

const int KEY_SIZE = 0x10;
const int MD5_SIZE = KEY_SIZE;
const int SHA256_SIZE = (KEY_SIZE * 2);

ScePsmEdataStatus aes_cbc_encrypt(const uint8_t* key, std::size_t key_size, const uint8_t* iv, std::size_t iv_size, const uint8_t* in_data, int data_size, uint8_t* output);
ScePsmEdataStatus aes_cbc_decrypt(const uint8_t* key, std::size_t key_size, const uint8_t* iv, std::size_t iv_size, const uint8_t* in_data, int data_size, uint8_t* output);
ScePsmEdataStatus md5_file(const char* filename, uint8_t* digest);
ScePsmEdataStatus sha256_hmac(const uint8_t* key, int key_size, const uint8_t* data, int data_len, uint8_t* sha_out);

extern "C" {
typedef struct IUnknown IUnknown;
#include "openssl/ssl.h"
#include "openssl/pkcs12.h"
#include "openssl/x509.h"
#include "openssl/aes.h"
#include "openssl/md5.h"
#include "openssl/sha.h"
#include "openssl/err.h"
#include "openssl/hmac.h"
}

#endif