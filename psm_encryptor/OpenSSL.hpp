#ifndef _PSM_ENCRYPTOR_OPENSSL_H
#define _PSM_ENCRYPTOR_OPENSSL_H 1

#include <cstdint>
#include "PsmEdata.hpp"

#define KEY_SIZE 0x10

PsmEdataStatus aes_cbc_decrypt(const uint8_t* key, size_t key_size, uint8_t* iv, size_t iv_size, const uint8_t* in_data, int data_size, uint8_t* output);

extern "C" {
typedef struct IUnknown IUnknown;
#include <openssl/ssl.h>
#include <openssl/pkcs12.h>
#include <openssl/x509.h>
#include <openssl/aes.h>
}

#endif