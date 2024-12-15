#ifndef _PSM_ENCRYPTOR_KEYS_H
#define _PSM_ENCRYPTOR_KEYS_H 1
#include <cstdint>
#include <iostream>

extern const char* SCE_PSM_PKCS12_PASSWORD;
extern const char* SCE_PSM_FIXED_KEY;
extern const char* SCE_PSM_FIXED_IV;
extern const char* SCE_PSM_HMAC_KEY;
extern const char* SCE_PSM_KEY;
extern const char* SCE_PSM_PSICV_KEY;
extern const char* SCE_PSM_OPICV_KEY;

extern const uint8_t SCE_PSM_HEADER_SIGNATURE_PUB_KEY[];
extern const uint8_t SCE_PSM_HEADER_SIGNATURE_PRIV_KEY[];

extern const uint8_t SCE_PSM_WHOLE_SIGNATURE_PUB_KEY[];
extern const uint8_t SCE_PSM_WHOLE_SIGNATURE_PRIV_KEY[];

int get_edata_header_private_key(const uint8_t** der_key, std::size_t* der_len);
int get_edata_whole_file_private_key(const uint8_t** der_key, std::size_t* der_len);
int get_edata_header_public_key(const uint8_t** der_key, std::size_t* der_len);
int get_edata_whole_file_public_key(const uint8_t** der_key, std::size_t* der_len);

#endif