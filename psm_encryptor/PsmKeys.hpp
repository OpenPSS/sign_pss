#ifndef _PSM_ENCRYPTOR_KEYS_H
#define _PSM_ENCRYPTOR_KEYS_H 1
#include <cstdint>

extern const char* SCE_PSM_PKCS12_PASSWORD;
extern const char* SCE_PSM_FIXED_KEY;
extern const char* SCE_PSM_FIXED_IV;
extern const char* SCE_PSM_HMAC_KEY;
extern const char* SCE_PSM_KEY;
extern const char* SCE_PSM_PSICV_KEY;
extern const char* SCE_PSM_OPICV_KEY;

extern const unsigned char SCE_PSM_HEADER_SIGNATURE_PUB_KEY[];
extern const unsigned char SCE_PSM_HEADER_SIGNATURE_PRIV_KEY[];

extern const unsigned char SCE_PSM_WHOLE_SIGNATURE_PUB_KEY[];
extern const unsigned char SCE_PSM_WHOLE_SIGNATURE_PRIV_KEY[];

uint64_t hex2bin(const char* hexEncoded, int dataSize, uint8_t* data);

#endif