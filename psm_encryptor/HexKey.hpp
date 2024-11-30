#ifndef _PSM_ENCRYPTOR_HEXKEY_H
#define _PSM_ENCRYPTOR_HEXKEY_H 1

#include <cstdint>
#include "OpenSSL.hpp"

const int ASCII_KEY_SIZE = (KEY_SIZE * 2) + 1;

uint64_t hex2bin(const char* hexEncoded, int dataSize, uint8_t* data);

#define get_ascii_key(hex, dstSz, dst) \
      do { \
            size_t keyStrlen = strlen(hex) + 1; \
            if (keyStrlen == ((dstSz * 2) + 1)) hex2bin(hex, dstSz, dst); \
            else memcpy_s(dst, dstSz, hex, dstSz); \
      } while (0);

#endif