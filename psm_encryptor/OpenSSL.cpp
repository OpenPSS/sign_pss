#include <cstdint>
#include <cstdio>
#include "PsmEdata.hpp"
#include "OpenSSL.hpp"

#include "openssl/hmac.h"

#include "annex_k.hpp"

#ifdef _WIN32

#define stdin  (__acrt_iob_func(0))
#define stdout (__acrt_iob_func(1))
#define stderr (__acrt_iob_func(2))

FILE _iob[] = { *stdin, *stdout, *stderr };
extern "C" FILE* __cdecl __iob_func(void) { return _iob; }

#endif /* _WIN32 */

ScePsmEdataStatus sha256_hmac(const uint8_t* key, int key_size, const uint8_t* data, int data_len, uint8_t* sha_out) {
    HMAC_CTX hmacSha;
    unsigned int len = KEY_SIZE * 2;

    HMAC_CTX_init(&hmacSha);

    HMAC_Init_ex(&hmacSha, key, key_size, EVP_sha256(), NULL);
    HMAC_Update(&hmacSha, data, data_len);
    HMAC_Final(&hmacSha, sha_out, &len);

    return SCE_OK;
}

ScePsmEdataStatus md5_file(const char* filename, uint8_t* digest) {
    char buffer[0x8000];

    FILE* mdFd;
    MD5_CTX md5Ctx;
    MD5_Init(&md5Ctx);

    if(fopen_s(&mdFd, filename, "rb")) return SCE_PSM_EDATA_ERROR_FREAD;

    fseek(mdFd, 0, SEEK_END);
    uint64_t totalSz = ftell(mdFd);
    fseek(mdFd, 0, SEEK_SET);

    do {
        std::size_t rd = fread(buffer, 1, sizeof(buffer), mdFd);
        MD5_Update(&md5Ctx, buffer, rd);
        totalSz -= rd;
    } while (totalSz > 0);

    if (mdFd) fclose(mdFd);

    MD5_Final(digest, &md5Ctx);
    return SCE_OK;
}

ScePsmEdataStatus aes_cbc_encrypt(const uint8_t* key, std::size_t key_size, const uint8_t* iv, std::size_t iv_size, const uint8_t* in_data, int data_size, uint8_t* output)
{
    if (!key)
        return SCE_PSM_EDATA_ERROR_INVAL;
    if (!iv)
        return SCE_PSM_EDATA_ERROR_INVAL;
    if (!in_data)
        return SCE_PSM_EDATA_ERROR_INVAL;

    uint8_t iv_copy[KEY_SIZE];
    memcpy_s(iv_copy, sizeof(iv_copy), iv, KEY_SIZE);

    AES_KEY dkey;
    AES_set_encrypt_key(key, key_size * 8, &dkey);
    AES_cbc_encrypt(in_data, output, data_size, &dkey, iv_copy, 1);

    return SCE_OK;
}

ScePsmEdataStatus aes_cbc_decrypt(const uint8_t* key, std::size_t key_size, const uint8_t* iv, std::size_t iv_size, const uint8_t* in_data, int data_size, uint8_t* output)
{
    if (!key)
        return SCE_PSM_EDATA_ERROR_INVAL;
    if (!iv)
        return SCE_PSM_EDATA_ERROR_INVAL;
    if (!in_data)
        return SCE_PSM_EDATA_ERROR_INVAL;
    
    uint8_t iv_copy[KEY_SIZE];
    memcpy_s(iv_copy, sizeof(iv_copy), iv, KEY_SIZE);

    AES_KEY dkey;
    AES_set_decrypt_key(key, key_size * 8, &dkey);
    AES_cbc_encrypt(in_data, output, data_size, &dkey, iv_copy, 0);

    return SCE_OK;
}