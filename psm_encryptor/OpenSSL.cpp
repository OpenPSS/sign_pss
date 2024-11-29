#include <cstdint>
#include <cstdio>
#include "PsmEdata.hpp"
#include "OpenSSL.hpp"

#define stdin  (__acrt_iob_func(0))
#define stdout (__acrt_iob_func(1))
#define stderr (__acrt_iob_func(2))

FILE _iob[] = { *stdin, *stdout, *stderr };
extern "C" FILE* __cdecl __iob_func(void) { return _iob; }


PsmEdataStatus aes_cbc_decrypt(const uint8_t* key, size_t key_size, uint8_t* iv, size_t iv_size, const uint8_t* in_data, int data_size, uint8_t* output)
{
    if (!key)
        return SCE_PSM_EDATA_ERROR_INVAL;
    if (!iv)
        return SCE_PSM_EDATA_ERROR_INVAL;
    if (!in_data)
        return SCE_PSM_EDATA_ERROR_INVAL;

    AES_KEY dkey;
    AES_set_decrypt_key(key, key_size * 8, &dkey);
    AES_cbc_encrypt(in_data, output, data_size, &dkey, iv, 0);

    return SCE_OK;
}