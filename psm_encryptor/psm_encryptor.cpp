#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>

#include "OpenSSL.hpp"
#include "Sony.hpp"

#include "PsmEdata.hpp"
#include "PsmHkapp.hpp"
#include "PsmKeys.hpp"
#include "psm_encryptor.hpp"

const char G_CONTENTID[0x2A] = { 0 };


PsmEdataStatus fill_contentid(char* contentId) {
    if (!contentId)
        return SCE_PSM_EDATA_ERROR_INVAL;
    strncpy_s(contentId, sizeof(G_CONTENTID), G_CONTENTID, strlen(G_CONTENTID));

    //memset(contentId, 0, sizeof(G_CONTENTID));
    //memcpy_s(contentId, sizeof(G_CONTENTID), G_CONTENTID, strlen(G_CONTENTID));

    return SCE_OK;
}

PsmEdataStatus get_keys_from_kdbg(const uint8_t* devPkcs12, unsigned int devPkcs12Size, const PsmHkapp* hostKdbg, size_t hostKdbgSize, uint8_t* game_key, uint8_t* vita_hmac_key, uint8_t* android_hmac_key, uint8_t* filename_hmac_key) {
    if (!devPkcs12)
        return SCE_PSM_EDATA_ERROR_INVAL;
    if (!hostKdbg)
        return SCE_PSM_EDATA_ERROR_INVAL;
    if (!game_key)
        return SCE_PSM_EDATA_ERROR_INVAL;
    if (!vita_hmac_key)
        return SCE_PSM_EDATA_ERROR_INVAL;
    if (!android_hmac_key)
        return SCE_PSM_EDATA_ERROR_INVAL;
    if (!filename_hmac_key)
        return SCE_PSM_EDATA_ERROR_INVAL;

    SSL_library_init();
    PKCS12* pkcs = d2i_PKCS12(NULL, &devPkcs12, devPkcs12Size);

    rsa_st* rsa = NULL;
    EVP_PKEY* pkey = NULL;
    X509* cert = NULL;
    STACK_OF(X509)* ca = NULL;

    PsmHkapp* rsa_decrypted_host_kdbg = NULL;
    PsmHkapp* aes_decrypted_host_kdbg = NULL;

    int res = SCE_OK;

    if (pkcs) {
        if (PKCS12_parse(pkcs, SCE_PSM_PKCS12_PASSWORD, &pkey, &cert, &ca)) {
            rsa = EVP_PKEY_get1_RSA(pkey);

            rsa_decrypted_host_kdbg = (PsmHkapp*)malloc(hostKdbgSize);
            aes_decrypted_host_kdbg = (PsmHkapp*)malloc(hostKdbgSize);
            if (rsa_decrypted_host_kdbg && aes_decrypted_host_kdbg)
            {
                memcpy_s(rsa_decrypted_host_kdbg, hostKdbgSize, hostKdbg, hostKdbgSize);
                if (RSA_private_decrypt(sizeof(PsmHkapp::rsa_section), hostKdbg->rsa_section.unk, rsa_decrypted_host_kdbg->rsa_section.unk, rsa, 1) >= 0)
                {
                    res = aes_cbc_decrypt(rsa_decrypted_host_kdbg->rsa_section.aes_section_key, sizeof(rsa_enc_section_hkapp::aes_section_key), rsa_decrypted_host_kdbg->rsa_section.aes_section_iv, sizeof(rsa_enc_section_hkapp::aes_section_iv), rsa_decrypted_host_kdbg->aes_section.unk, sizeof(aes_enc_section_hkapp), aes_decrypted_host_kdbg->aes_section.unk);
                    
                    // extract out vita / android / game keys
                    memcpy_s(vita_hmac_key, KEY_SIZE, aes_decrypted_host_kdbg->aes_section.vita_hmac_key, sizeof(aes_enc_section_hkapp::vita_hmac_key));
                    memcpy_s(android_hmac_key, KEY_SIZE, aes_decrypted_host_kdbg->aes_section.android_hmac_key, sizeof(aes_enc_section_hkapp::android_hmac_key));
                    memcpy_s(game_key, KEY_SIZE, aes_decrypted_host_kdbg->aes_section.game_key, sizeof(aes_enc_section_hkapp::game_key));

                    // get filename hmac key
                    memset(filename_hmac_key, 0, KEY_SIZE);
                    size_t hmac_sz = strlen(SCE_PSM_HMAC_KEY) + 1;
                    if (hmac_sz == 0x21)
                        hex2bin(SCE_PSM_HMAC_KEY, KEY_SIZE, filename_hmac_key);
                    else
                        memcpy_s(filename_hmac_key, KEY_SIZE, SCE_PSM_HMAC_KEY, hmac_sz - 1);

                }
                else {
                    res = SCE_PSM_EDATA_ERROR_OPENSSL;
                }
            }
            else
            {
                res = SCE_PSM_EDATA_ERROR_FATAL;
            }
        }
        else
        {
            res = SCE_PSM_EDATA_ERROR_OPENSSL;
        }
        PKCS12_free(pkcs);
    }
    else
    {
        res = SCE_PSM_EDATA_ERROR_OPENSSL;
    }

    // free everything
    if (cert)
        X509_free(cert);

    if (ca)
        sk_X509_pop_free(ca, X509_free);

    if (rsa)
        RSA_free(rsa);

    if (rsa_decrypted_host_kdbg)
        free(rsa_decrypted_host_kdbg);

    if (aes_decrypted_host_kdbg)
        free(aes_decrypted_host_kdbg);

    return SCE_OK;
}

PsmEdataStatus get_psse_header_keys(uint8_t header_key[KEY_SIZE], uint8_t header_iv[KEY_SIZE]) {
    if (!header_key || !header_iv)
        return SCE_PSM_EDATA_ERROR_INVAL;

    memset(header_key, 0, KEY_SIZE);

    size_t headerKeySz = strlen(SCE_PSM_FIXED_KEY) + 1;
    if (headerKeySz == 0x21)
        hex2bin(SCE_PSM_FIXED_KEY, KEY_SIZE, header_key);
    else
        memcpy_s(header_key, KEY_SIZE, SCE_PSM_FIXED_KEY, headerKeySz - 1);

    memset(header_iv, 0, KEY_SIZE);

    size_t headerIvSz = strlen(SCE_PSM_FIXED_IV) + 1;
    if (headerIvSz == 0x21)
        hex2bin(SCE_PSM_FIXED_IV, KEY_SIZE, header_iv);
    else
        memcpy_s(header_iv, KEY_SIZE, SCE_PSM_FIXED_IV, headerIvSz - 1);

    return SCE_OK;
}

PsmEdataStatus  scePsmEdataEncrypt(const char* infile, const char* outfile, const char* installPath, ScePsmEdataType type, uint8_t* devPkcs12, size_t devPkcs12Size, PsmHkapp* hostKdbg, size_t hostKdbgSize) {
    char contentId[sizeof(G_CONTENTID)];
    char installPathLowercase[0x400];
    
    uint8_t game_key[KEY_SIZE];
    uint8_t vita_hmac_key[KEY_SIZE];
    uint8_t android_hmac_key[KEY_SIZE];
    uint8_t filename_hmac_key[KEY_SIZE];

    uint8_t psse_header_key[KEY_SIZE];
    uint8_t psse_header_iv[KEY_SIZE];
    
    PsmEdataCtx edataContext;

    if (!infile || !outfile || !installPath)
        return SCE_PSM_EDATA_ERROR_INVAL;
    
    PsmEdataStatus res = fill_contentid(contentId);
    if (res == SCE_OK) {
        sprintf_s(installPathLowercase, sizeof(installPathLowercase), "%s", installPath);
        _strlwr_s(installPathLowercase, sizeof(installPathLowercase));
        
        res = get_keys_from_kdbg(devPkcs12, devPkcs12Size, hostKdbg, hostKdbgSize, game_key, vita_hmac_key, android_hmac_key, filename_hmac_key);
        if (res == SCE_OK) {
            res = get_psse_header_keys(psse_header_key, psse_header_iv);
            if (res == SCE_OK) {
                PsmEdataCtx edataCtx;

                edataCtx.infile = infile;
                edataCtx.outfile = contentId;
                edataCtx.contentId = outfile;
                edataCtx.installPath = installPathLowercase;
                edataCtx.type = type;
                edataCtx.gameKey = game_key;
                edataCtx.vita_hmac_key = vita_hmac_key;
                edataCtx.android_hmac_key = android_hmac_key;
                edataCtx.filename_key = filename_hmac_key;
                edataCtx.psse_header_key = psse_header_key;
                edataCtx.psse_header_iv = psse_header_iv;

                if (type > ReadonlyIcvAndCrypto)
                {
                    unsigned int isInvalidType = type - 2;
                    if (!isInvalidType)
                        return SCE_PSM_EDATA_ERROR_NOT_IMPLEMENTED;
                    if ((isInvalidType - 1) > 1)
                        return SCE_PSM_EDATA_ERROR_INVAL;
                }
                else if (type != ReadonlyIcvAndCrypto) {
                    if (type == WritableIcvAndCrypto
                        || type == 0x80000002
                        || type == WritableIcv
                        || type == WritableWholeSignature)
                    {
                        return SCE_PSM_EDATA_ERROR_NOT_IMPLEMENTED;
                    }
                    return SCE_PSM_EDATA_ERROR_INVAL;
                }
                memcpy(&edataContext, &edataCtx, sizeof(edataCtx));
                // return do_edata_encryption(&edataCtx);
            }
        }
    }
    return res;
}


#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN 1
#include <windows.h>

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
#endif