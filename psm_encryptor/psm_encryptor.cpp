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

static char G_CONTENTID[0x2A] = { 0 };
static FILE* G_PLAINTEXT_EDATA_FILE_FD = NULL;

static FILE* G_CIPHERTEXT_EDATA_FILE_FD = NULL;
static uint64_t G_CIPHERTEXT_EDATA_FILE_OFFSET = 0;

static psse_header G_PSSE_HEADER;
static psse_block_signature G_PSSE_BLOCK_SIGNATURES;

static ScePsmEdataType G_EDATA_TYPE;
static size_t G_CURRENT_BLOCK;
static size_t G_BLOCK_SIZE;
static bool G_NEED_SIGNATURE_BLOCK;


ScePsmEdataStatus fill_contentid(char* contentId) {
    if (!contentId)
        return SCE_PSM_EDATA_ERROR_INVAL;
    
    strncpy_s(contentId, sizeof(G_CONTENTID), G_CONTENTID, strlen(G_CONTENTID));

    return SCE_OK;
}

ScePsmEdataStatus get_keys_from_kdbg(const uint8_t* devPkcs12, unsigned int devPkcs12Size, const PsmHkapp* hostKdbg, size_t hostKdbgSize, uint8_t* gameKey, uint8_t* vitaHmacKey, uint8_t* androidHmacKey, uint8_t* filename_hmac_key) {
    if (!devPkcs12)
        return SCE_PSM_EDATA_ERROR_INVAL;
    if (!hostKdbg)
        return SCE_PSM_EDATA_ERROR_INVAL;
    if (!gameKey)
        return SCE_PSM_EDATA_ERROR_INVAL;
    if (!vitaHmacKey)
        return SCE_PSM_EDATA_ERROR_INVAL;
    if (!androidHmacKey)
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
                    memcpy_s(vitaHmacKey, KEY_SIZE, aes_decrypted_host_kdbg->aes_section.vitaHmacKey, sizeof(aes_enc_section_hkapp::vitaHmacKey));
                    memcpy_s(androidHmacKey, KEY_SIZE, aes_decrypted_host_kdbg->aes_section.androidHmacKey, sizeof(aes_enc_section_hkapp::androidHmacKey));
                    memcpy_s(gameKey, KEY_SIZE, aes_decrypted_host_kdbg->aes_section.game_key, sizeof(aes_enc_section_hkapp::game_key));

                    // get filename hmac key
                    memset(filename_hmac_key, 0, KEY_SIZE);
                    size_t hmac_sz = strlen(SCE_PSM_HMAC_KEY) + 1;
                    if (hmac_sz == ASCII_KEY_SIZE)
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

ScePsmEdataStatus get_psse_header_keys(uint8_t* header_key, uint8_t* header_iv) {
    if (!header_key || !header_iv)
        return SCE_PSM_EDATA_ERROR_INVAL;

    memset(header_key, 0, KEY_SIZE);

    size_t headerKeySz = strlen(SCE_PSM_FIXED_KEY) + 1;
    if (headerKeySz == ASCII_KEY_SIZE)
        hex2bin(SCE_PSM_FIXED_KEY, KEY_SIZE, header_key);
    else
        memcpy_s(header_key, KEY_SIZE, SCE_PSM_FIXED_KEY, headerKeySz - 1);

    memset(header_iv, 0, KEY_SIZE);

    size_t headerIvSz = strlen(SCE_PSM_FIXED_IV) + 1;
    if (headerIvSz == ASCII_KEY_SIZE)
        hex2bin(SCE_PSM_FIXED_IV, KEY_SIZE, header_iv);
    else
        memcpy_s(header_iv, KEY_SIZE, SCE_PSM_FIXED_IV, headerIvSz - 1);

    return SCE_OK;
}

ScePsmEdataStatus edata_plaintext_filesize_check(const char* fileName) {
    // error if file is already opened
    if (G_PLAINTEXT_EDATA_FILE_FD) return SCE_PSM_EDATA_ERROR_FOPENED;
    if (fopen_s(&G_PLAINTEXT_EDATA_FILE_FD, fileName, "rb")) return SCE_PSM_EDATA_ERROR_FOPEN;

    // find filesize
    fseek(G_PLAINTEXT_EDATA_FILE_FD, 0, SEEK_END);
    uint64_t size = ftell(G_PLAINTEXT_EDATA_FILE_FD);
    fseek(G_PLAINTEXT_EDATA_FILE_FD, 0, SEEK_SET);

    // check filesize is < max size
    if (size <= G_PSM_EDATA_MAX_SIZE) return SCE_OK;

    // close the file if this isnt the case and return error
    if (G_PLAINTEXT_EDATA_FILE_FD) fclose(G_PLAINTEXT_EDATA_FILE_FD);
    G_PLAINTEXT_EDATA_FILE_FD = NULL;
    return SCE_PSM_EDATA_ERROR_PLAIN_TO_LARGE;
}

ScePsmEdataStatus close_edata_encrypted_file() {
    fclose(G_PLAINTEXT_EDATA_FILE_FD);
    G_PLAINTEXT_EDATA_FILE_FD = 0LL;
    return SCE_OK;
}

ScePsmEdataStatus open_edata_encrypted_file(const char* fileName) {
    if (G_CIPHERTEXT_EDATA_FILE_FD) return SCE_PSM_EDATA_ERROR_FOPENED;
    if (fopen_s(&G_CIPHERTEXT_EDATA_FILE_FD, fileName, "wb+")) return SCE_PSM_EDATA_ERROR_FOPEN;
    G_CIPHERTEXT_EDATA_FILE_OFFSET = 0;
    return SCE_OK;
}

ScePsmEdataStatus setup_psse_header(PsmEdataCtx edataContext, psse_header* psseHeader) {
    memcpy_s(psseHeader->magic, sizeof(psse_header) - offsetof(psse_header, magic), G_PSM_EDATA_MAGIC, sizeof(G_PSM_EDATA_MAGIC));
    memcpy_s(&psseHeader->version, sizeof(psse_header) - offsetof(psse_header, version), &G_PSM_EDATA_VERSION, sizeof(G_PSM_EDATA_VERSION));

    uint8_t shaOut[SHA256_SIZE];
    uint8_t md5Out[MD5_SIZE];

    const uint8_t* der;
    size_t len;

    // check filesize of the file
    uint64_t inputFileSize = 0;
    FILE* inputFileFd = NULL;
    if (!fopen_s(&inputFileFd, edataContext.infile, "rb"))
    {
        fseek(inputFileFd, 0, SEEK_END);
        inputFileSize = ftell(inputFileFd);
        fseek(inputFileFd, 0, SEEK_SET);
        fclose(inputFileFd);
    }

    memcpy_s(&psseHeader->file_size, sizeof(psse_header) - offsetof(psse_header, file_size), &inputFileSize, sizeof(inputFileSize));
    memcpy_s(&psseHeader->psse_type, sizeof(psse_header) - offsetof(psse_header, psse_type), &G_PSM_EDATA_TYPES[G_EDATA_TYPE], sizeof(G_EDATA_TYPE));
    strncpy_s(psseHeader->content_id, sizeof(psse_header) - offsetof(psse_header, content_id), edataContext.contentId, strlen(edataContext.contentId));

    // calculate md5
    md5_file(edataContext.infile, md5Out);
    memcpy_s(psseHeader->file_md5, sizeof(psse_header) - offsetof(psse_header, file_md5), md5Out, sizeof(md5Out));
    
    // sha256 hmac
    sha256_hmac(edataContext.filenameKey, KEY_SIZE, (uint8_t*)edataContext.installPath, strlen(edataContext.installPath), shaOut);
    memcpy_s(psseHeader->install_path_hmac, sizeof(psse_header) - offsetof(psse_header, install_path_hmac), shaOut, sizeof(shaOut));
    
    // generate IV
    MD5((uint8_t*)psseHeader, offsetof(psse_header, file_iv), psseHeader->header_md5);

    // encrypt filename hmac, and md5_header
    aes_cbc_encrypt(edataContext.psseHeaderKey, KEY_SIZE, edataContext.psseHeaderIv, KEY_SIZE, shaOut, sizeof(shaOut), psseHeader->install_path_hmac);
    aes_cbc_encrypt(edataContext.psseHeaderKey, KEY_SIZE, edataContext.psseHeaderIv, KEY_SIZE, psseHeader->header_md5, sizeof(psse_header::header_md5), psseHeader->file_iv);

    // sha256 the header
    SHA256((uint8_t*)&psseHeader, offsetof(psse_header, header_signature), shaOut);

    // sign it
    get_edata_header_private_key(&der, &len);
    RSA* rsaCtx = d2i_RSAPrivateKey(NULL, &der, len);
    len = sizeof(psse_header::header_signature);
    RSA_sign(NID_sha256, shaOut, sizeof(shaOut), psseHeader->header_signature, &len, rsaCtx);
    RSA_free(rsaCtx);

    return SCE_OK;
}

ScePsmEdataStatus do_edata_encryption(PsmEdataCtx edataContext) {
    if (!edataContext.infile) return SCE_PSM_EDATA_ERROR_INVAL;
    if (!edataContext.outFile) return SCE_PSM_EDATA_ERROR_INVAL;
    if (!edataContext.contentId) return SCE_PSM_EDATA_ERROR_INVAL;
    if (!edataContext.installPath) return SCE_PSM_EDATA_ERROR_INVAL;
    if (!edataContext.gameKey) return SCE_PSM_EDATA_ERROR_INVAL;
    if (!edataContext.vitaHmacKey) return SCE_PSM_EDATA_ERROR_INVAL;

    if (!edataContext.androidHmacKey || !edataContext.filenameKey || !edataContext.psseHeaderKey || !edataContext.psseHeaderIv)
        return SCE_PSM_EDATA_ERROR_INVAL;

    ScePsmEdataStatus res = edata_plaintext_filesize_check(edataContext.infile);
    if (res != SCE_OK) return res;

    res = open_edata_encrypted_file(edataContext.outFile);

    if (res != SCE_OK) {
        close_edata_encrypted_file();
        return res;
    }

    G_EDATA_TYPE = edataContext.type;

    // setup psse header
    psse_header psseHeader;
    res = setup_psse_header(edataContext, &psseHeader);
    if (res == SCE_OK) {

    }

    return res;
}

ScePsmEdataStatus  scePsmEdataEncrypt(const char* infile, const char* outfile, const char* installPath, ScePsmEdataType type, uint8_t* devPkcs12, size_t devPkcs12Size, PsmHkapp* hostKdbg, size_t hostKdbgSize) {
    char contentId[sizeof(G_CONTENTID)];
    char installPathLowercase[0x400];
    
    uint8_t gameKey[KEY_SIZE];
    uint8_t vitaHmacKey[KEY_SIZE];
    uint8_t androidHmacKey[KEY_SIZE];
    uint8_t filenameHmacKey[KEY_SIZE];

    uint8_t psseHeaderKey[KEY_SIZE];
    uint8_t psseHeaderIv[KEY_SIZE];

    if (!infile || !outfile || !installPath)
        return SCE_PSM_EDATA_ERROR_INVAL;
    
    ScePsmEdataStatus res = fill_contentid(contentId);
    if (res == SCE_OK) {
        sprintf_s(installPathLowercase, sizeof(installPathLowercase), "%s", installPath);
        _strlwr_s(installPathLowercase, sizeof(installPathLowercase));
        
        res = get_keys_from_kdbg(devPkcs12, devPkcs12Size, hostKdbg, hostKdbgSize, gameKey, vitaHmacKey, androidHmacKey, filenameHmacKey);
        if (res == SCE_OK) {
            res = get_psse_header_keys(psseHeaderKey, psseHeaderIv);
            if (res == SCE_OK) {
                PsmEdataCtx edataContext;

                edataContext.infile = infile;
                edataContext.contentId = contentId;
                edataContext.outFile = outfile;
                edataContext.installPath = installPathLowercase;
                edataContext.type = type;
                edataContext.gameKey = gameKey;
                edataContext.vitaHmacKey = vitaHmacKey;
                edataContext.androidHmacKey = androidHmacKey;
                edataContext.filenameKey = filenameHmacKey;
                edataContext.psseHeaderKey = psseHeaderKey;
                edataContext.psseHeaderIv = psseHeaderIv;

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
                return do_edata_encryption(edataContext);
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