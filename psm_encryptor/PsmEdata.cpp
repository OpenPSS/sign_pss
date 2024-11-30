#include "PsmKeys.hpp"
#include "PsmEdata.hpp"
#include "PsmHkapp.hpp"

#include "HexKey.hpp"
#include "OpenSSL.hpp"

#include <cstdio>
#include <cstdint>
#include <cstring>


static char G_CONTENTID[PSM_CONTENT_ID_SIZE] = { 0 };
static uint8_t G_PLAINTEXT_IV[KEY_SIZE] = { 0 };

static FILE* G_PLAINTEXT_EDATA_FILE_FD = NULL;

static FILE* G_CIPHERTEXT_EDATA_FILE_FD = NULL;
static uint64_t G_CIPHERTEXT_EDATA_FILE_OFFSET = 0;

static psse_header G_PSSE_HEADER;
static psse_block_signature G_PSSE_BLOCK_SIGNATURES;

static ScePsmEdataType G_EDATA_TYPE;
static int G_CURRENT_BLOCK;
static int G_BLOCK_SIZE;
static int G_NEED_SIGNATURE_BLOCK;


ScePsmEdataStatus get_content_id(char* contentId) {
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

    RSA* rsa = NULL;
    EVP_PKEY* pkey = NULL;
    X509* cert = NULL;
    STACK_OF(X509)* ca = NULL;

    PsmHkapp* rsa_decrypted_host_kdbg = NULL;
    PsmHkapp* aes_decrypted_host_kdbg = NULL;

    ScePsmEdataStatus res = SCE_OK;

    if (pkcs) {
        if (PKCS12_parse(pkcs, SCE_PSM_PKCS12_PASSWORD, &pkey, &cert, &ca)) {
            rsa = EVP_PKEY_get1_RSA(pkey);

            rsa_decrypted_host_kdbg = (PsmHkapp*)malloc(hostKdbgSize);
            aes_decrypted_host_kdbg = (PsmHkapp*)malloc(hostKdbgSize);

            if (rsa_decrypted_host_kdbg && aes_decrypted_host_kdbg)
            {
                memcpy_s(rsa_decrypted_host_kdbg, hostKdbgSize, hostKdbg, hostKdbgSize);
                if (RSA_private_decrypt(sizeof(PsmHkapp::rsa_section), (uint8_t*)&hostKdbg->rsa_section, (uint8_t*)&rsa_decrypted_host_kdbg->rsa_section, rsa, RSA_PKCS1_PADDING) >= 0)
                {
                    res = aes_cbc_decrypt(rsa_decrypted_host_kdbg->rsa_section.aes_section_key, sizeof(rsa_enc_section_hkapp::aes_section_key), rsa_decrypted_host_kdbg->rsa_section.aes_section_iv, sizeof(rsa_enc_section_hkapp::aes_section_iv), (uint8_t*)&rsa_decrypted_host_kdbg->aes_section, sizeof(aes_enc_section_hkapp), (uint8_t*)&aes_decrypted_host_kdbg->aes_section);

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

    return res;
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
    if (size <= PSM_EDATA_MAX_FILE_SIZE) return SCE_OK;

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

    memset(psseHeader->content_id, 0, sizeof(psse_header::content_id));
    strncpy_s(psseHeader->content_id, sizeof(psse_header) - offsetof(psse_header, content_id), edataContext.contentId, strlen(edataContext.contentId));

    // calculate md5
    md5_file(edataContext.infile, md5Out);
    memcpy_s(psseHeader->file_md5, sizeof(psse_header) - offsetof(psse_header, file_md5), md5Out, sizeof(md5Out));

    // sha256 hmac
    sha256_hmac(edataContext.filenameKey, KEY_SIZE, (uint8_t*)edataContext.installPath, strlen(edataContext.installPath), shaOut);
    memcpy_s(psseHeader->install_path_hmac, sizeof(psse_header) - offsetof(psse_header, install_path_hmac), shaOut, sizeof(shaOut));

    // generate IV
    MD5((uint8_t*)psseHeader, offsetof(psse_header, file_iv), G_PLAINTEXT_IV);

    // encrypt filename hmac, and md5_header
    aes_cbc_encrypt(edataContext.psseHeaderKey, KEY_SIZE, edataContext.psseHeaderIv, KEY_SIZE, shaOut, sizeof(shaOut), psseHeader->install_path_hmac);
    aes_cbc_encrypt(edataContext.psseHeaderKey, KEY_SIZE, edataContext.psseHeaderIv, KEY_SIZE, G_PLAINTEXT_IV, sizeof(G_PLAINTEXT_IV), psseHeader->file_iv);

    // sha256 the header
    SHA256((uint8_t*)psseHeader, offsetof(psse_header, header_signature), shaOut);

    // sign it
    get_edata_header_private_key(&der, &len);
    RSA* rsaCtx = d2i_RSAPrivateKey(NULL, &der, len);
    
    unsigned int rsaLen = sizeof(psse_header::header_signature);
    RSA_sign(NID_sha256, shaOut, sizeof(shaOut), psseHeader->header_signature, &rsaLen, rsaCtx);
    RSA_free(rsaCtx);

    return SCE_OK;
}

ScePsmEdataStatus get_global_psse_header(psse_header* psseHeader, int* toRead)
{
    memcpy_s(&G_PSSE_HEADER, sizeof(psse_header), psseHeader, sizeof(psse_header));
    G_CURRENT_BLOCK = 0;
    G_BLOCK_SIZE = PSM_EDATA_FIRST_BLOCK_SIZE;
    G_NEED_SIGNATURE_BLOCK = 0;
    memset(G_PSSE_BLOCK_SIGNATURES.android_hmac, 0, sizeof(G_PSSE_BLOCK_SIGNATURES.android_hmac));
    memset(G_PSSE_BLOCK_SIGNATURES.vita_hmac, 0, sizeof(G_PSSE_BLOCK_SIGNATURES.vita_hmac));
    *toRead = PSM_EDATA_FIRST_BLOCK_SIZE;
    return SCE_OK;
}

size_t write_psse_header_to_disk()
{
    size_t result = fwrite(&G_PSSE_HEADER, 1, sizeof(psse_header), G_CIPHERTEXT_EDATA_FILE_FD);
    G_CIPHERTEXT_EDATA_FILE_OFFSET += result;
    return result;
}

ScePsmEdataStatus read_from_plaintext_file(uint8_t* buffer, int* totalRead)
{
    *totalRead = fread(buffer, 1, *totalRead, G_PLAINTEXT_EDATA_FILE_FD);
    return SCE_OK;
}

ScePsmEdataStatus create_block_signature(uint8_t* vitaHmac, uint8_t* androidHmac, uint8_t* psseCiphertext, int* len) {
    if (!G_CIPHERTEXT_EDATA_FILE_FD) return SCE_PSM_EDATA_ERROR_FILE_NOT_OPENED;

    if (G_EDATA_TYPE != ReadonlyWholeSignature) {
        memcpy_s(&G_PSSE_BLOCK_SIGNATURES.vita_hmac[SHA256_SIZE * (G_CURRENT_BLOCK % PSM_EDATA_BLOCKS_PER_SIGNATURE)], SHA256_SIZE, vitaHmac, SHA256_SIZE);
        memcpy_s(&G_PSSE_BLOCK_SIGNATURES.android_hmac[SHA256_SIZE * (G_CURRENT_BLOCK % PSM_EDATA_BLOCKS_PER_SIGNATURE)], SHA256_SIZE, androidHmac, SHA256_SIZE);
        G_NEED_SIGNATURE_BLOCK += SHA256_SIZE;
    }

    if (*len >= G_BLOCK_SIZE)
    {
        if (((G_CURRENT_BLOCK % PSM_EDATA_BLOCKS_PER_SIGNATURE) == 0xF || (G_CURRENT_BLOCK % PSM_EDATA_BLOCKS_PER_SIGNATURE) == 0) && G_EDATA_TYPE != ReadonlyWholeSignature)
        {
            if (G_CURRENT_BLOCK >> 4)
                fseek(G_CIPHERTEXT_EDATA_FILE_FD, (G_CURRENT_BLOCK >> 4 << 19), SEEK_SET);
            else
                fseek(G_CIPHERTEXT_EDATA_FILE_FD, sizeof(psse_header), SEEK_SET);

            G_CIPHERTEXT_EDATA_FILE_OFFSET += fwrite(G_PSSE_BLOCK_SIGNATURES.vita_hmac, 1, sizeof(psse_block_signature::vita_hmac), G_CIPHERTEXT_EDATA_FILE_FD);
            G_CIPHERTEXT_EDATA_FILE_OFFSET += fwrite(G_PSSE_BLOCK_SIGNATURES.android_hmac, 1, sizeof(psse_block_signature::android_hmac), G_CIPHERTEXT_EDATA_FILE_FD);

            if ((G_CURRENT_BLOCK % PSM_EDATA_BLOCKS_PER_SIGNATURE) == 0xF)
            {
                G_NEED_SIGNATURE_BLOCK = 0;
                memset(G_PSSE_BLOCK_SIGNATURES.vita_hmac, 0, sizeof(G_PSSE_BLOCK_SIGNATURES.vita_hmac));
                memset(G_PSSE_BLOCK_SIGNATURES.android_hmac, 0, sizeof(G_PSSE_BLOCK_SIGNATURES.vita_hmac));
            }

            fseek(G_CIPHERTEXT_EDATA_FILE_FD, 0, SEEK_END);

        }
    }
    else if (G_EDATA_TYPE != ReadonlyWholeSignature) {
        if (G_CURRENT_BLOCK >> 4)
            fseek(G_CIPHERTEXT_EDATA_FILE_FD, G_CURRENT_BLOCK >> 4 << 19, SEEK_SET);
        else
            fseek(G_CIPHERTEXT_EDATA_FILE_FD, sizeof(psse_header), SEEK_SET);

        G_CIPHERTEXT_EDATA_FILE_OFFSET += fwrite(G_PSSE_BLOCK_SIGNATURES.vita_hmac, 1, sizeof(psse_block_signature::vita_hmac), G_CIPHERTEXT_EDATA_FILE_FD);
        G_CIPHERTEXT_EDATA_FILE_OFFSET += fwrite(G_PSSE_BLOCK_SIGNATURES.android_hmac, 1, sizeof(psse_block_signature::android_hmac), G_CIPHERTEXT_EDATA_FILE_FD);

        G_NEED_SIGNATURE_BLOCK = 0;

        memset(G_PSSE_BLOCK_SIGNATURES.vita_hmac, 0, sizeof(psse_block_signature::vita_hmac));
        memset(G_PSSE_BLOCK_SIGNATURES.android_hmac, 0, sizeof(psse_block_signature::android_hmac));

        fseek(G_CIPHERTEXT_EDATA_FILE_FD, 0, SEEK_END);
    }
    G_CIPHERTEXT_EDATA_FILE_OFFSET += fwrite(psseCiphertext, 1, *len, G_CIPHERTEXT_EDATA_FILE_FD);
    ++G_CURRENT_BLOCK;

    if (G_EDATA_TYPE == ReadonlyWholeSignature)
    {
        G_BLOCK_SIZE = PSM_EDATA_NO_SIG_BLOCK_SIZE;
    }
    else
    {
        G_BLOCK_SIZE = PSM_EDATA_NO_SIG_BLOCK_SIZE;
        if ((G_CURRENT_BLOCK % PSM_EDATA_BLOCKS_PER_SIGNATURE) == 0)
            G_BLOCK_SIZE = PSM_EDATA_SIG_BLOCK_SIZE;
    }

    *len = G_BLOCK_SIZE;

    return SCE_OK;
}

ScePsmEdataStatus write_whole_file_signature_and_hmac() {

    const uint8_t* der;
    size_t len = 0xDEADBEEF;

    if (G_EDATA_TYPE != ReadonlyWholeSignature && G_NEED_SIGNATURE_BLOCK)
    {
        int blockStart = 0;
        if (G_CURRENT_BLOCK >> 4)
            blockStart = G_CURRENT_BLOCK >> 4 << 19;
        else
            blockStart = sizeof(psse_header);

        fseek(G_CIPHERTEXT_EDATA_FILE_FD, blockStart, SEEK_SET);
        G_CIPHERTEXT_EDATA_FILE_OFFSET += fwrite(G_PSSE_BLOCK_SIGNATURES.vita_hmac, 1, sizeof(psse_block_signature::vita_hmac), G_CIPHERTEXT_EDATA_FILE_FD);
        G_CIPHERTEXT_EDATA_FILE_OFFSET += fwrite(G_PSSE_BLOCK_SIGNATURES.android_hmac, 1, sizeof(psse_block_signature::android_hmac), G_CIPHERTEXT_EDATA_FILE_FD);

        G_NEED_SIGNATURE_BLOCK = 0;
    }

    fseek(G_CIPHERTEXT_EDATA_FILE_FD, 0, SEEK_SET);

    uint8_t sigOut[sizeof(psse_header::whole_file_signature)];
    memset(sigOut, 0, sizeof(sigOut));

    SHA256_CTX shaCtx;
    SHA256_Init(&shaCtx);

    // begin signing 

    for (int i = 0; len != 0; i++) {
        uint8_t fileBlock[PSM_EDATA_NO_SIG_BLOCK_SIZE];
        len = fread(fileBlock, 1, sizeof(fileBlock), G_CIPHERTEXT_EDATA_FILE_FD);

        if (i == 0) // hash everything except signature section
            memset(((psse_header*)fileBlock)->whole_file_signature, 0, sizeof(psse_header::whole_file_signature));

        if (len != (len & 0xFFFFFFF0)) // why?
            len = (len + 0x10) & 0xFFFFFFF0;

        SHA256_Update(&shaCtx, fileBlock, len);
    };

    uint8_t shaOut[SHA256_SIZE];
    SHA256_Final(shaOut, &shaCtx);

    get_edata_whole_file_private_key(&der, &len);
    RSA* rsa = d2i_RSAPrivateKey(NULL, &der, len);

    unsigned int rsaLen = sizeof(psse_header::whole_file_signature);
    RSA_sign(NID_sha256, shaOut, sizeof(shaOut), sigOut, &rsaLen, rsa);
    RSA_free(rsa);

    // write signature to file
    fseek(G_CIPHERTEXT_EDATA_FILE_FD, offsetof(psse_header, whole_file_signature), SEEK_SET);
    G_CIPHERTEXT_EDATA_FILE_OFFSET += fwrite(sigOut, 1, sizeof(sigOut), G_CIPHERTEXT_EDATA_FILE_FD);
    if (G_CIPHERTEXT_EDATA_FILE_FD) fclose(G_CIPHERTEXT_EDATA_FILE_FD);
    G_CIPHERTEXT_EDATA_FILE_FD = NULL;

    return SCE_OK;
}

ScePsmEdataStatus do_edata_encryption(PsmEdataCtx edataContext) {

    uint8_t vitaHmac[SHA256_SIZE];
    uint8_t androidHmac[SHA256_SIZE];

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
        uint8_t filePlaintext[PSM_EDATA_MAX_BLOCK_SIZE];
        memset(filePlaintext, 0, sizeof(filePlaintext));

        int len;
        res = get_global_psse_header(&psseHeader, &len);
        if (res == SCE_OK) {
            write_psse_header_to_disk();
            res = read_from_plaintext_file(filePlaintext, &len);
            if (len) {
                while (1) {
                    uint8_t blockCiphertext[PSM_EDATA_MAX_BLOCK_SIZE];
                    uint8_t blockPlaintext[PSM_EDATA_MAX_BLOCK_SIZE];

                    memset(blockCiphertext, 0, sizeof(blockCiphertext));
                    memset(blockPlaintext, 0, sizeof(blockPlaintext));

                    memcpy_s(blockPlaintext, sizeof(blockPlaintext), filePlaintext, len);


                    // align to aes block size
                    if ((len % AES_BLOCK_SIZE) != 0) len = AES_BLOCK_SIZE * ((len >> 4) + 1);

                    if (G_EDATA_TYPE == ReadonlyIcvAndCrypto)
                    {
                        uint8_t ivMask[sizeof(psse_header::file_iv)]; // calculate IV of current block
                        memset(ivMask, 0, sizeof(ivMask));
                        memcpy_s(ivMask, sizeof(ivMask), &G_CURRENT_BLOCK, sizeof(G_CURRENT_BLOCK));

                        for (int i = 0; i < sizeof(ivMask); i++) {
                            ivMask[i] ^= G_PLAINTEXT_IV[i];
                        }

                        // encrypt this block
                        aes_cbc_encrypt(edataContext.gameKey, KEY_SIZE, ivMask, sizeof(ivMask), blockPlaintext, len, blockCiphertext);
                    }
                    else if (G_EDATA_TYPE == ReadonlyIcv || G_EDATA_TYPE == ReadonlyWholeSignature) {
                        memcpy_s(blockCiphertext, sizeof(blockCiphertext), blockPlaintext, len);
                    }

                    if (G_EDATA_TYPE != ReadonlyWholeSignature) { // calculate hmac
                        memcpy_s(&blockCiphertext[len], sizeof(blockCiphertext) - len, &G_CURRENT_BLOCK, sizeof(&G_CURRENT_BLOCK));
                        memset(vitaHmac, 0, sizeof(vitaHmac));
                        sha256_hmac(edataContext.vitaHmacKey, KEY_SIZE, blockCiphertext, len + KEY_SIZE, vitaHmac);
                        memset(androidHmac, 0, sizeof(androidHmac));
                        sha256_hmac(edataContext.androidHmacKey, KEY_SIZE, blockCiphertext, len + KEY_SIZE, androidHmac);
                    }

                    res = create_block_signature(vitaHmac, androidHmac, blockCiphertext, &len);
                    if (res == SCE_OK) {
                        res = read_from_plaintext_file(filePlaintext, &len);
                        if (res == SCE_OK) {
                            if (len != 0) continue;
                        }
                    }

                    break;

                }
            }
        }
    }
    close_edata_encrypted_file();
    write_whole_file_signature_and_hmac();
    return res;
}
