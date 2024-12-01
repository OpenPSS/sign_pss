#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <cstddef>
#include <cstring>

#include "OpenSSL.hpp"
#include "PsmEdata.hpp"
#include "PsmHkapp.hpp"
#include "PsmKeys.hpp"
#include "psm_encryptor.hpp"
#include "HexKey.hpp"
#include "annex_k.hpp"


#ifdef _PSM_SIGNTOOL_BUILD 

// since we have the code now.. can easily add our own to build for the retail PSM runtime <3

ScePsmEdataStatus scePsmEdataEncryptForRetail(const char* infile, const char* outfile,
                                      const char* installPath, ScePsmEdataType type, 
                                      const char* contentId, const unsigned char* gameKey,
                                      const unsigned char* vitaHmacKey, const unsigned char* androidHmacKey) {

    char gameContentId[PSM_CONTENT_ID_SIZE];
    char installPathLowercase[0x400];

    uint8_t psmGameKey[KEY_SIZE];
    uint8_t psmVitaHmacKey[KEY_SIZE];
    uint8_t psmAndroidHmacKey[KEY_SIZE];
    uint8_t psmFilenameHmacKey[KEY_SIZE];

    uint8_t psseHeaderKey[KEY_SIZE];
    uint8_t psseHeaderIv[KEY_SIZE];
    
    get_ascii_key(SCE_PSM_HMAC_KEY, sizeof(psmFilenameHmacKey), psmFilenameHmacKey);
    get_ascii_key((const char*)gameKey, sizeof(psmGameKey), psmGameKey);
    get_ascii_key((const char*)vitaHmacKey, sizeof(psmVitaHmacKey), psmVitaHmacKey);
    get_ascii_key((const char*)androidHmacKey, sizeof(psmAndroidHmacKey), psmAndroidHmacKey);

    if (!infile || !outfile || !installPath)
        return SCE_PSM_EDATA_ERROR_INVAL;

    if (!contentId, !gameKey, !vitaHmacKey, !androidHmacKey)
        return SCE_PSM_EDATA_ERROR_INVAL;

    ScePsmEdataStatus res = get_psse_header_keys(psseHeaderKey, psseHeaderIv);

    sprintf_s(installPathLowercase, sizeof(installPathLowercase), "%s", installPath);
    _strlwr_s(installPathLowercase, sizeof(installPathLowercase));

    strncpy_s(gameContentId, sizeof(gameContentId), contentId, sizeof(gameContentId)); // copy the game content id specifed

    if (res == SCE_OK) {
        PsmEdataCtx edataContext;

        edataContext.infile = infile;
        edataContext.contentId = gameContentId;
        edataContext.outFile = outfile;
        edataContext.installPath = installPathLowercase;
        edataContext.type = type;
        edataContext.gameKey = psmGameKey;
        edataContext.vitaHmacKey = psmVitaHmacKey;
        edataContext.androidHmacKey = psmAndroidHmacKey;
        edataContext.filenameKey = psmFilenameHmacKey;
        edataContext.psseHeaderKey = psseHeaderKey;
        edataContext.psseHeaderIv = psseHeaderIv;

        if (type > ReadonlyIcvAndCrypto)
        {
            unsigned int isInvalidType = type - ReadonlyIcvAndScramble;
            if (!isInvalidType)
                return SCE_PSM_EDATA_ERROR_NOT_IMPLEMENTED;
            if ((isInvalidType - 1) > 1)
                return SCE_PSM_EDATA_ERROR_INVAL;
        }
        else if (type != ReadonlyIcvAndCrypto) {
            if (type == WritableIcvAndCrypto || type == WritableIcvUnknown || type == WritableIcv || type == WritableWholeSignature)
                return SCE_PSM_EDATA_ERROR_NOT_IMPLEMENTED;
            return SCE_PSM_EDATA_ERROR_INVAL;
        }

        return do_edata_encryption(edataContext);
    }

}


#endif

ScePsmEdataStatus  scePsmEdataEncrypt(const char* infile, const char* outfile, const char* installPath, ScePsmEdataType type, uint8_t* devPkcs12, std::size_t devPkcs12Size, PsmHkapp* hostKdbg, std::size_t hostKdbgSize) {
    char contentId[PSM_CONTENT_ID_SIZE];
    char installPathLowercase[0x400];
    
    uint8_t gameKey[KEY_SIZE];
    uint8_t vitaHmacKey[KEY_SIZE];
    uint8_t androidHmacKey[KEY_SIZE];
    uint8_t filenameHmacKey[KEY_SIZE];

    uint8_t psseHeaderKey[KEY_SIZE];
    uint8_t psseHeaderIv[KEY_SIZE];

    if (!infile || !outfile || !installPath)
        return SCE_PSM_EDATA_ERROR_INVAL;
    
    ScePsmEdataStatus res = get_content_id(contentId);
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
                    unsigned int isInvalidType = type - ReadonlyIcvAndScramble;
                    if (!isInvalidType)
                        return SCE_PSM_EDATA_ERROR_NOT_IMPLEMENTED;
                    if ((isInvalidType - 1) > 1)
                        return SCE_PSM_EDATA_ERROR_INVAL;
                }
                else if (type != ReadonlyIcvAndCrypto) {
                    if (type == WritableIcvAndCrypto || type == WritableIcvUnknown || type == WritableIcv || type == WritableWholeSignature)
                        return SCE_PSM_EDATA_ERROR_NOT_IMPLEMENTED;
                    return SCE_PSM_EDATA_ERROR_INVAL;
                }

                return do_edata_encryption(edataContext);
            }
        }
    }
    return res;
}

ScePsmEdataStatus scePsmGetVersion(char* buildVersion, char* buildDate)
{
    if (!buildVersion || !buildVersion)
        return SCE_PSM_EDATA_ERROR_INVAL;

    sprintf_s(buildVersion, 0x20, "%s", "1.1.0.2");
    sprintf_s(buildDate, 0x40, "%s %s", "Feb  4 2014", "14:02:08");

    return SCE_OK;
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