#ifndef _PSM_ENCRYPTOR_EDATA
#define _PSM_ENCRYPTOR_EDATA 1
#include <cstdint>

typedef enum ScePsmEdataType
{
	Invalid = 0,
	ReadonlyIcv = 3,
	ReadonlyIcvAndCrypto = 1,
	ReadonlyIcvAndScramble = 2,
	ReadonlyWholeSignature = 4,
	WritableIcv = -2147483645,
	WritableIcvAndCrypto = -2147483647,
	WritableIcvAndScramble = -2139095038,
	WritableWholeSignature = -2147483644
} ScePsmEdataType;

typedef enum PsmEdataStatus
{
	SCE_OK = 0,
	SCE_PSM_EDATA_ERROR_ALREADY_INITIALIZED = -2138111168,
	SCE_PSM_EDATA_ERROR_BADF = -2138111223,
	SCE_PSM_EDATA_ERROR_CRYPTO = -2138111069,
	SCE_PSM_EDATA_ERROR_ECONTENTID = -2138111209,
	SCE_PSM_EDATA_ERROR_EDATA_TO_LARGE = -2138111062,
	SCE_PSM_EDATA_ERROR_EFWRITE = -2138111049,
	SCE_PSM_EDATA_ERROR_EGENRANDOM = -2138111048,
	SCE_PSM_EDATA_ERROR_EISDIR = -2138111211,
	SCE_PSM_EDATA_ERROR_FATAL = -2138111072,
	SCE_PSM_EDATA_ERROR_FFORMAT = -2138111185,
	SCE_PSM_EDATA_ERROR_FILE_NOT_OPENED = -2138111064,
	SCE_PSM_EDATA_ERROR_FINDSEED = -2138111070,
	SCE_PSM_EDATA_ERROR_FOPEN = -2138111054,
	SCE_PSM_EDATA_ERROR_FOPENED = -2138111053,
	SCE_PSM_EDATA_ERROR_FREAD = -2138111050,
	SCE_PSM_EDATA_ERROR_FSEEK = -2138111052,
	SCE_PSM_EDATA_ERROR_FSTAT = -2138111051,
	SCE_PSM_EDATA_ERROR_HEADER_SIGNATULRE = -2138111066,
	SCE_PSM_EDATA_ERROR_INVAL = -2138111210,
	SCE_PSM_EDATA_ERROR_INVALID_LICENSE = -2138111024,
	SCE_PSM_EDATA_ERROR_KEY_FILE_OPEN = -2138111056,
	SCE_PSM_EDATA_ERROR_KEY_FILE_READ = -2138111055,
	SCE_PSM_EDATA_ERROR_MFILE = -2138111208,
	SCE_PSM_EDATA_ERROR_NOENT = -2138111230,
	SCE_PSM_EDATA_ERROR_NOT_ACTIVATED = -2138111023,
	SCE_PSM_EDATA_ERROR_NOT_IMPLEMENTED = -2138111071,
	SCE_PSM_EDATA_ERROR_NOT_INITIALIZED = -2138111167,
	SCE_PSM_EDATA_ERROR_OPENSSL = -2138111068,
	SCE_PSM_EDATA_ERROR_OVERFLOW = -2138111093,
	SCE_PSM_EDATA_ERROR_PLAIN_TO_LARGE = -2138111063,
	SCE_PSM_EDATA_ERROR_THREAD = -2138111038,
	SCE_PSM_EDATA_ERROR_THREAD_MALLOC = -2138111039,
	SCE_PSM_EDATA_ERROR_THREAD_MODULE = -2138111040,
	SCE_PSM_EDATA_ERROR_VERIFY_ICV = -2138111067,
	SCE_PSM_EDATA_ERROR_WHOLE_SIGNATULRE = -2138111065
} PsmEdataStatus;

typedef struct psse_header {
	char magic[0x4];
	int version;
	uint64_t file_size;
	int psse_type;
	char content_id[0x2C];
	char file_md5[0x10];
	char install_path_hmac[0x20];
	char file_iv[0x10];
	char header_signature[0x100];
	char whole_file_signature[0x100];
} psse_header;

typedef struct psse_block_signature {
	char vita_hmac[0x200];
	char android_hmac[0x200];
} psse_block_signature;

typedef struct PsmEdataCtx {
	const char* infile;
	const char* contentId;
	const char* outfile;
	const char* installPath;
	const void* gameKey;
	const void* vita_hmac_key;
	const void* android_hmac_key;
	const void* filename_key;
	const void* psse_header_key;
	const void* psse_header_iv;
	ScePsmEdataType type;
} PsmEdataCtx;

#endif