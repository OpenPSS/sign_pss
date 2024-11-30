#ifndef _PSM_ENCRYPTOR_H
#define _PSM_ENCRYPTOR_H 1

#include "PsmEdata.hpp"
#include "PsmHkapp.hpp"

#ifdef __cplusplus
extern "C" {
#endif
	__declspec(dllexport) ScePsmEdataStatus  scePsmEdataEncrypt(const char* infile, const char* outfile, const char* installPath, ScePsmEdataType type, uint8_t* devPkcs12, size_t devPkcs12Size, PsmHkapp* hostKdbg, size_t hostKdbgSize);
	__declspec(dllexport) ScePsmEdataStatus  scePsmGetVersion(char* build_version, char* build_date);

#ifdef __cplusplus
}
#endif


#endif