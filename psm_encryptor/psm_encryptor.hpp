#ifndef _PSM_ENCRYPTOR_H
#define _PSM_ENCRYPTOR_H 1

extern "C" {
#include "PsmEdata.hpp"
#include "PsmHkapp.hpp"

__declspec(dllexport) PsmEdataStatus  scePsmEdataEncrypt(const char* infile, const char* outfile, const char* installPath, ScePsmEdataType type, uint8_t* devPkcs12, size_t devPkcs12Size, PsmHkapp* hostKdbg, size_t hostKdbgSize);

}


#endif