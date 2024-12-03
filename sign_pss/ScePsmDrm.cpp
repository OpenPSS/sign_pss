typedef struct IUnknown IUnknown;
#include <openssl/rand.h>
#include <cstring>
#include <string>
#include <fstream>

#include "ScePsmDrm.hpp"
#include "annex_k.hpp"

#ifndef _WIN32
#include <byteswap.h>
#define _byteswap_ulong bswap_32
#endif

bool CreateFakeLicense(std::string licenseFolder, std::string contentId, uint8_t* gameKey, uint8_t* vitaHmacKey, uint8_t* androidHmacKey) {

	// create psmdrm license
	ScePsmDrmLicense license;
	memset(&license, 0, sizeof(ScePsmDrmLicense));

	license.unk1 = _byteswap_ulong(1);
	license.account_id = 0x0123456789ABCDEFLL;
	strncpy_s(license.content_id, sizeof(license.content_id), contentId.c_str(), contentId.length());

	// generate keyset
	RAND_bytes((uint8_t*)&license.keyset, sizeof(ScePsmDrmKeySet));
	memcpy(license.keyset.hmac_key, vitaHmacKey, 0x10);
	memcpy(license.keyset.key, gameKey, 0x10);

	// write licenses to license folder ...
	std::fstream fakeRifVita(licenseFolder + "/FAKE.RIF", std::ios::out | std::ios::trunc | std::ios::binary);
	fakeRifVita.write((char*)&license, sizeof(ScePsmDrmLicense));
	fakeRifVita.close();

	memcpy(license.keyset.hmac_key, androidHmacKey, 0x10);
	std::fstream fakeRifAndroid(licenseFolder + "/FAKE.RIF_ANDROID", std::ios::out | std::ios::trunc | std::ios::binary);
	fakeRifAndroid.write((char*)&license, sizeof(ScePsmDrmLicense));
	fakeRifAndroid.close();

	return true;
}