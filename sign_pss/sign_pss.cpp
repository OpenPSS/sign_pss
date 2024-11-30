typedef struct IUnknown IUnknown;
#include <openssl/rand.h>

#include <vector>
#include <string>
#include <fstream>
#include <iostream>

#include "io.hpp"
#include "path.hpp"
#include "txt.hpp"

#include "ScePsmEdata.hpp"
#include "ScePsmDrm.hpp"

bool doEncrypt(std::string path) {
	std::string filename = getFilename(path);
	std::string extension = getExtension(path);

	std::string mustEncryptExt[]{ ".exe", ".cgx", ".dll" };
	std::string encryptBlacklist[]{ "edata.list", "app.info", "app.cfg", "psse.list" };
	std::string extBlacklist[]{ ".mdb" };

	for (std::string encExtension : mustEncryptExt) {
		if (_stricmp(encExtension.c_str(), extension.c_str()) == 0) return true;
	}

	for (std::string blacklistedExt : extBlacklist) {
		if (_stricmp(blacklistedExt.c_str(), extension.c_str()) == 0) return false;
	}

	for (std::string blacklistedFile : encryptBlacklist) {
		if (_stricmp(blacklistedFile.c_str(), filename.c_str()) == 0) return false;
	}


	return true;
}


int recursiveEncryptOrCopy(std::string srcFolder, std::string dstFolder, std::string installFolder, std::vector<std::string>& files,
	std::string contentId, uint8_t* gameKey, uint8_t* vitaHmacKey, uint8_t* androidHmacKey) {

	createDirectories(dstFolder.c_str());

	void* handle = openDirectory(srcFolder.c_str());

	std::string nextFile;
	bool isDirectory;
	readDirectory(handle, nextFile, &isDirectory);

	std::string dstFolderName = getFilename(dstFolder);

	do {
		switchSlashesToPsmStyle(nextFile);

		std::string installPath = installFolder + "/" + nextFile;
		std::string srcInPath = srcFolder + "/" + nextFile;
		std::string destOutPath = dstFolder + "/" + nextFile;


		if (!isDirectory) {
			if (doEncrypt(srcInPath)) {
				files.push_back(installPath);
				std::cout << "Signing ... " << installPath << std::endl;
				if (scePsmEdataEncryptForRetail(srcInPath.c_str(), destOutPath.c_str(), installPath.c_str(), ReadonlyIcvAndCrypto, contentId.c_str(), gameKey, vitaHmacKey, androidHmacKey) != SCE_OK) return false;
			}
			else {
				std::cout << "Copying ... " << installPath << std::endl;
				copyFile(srcInPath, destOutPath);
			}
		}
		else {
			recursiveEncryptOrCopy(srcInPath, destOutPath, installPath, files, contentId, gameKey, vitaHmacKey, androidHmacKey);
		}


	} while (readDirectory(handle, nextFile, &isDirectory));


	return true;
}

bool signApp(std::string inDir, std::string outDir, std::string contentId, uint8_t* gameKey, uint8_t* vitaHmacKey, uint8_t* androidHmacKey) {

	if (!fileExist(inDir + "/Application/app.info")) {
		std::cout << "/Application/app.info could not be found within " << inDir << std::endl;
		std::cout << "please make sure the input folder is the one containing /Application/app.info." << std::endl;
		return false;
	}

	std::string appPrefix = "/Application";
	std::string licensePrefix = "/License";
	std::string systemPrefix = "/System";


	std::string inAppFolder = inDir + appPrefix;
	std::string applicationFolder = outDir + "/RO"+ appPrefix;
	std::string licenseFolder = outDir + "/RO" + licensePrefix;
	std::string systemFolder = outDir + "/RW" + systemPrefix;

	createDirectories(applicationFolder);
	createDirectories(licenseFolder);
	createDirectories(systemFolder);

	std::vector<std::string> edataList;
	
	std::cout << "Signing files ... " << std::endl;

	if(!recursiveEncryptOrCopy(inAppFolder, applicationFolder, appPrefix, edataList, contentId, gameKey, vitaHmacKey, androidHmacKey)) return false;

	std::cout << "Creating edata.list & psse.list" << std::endl;

	// create edata.list & psse.list
	std::ofstream psseStream(applicationFolder + "/edata.list", std::ios::out | std::ios::trunc);
	for (std::string edataFile : edataList) {
		std::string line = edataFile.substr(appPrefix.length() + 1);
		if (line.empty()) continue;

		psseStream << line << std::endl;
	}
	psseStream.close();

	if (scePsmEdataEncryptForRetail(std::string(applicationFolder + "/edata.list").c_str(), std::string(applicationFolder + "/psse.list").c_str(), "/Application/psse.list", ReadonlyIcvAndCrypto, contentId.c_str(), gameKey, vitaHmacKey, androidHmacKey) != SCE_OK) return false;

	std::cout << "Creating fake licenses" << std::endl;

	// create psmdrm license
	ScePsmDrmLicense license;
	memset(&license, 0, sizeof(ScePsmDrmLicense));

	license.unk1 = _byteswap_ulong(1);
	license.account_id = 0x0123456789ABCDEFLL;
	strncpy_s(license.content_id, contentId.c_str(), sizeof(license.content_id));

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

	std::cout << "Creating content_id file" << std::endl;
	
	char contentIdBytes[0x30];
	memset(contentIdBytes, 0, sizeof(contentIdBytes));
	strncpy_s(contentIdBytes, contentId.c_str(), sizeof(contentIdBytes));

	std::fstream contentIdFile(systemFolder + "/content_id", std::ios::out | std::ios::trunc | std::ios::binary);
	contentIdFile.write(contentIdBytes, sizeof(contentIdBytes));
	contentIdFile.close();


	return true;
}

int main(int argc, char** argv)
{	
	std::string exeName = "sign_pss";
	if(argc > 1) exeName = getFilename(argv[0]);

	std::cout << exeName << " by OpenPSS" << std::endl;
	std::cout << "Developed by Li of The Crystal System" << std::endl;
	
	if (argc < 4) {
		std::cout << "Usage: " << exeName << " <game_folder> <output_folder> <content_id> [game_key] [vita_hmac_key] [android_hmac_key]" << std::endl;
		std::cout << std::endl;
		std::cout << "game_folder - the folder containing the plaintext PSM game files (/Application, /System, etc)" << std::endl;
		std::cout << "content_id - the content id to use for PSSE signature, eg; UM0000-NPNA99999_00-0000000000000000" << std::endl;
		std::cout << "game_key - game specific key used to encrypt the data, found in RIF" << std::endl;
		std::cout << "vita_hmac_key - HMAC key used for verifying psm file integrity on VITA, found in vita psm RIF" << std::endl;
		std::cout << "android_hmac_key - HMAC key used for verifying psm file integrity on ANDROID, found in android psm RIF" << std::endl;
		std::cout << std::endl;
		std::cout << "Options within [square brackets] are optional, if not included a random value will be used for it instead." << std::endl;
		std::cout << "also; a NoPsmDrm FAKE.RIF will be generated for the content_id specified." << std::endl;
		return -1;
	}

	std::string appFolder = std::string(argv[1]);
	std::string signedAppFolder = std::string(argv[2]);
	std::string contentId = std::string(argv[3]);


	// read or generate gamekey & vita/android hmac keys.
	uint8_t gameKey[0x10];
	if (argc < 5) RAND_bytes(gameKey, sizeof(gameKey));
	else hex2bin(gameKey, (unsigned char*)argv[4], sizeof(gameKey));
	
	uint8_t vitaHmac[0x10];
	if (argc < 6) RAND_bytes(vitaHmac, sizeof(vitaHmac));
	else hex2bin(vitaHmac, (unsigned char*)argv[5], sizeof(vitaHmac));

	uint8_t androidHmac[0x10];
	if (argc < 7) RAND_bytes(androidHmac, sizeof(androidHmac));
	else hex2bin(androidHmac, (unsigned char*)argv[6], sizeof(androidHmac));

	printBuffer("Using GAME_KEY:     ", gameKey, sizeof(gameKey));
	printBuffer("Using VITA_HMAC:    ", vitaHmac, sizeof(vitaHmac));
	printBuffer("Using ANDROID_HMAC: ", androidHmac, sizeof(androidHmac));

	// actually sign the application
	if (signApp(appFolder, signedAppFolder, contentId, gameKey, vitaHmac, androidHmac)) {
		std::cout << "Application signing success!" << std::endl;
		return 0;
	}
	else {
		std::cerr << "Application signing failed." << std::endl;
	}
	return -1;
}
