#include "ScePsmDrm.hpp"
#include "ScePsmEdata.hpp"

#include <vector>
#include <string>
#include <cstring>
#include <fstream>
#include <iostream>

#include "io.hpp"
#include "path.hpp"
#include "txt.hpp"
#include "annex_k.hpp"
#include "appinfo.hpp"

#ifndef _WIN32
#include "strings.h"
#define _stricmp strcasecmp
#endif

bool doEncrypt(std::string path, bool unity) {
	std::string filename = getFilename(path);
	std::string extension = getExtension(path);

	std::string extAllowlist[]{ ".exe", ".cgx", ".dll" };
	std::string filenameAllowlist[]{ "unity_builtin_extra" };

	std::string filenameDenylist[]{ "edata.list", "app.info", "app.cfg", "psse.list" };
	std::string extDenylist[]{ ".mdb" };

	for (std::string encExtension : extAllowlist) {
		if (_stricmp(encExtension.c_str(), extension.c_str()) == 0) return true;
	}

	if (unity) { // only encrypt untiy_builtin_extra if its a unity game
		for (std::string encWhitelist : filenameAllowlist) {
			if (_stricmp(encWhitelist.c_str(), filename.c_str()) == 0) return true;
		}
	}

	for (std::string blacklistedExt : extDenylist) {
		if (_stricmp(blacklistedExt.c_str(), extension.c_str()) == 0) return false;
	}

	for (std::string blacklistedFile : filenameDenylist) {
		if (_stricmp(blacklistedFile.c_str(), filename.c_str()) == 0) return false;
	}


	return !unity;
}


int recursiveEncryptOrCopy(std::string srcFolder, std::string dstFolder, std::string installFolder, std::vector<std::string>& files,
	std::string contentId, uint8_t* gameKey, uint8_t* vitaHmacKey, uint8_t* androidHmacKey, bool unity) {

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
			if (doEncrypt(srcInPath, unity)) {
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
			recursiveEncryptOrCopy(srcInPath, destOutPath, installPath, files, contentId, gameKey, vitaHmacKey, androidHmacKey, unity);
		}


	} while (readDirectory(handle, nextFile, &isDirectory));


	return true;
}

bool createContentIdFile(std::string systemFolder, std::string contentId) {
	char contentIdBytes[0x30];
	memset(contentIdBytes, 0, sizeof(contentIdBytes));
	strncpy_s(contentIdBytes, sizeof(contentIdBytes), contentId.c_str(), contentId.length());

	std::fstream contentIdFile(systemFolder + "/content_id", std::ios::out | std::ios::trunc | std::ios::binary);
	contentIdFile.write(contentIdBytes, sizeof(contentIdBytes));
	contentIdFile.close();

	return true;
}

bool signApp(std::string inDir, std::string outDir, std::string contentId, uint8_t* gameKey, uint8_t* vitaHmacKey, uint8_t* androidHmacKey) {
	std::string appPrefix = "/Application";
	std::string licensePrefix = "/License";
	std::string systemPrefix = "/System";

	std::string appInfoFile = inDir + appPrefix + "/app.info";

	if (!fileExist(appInfoFile)) {
		std::cerr << appInfoFile << " could not be found.." << std::endl;
		std::cerr << "please make sure the input folder is the one containing /Application/app.info." << std::endl;
		return false;
	}

	AppInfo applicationInfo = AppInfo(appInfoFile);
	
	if (!applicationInfo.Validate()) {
		std::cerr << "The application may have issues promoting on PSVita, please check your app.info is correct!" << std::endl;
	}
	else {
		std::cout << "app.info read successfully;" << std::endl;

		std::cout << std::endl;
		std::cout << "\tPSM version:  " << stripNonAscii(applicationInfo.TargetRuntimeVersion) << std::endl;
		std::cout << "\tProject name: " << stripNonAscii(applicationInfo.ProjectName) << std::endl;
		std::cout << "\tName:         " << stripNonAscii(applicationInfo.Names.at(0).Name) << std::endl;
		std::cout << "\tShort name:   " << stripNonAscii(applicationInfo.ShortNames.at(0).Name) << std::endl;
		std::cout << "\tAuthor:       " << stripNonAscii(applicationInfo.Author) << std::endl;
		std::cout << "\tWebsite:      " << stripNonAscii(applicationInfo.Website) << std::endl;
		std::cout << "\tIs Unity:     " << (applicationInfo.IsPsmUnity() ? "YES" : "NO") << std::endl;
		std::cout << std::endl;
	}

	std::string inAppFolder = inDir + appPrefix;
	std::string applicationFolder = outDir + "/RO"+ appPrefix;
	std::string licenseFolder = outDir + "/RO" + licensePrefix;
	std::string systemFolder = outDir + "/RW" + systemPrefix;

	createDirectories(applicationFolder);
	createDirectories(licenseFolder);
	createDirectories(systemFolder);

	std::vector<std::string> edataList;	
	std::cout << "Signing files ... " << std::endl;

	if(!recursiveEncryptOrCopy(inAppFolder, applicationFolder, appPrefix, edataList, contentId, gameKey, vitaHmacKey, androidHmacKey, applicationInfo.IsPsmUnity())) return false;

	std::cout << "Writing ... /Application/edata.list" << std::endl;
	std::ofstream psseStream(applicationFolder + "/edata.list", std::ios::out | std::ios::trunc);
	for (std::string edataFile : edataList) {
		std::string line = edataFile.substr(appPrefix.length() + 1);
		if (line.empty()) continue;

		psseStream << line << std::endl;
	}
	psseStream.close();

	std::cout << "Signing ... /Application/edata.list -> /Application/psse.list" << std::endl;
	if (scePsmEdataEncryptForRetail(std::string(applicationFolder + "/edata.list").c_str(), std::string(applicationFolder + "/psse.list").c_str(), "/Application/psse.list", ReadonlyIcvAndCrypto, contentId.c_str(), gameKey, vitaHmacKey, androidHmacKey) != SCE_OK) return false;

	if (!CreateFakeLicense(licenseFolder, contentId, gameKey, vitaHmacKey, androidHmacKey)) return false;

	std::cout << "Writing ... /System/content_id" << std::endl;
	if (!createContentIdFile(systemFolder, contentId)) return false;

	if (applicationInfo.IsPsmUnity()) {
		std::cout << std::endl;

		std::cout << "NOTE: you will need to copy the \"PlayStation(r)Mobile Runtime Package for Unity\" v\"" << stripNonAscii(applicationInfo.UnityApplicationVer) << "\" (PCSI00010)" << std::endl;
		std::cout << "into the \"" << outDir << "/runtime\" folder of this signed PSM Application!" << std::endl;
		std::cout << "(you can find it within offical retail games)" << std::endl;

		std::cout << std::endl;

	}


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
		std::cout << "content_id - the content id to use for PSSE signature, eg; UM0999-NPNA99999_00-0000000000000000" << std::endl;
		std::cout << "game_key - game specific key used to encrypt the data, found in RIF" << std::endl;
		std::cout << "vita_hmac_key - HMAC key used for verifying psm file integrity on VITA, found in vita psm RIF" << std::endl;
		std::cout << "android_hmac_key - HMAC key used for verifying psm file integrity on ANDROID, found in android psm RIF" << std::endl;
		std::cout << std::endl;
		std::cout << "Options within [square brackets] are optional, if not included a random value will be used for it instead." << std::endl;
		std::cout << "also; a NoPsmDrm FAKE.RIF will be generated for the content_id specified." << std::endl;
		return -1;
	}

	std::cout << std::endl;
	std::cout << std::endl;
	std::cout << std::endl;

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
