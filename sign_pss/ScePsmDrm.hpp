#ifndef _PSMDRM_H
#define _PSMDRM_H 1

#include <cstdint>

typedef struct ScePsmDrmKeySet {
	uint8_t hmac_key[0x20];
	uint8_t key[0x10];
	uint8_t signature[0x1D0];
} ScePsmDrmKeySet;

typedef struct ScePsmDrmLicense {
	char magic[0x8];
	uint32_t unk1;
	uint32_t unk2;
	uint64_t account_id;
	uint32_t unk3;
	uint32_t unk4;
	uint64_t start_time;
	uint64_t expiration_time;
	uint8_t activation_checksum[0x20];
	char content_id[0x30];
	uint8_t unk5[0x80];
	ScePsmDrmKeySet keyset;
	uint8_t rsa_signature[0x100];
} ScePsmDrmLicense;

#endif