#ifndef _PSM_ENCRYPTOR_HKAPP
#define _PSM_ENCRYPTOR_HKAPP 1

typedef struct aes_enc_section_hkapp {
	unsigned char vitaHmacKey[0x10];
	unsigned char unk[0x10];
	unsigned char androidHmacKey[0x10];
	unsigned char unk1[0x30];
	unsigned char game_key[0x10];
	unsigned char unk2[0x110];
} aes_enc_section_hkapp;

typedef struct rsa_enc_section_hkapp {
	unsigned char unk[0xC0];
	unsigned char aes_section_key[0x10];
	unsigned char aes_section_iv[0x10];
	unsigned char unk2[0x20];
} rsa_enc_section_hkapp;

typedef struct PsmHkapp {
	const char magic[0x4];
	int version;
	uint64_t flags;
	uint64_t unk1;
	uint64_t unk2;
	uint64_t unk4;
	char app_name[0x58];
	aes_enc_section_hkapp aes_section;
	rsa_enc_section_hkapp rsa_section;
	char unk6[0x100];
} PsmHkapp;

#endif