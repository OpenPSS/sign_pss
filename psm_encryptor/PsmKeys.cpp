#include "PsmKeys.hpp"

const char* SCE_PSM_PKCS12_PASSWORD = "password";
const char* SCE_PSM_FIXED_IV        = "000102030405060708090A0B0C0D0E0F";
const char* SCE_PSM_HMAC_KEY        = "DEADBEEF04290429DEADBEEF04290429";
const char* SCE_PSM_KEY		        = "DEADBEEFDEADBEEFDEADBEEFDEADBEEF";
const char* SCE_PSM_PSICV_KEY       = "CEACBEEFCEACBEEFCEACBEEFCEACBEEF";
const char* SCE_PSM_OPICV_KEY       = "BEABBEEFBEABBEEFBEABBEEFBEABBEEF";

#ifdef _PSM_RELEASE
const char* SCE_PSM_FIXED_KEY = "4E298B40F531F469D21F75B133C307BE";
#else
const char* SCE_PSM_FIXED_KEY = "00112233445566778899AABBCCDDEEFF";
#endif

const uint8_t SCE_PSM_HEADER_SIGNATURE_PUB_KEY[] = {
  0x30, 0x82, 0x01, 0x0a, 0x02, 0x82, 0x01, 0x01, 0x00, 0xa9, 0x8f, 0x6b,
  0x27, 0xf5, 0xaf, 0xf0, 0xf9, 0x6c, 0x74, 0x11, 0xa3, 0x37, 0xdf, 0xcf,
  0x72, 0x3c, 0x37, 0xbe, 0xf6, 0xff, 0x65, 0x52, 0xb8, 0xe5, 0xa3, 0xee,
  0xe3, 0x67, 0x2c, 0xf0, 0x36, 0x6e, 0xa0, 0x44, 0x2b, 0x79, 0x13, 0x01,
  0x8c, 0x73, 0x55, 0xc0, 0xf2, 0x33, 0x6d, 0xe4, 0x96, 0xdc, 0xad, 0xe8,
  0xbf, 0x5a, 0x32, 0xd1, 0xdb, 0x25, 0x70, 0x5d, 0x5a, 0x9a, 0x11, 0xc0,
  0x6f, 0xff, 0x68, 0x01, 0x77, 0x6b, 0xff, 0x87, 0x1f, 0xdd, 0xdc, 0x4e,
  0xa4, 0xca, 0xf4, 0x98, 0x86, 0xe0, 0x2d, 0x48, 0x35, 0xb3, 0xdc, 0xc9,
  0x67, 0x44, 0x57, 0xe4, 0xe6, 0x67, 0x44, 0xcb, 0x99, 0x71, 0x55, 0x27,
  0x1c, 0x21, 0x1e, 0x2f, 0xae, 0x0e, 0xce, 0xa5, 0xfa, 0xbd, 0x91, 0x71,
  0x97, 0x66, 0xc4, 0x88, 0x86, 0x00, 0x72, 0xe8, 0x1c, 0xcc, 0x7b, 0x5d,
  0xfe, 0xa0, 0x90, 0x7d, 0x25, 0xe6, 0x0c, 0xcb, 0x28, 0x50, 0x0d, 0x3f,
  0xdc, 0x9c, 0xc2, 0x44, 0xdb, 0xba, 0xed, 0x7a, 0x41, 0xfd, 0xa5, 0x71,
  0xc2, 0x7d, 0x87, 0xe9, 0x2b, 0x17, 0xe3, 0x4b, 0x02, 0x89, 0x32, 0x9e,
  0xb0, 0xfe, 0xfe, 0xd4, 0x68, 0x2f, 0x16, 0x79, 0xd8, 0x9f, 0xf0, 0x0d,
  0x2a, 0x78, 0xf7, 0x8b, 0x8a, 0x05, 0xa9, 0xb4, 0xd7, 0x30, 0x6e, 0x99,
  0x2a, 0xae, 0x7b, 0x7a, 0x0e, 0x9a, 0xdd, 0xf4, 0xf4, 0xbc, 0x28, 0x6e,
  0x1e, 0x52, 0xa8, 0x0a, 0xb2, 0xdf, 0x31, 0x01, 0x2b, 0x18, 0xb9, 0x96,
  0x67, 0x04, 0x46, 0xf0, 0x7a, 0xf2, 0x30, 0x7a, 0x7f, 0xfc, 0xbc, 0x45,
  0xad, 0xb3, 0xb8, 0x15, 0xb6, 0x59, 0x53, 0x6a, 0x7a, 0xad, 0xa8, 0x13,
  0xfd, 0x30, 0x31, 0x56, 0xc7, 0x92, 0xe2, 0x81, 0x57, 0x00, 0x1d, 0xc7,
  0xbb, 0x9a, 0xf9, 0x3a, 0x59, 0xa6, 0x07, 0xe4, 0xf2, 0xee, 0x34, 0xf8,
  0x87, 0x02, 0x03, 0x01, 0x00, 0x01
};

const uint8_t SCE_PSM_HEADER_SIGNATURE_PRIV_KEY[] = {
  0x30, 0x82, 0x04, 0xa6, 0x02, 0x01, 0x00, 0x02, 0x82, 0x01, 0x01, 0x00,
  0xa9, 0x8f, 0x6b, 0x27, 0xf5, 0xaf, 0xf0, 0xf9, 0x6c, 0x74, 0x11, 0xa3,
  0x37, 0xdf, 0xcf, 0x72, 0x3c, 0x37, 0xbe, 0xf6, 0xff, 0x65, 0x52, 0xb8,
  0xe5, 0xa3, 0xee, 0xe3, 0x67, 0x2c, 0xf0, 0x36, 0x6e, 0xa0, 0x44, 0x2b,
  0x79, 0x13, 0x01, 0x8c, 0x73, 0x55, 0xc0, 0xf2, 0x33, 0x6d, 0xe4, 0x96,
  0xdc, 0xad, 0xe8, 0xbf, 0x5a, 0x32, 0xd1, 0xdb, 0x25, 0x70, 0x5d, 0x5a,
  0x9a, 0x11, 0xc0, 0x6f, 0xff, 0x68, 0x01, 0x77, 0x6b, 0xff, 0x87, 0x1f,
  0xdd, 0xdc, 0x4e, 0xa4, 0xca, 0xf4, 0x98, 0x86, 0xe0, 0x2d, 0x48, 0x35,
  0xb3, 0xdc, 0xc9, 0x67, 0x44, 0x57, 0xe4, 0xe6, 0x67, 0x44, 0xcb, 0x99,
  0x71, 0x55, 0x27, 0x1c, 0x21, 0x1e, 0x2f, 0xae, 0x0e, 0xce, 0xa5, 0xfa,
  0xbd, 0x91, 0x71, 0x97, 0x66, 0xc4, 0x88, 0x86, 0x00, 0x72, 0xe8, 0x1c,
  0xcc, 0x7b, 0x5d, 0xfe, 0xa0, 0x90, 0x7d, 0x25, 0xe6, 0x0c, 0xcb, 0x28,
  0x50, 0x0d, 0x3f, 0xdc, 0x9c, 0xc2, 0x44, 0xdb, 0xba, 0xed, 0x7a, 0x41,
  0xfd, 0xa5, 0x71, 0xc2, 0x7d, 0x87, 0xe9, 0x2b, 0x17, 0xe3, 0x4b, 0x02,
  0x89, 0x32, 0x9e, 0xb0, 0xfe, 0xfe, 0xd4, 0x68, 0x2f, 0x16, 0x79, 0xd8,
  0x9f, 0xf0, 0x0d, 0x2a, 0x78, 0xf7, 0x8b, 0x8a, 0x05, 0xa9, 0xb4, 0xd7,
  0x30, 0x6e, 0x99, 0x2a, 0xae, 0x7b, 0x7a, 0x0e, 0x9a, 0xdd, 0xf4, 0xf4,
  0xbc, 0x28, 0x6e, 0x1e, 0x52, 0xa8, 0x0a, 0xb2, 0xdf, 0x31, 0x01, 0x2b,
  0x18, 0xb9, 0x96, 0x67, 0x04, 0x46, 0xf0, 0x7a, 0xf2, 0x30, 0x7a, 0x7f,
  0xfc, 0xbc, 0x45, 0xad, 0xb3, 0xb8, 0x15, 0xb6, 0x59, 0x53, 0x6a, 0x7a,
  0xad, 0xa8, 0x13, 0xfd, 0x30, 0x31, 0x56, 0xc7, 0x92, 0xe2, 0x81, 0x57,
  0x00, 0x1d, 0xc7, 0xbb, 0x9a, 0xf9, 0x3a, 0x59, 0xa6, 0x07, 0xe4, 0xf2,
  0xee, 0x34, 0xf8, 0x87, 0x02, 0x03, 0x01, 0x00, 0x01, 0x02, 0x82, 0x01,
  0x01, 0x00, 0x97, 0x2f, 0x84, 0xc9, 0x1d, 0x7c, 0xe2, 0x2d, 0x53, 0xb1,
  0x6e, 0x64, 0x8d, 0x16, 0x67, 0x3e, 0xa1, 0x48, 0xc7, 0x62, 0x2e, 0xb8,
  0xe6, 0x78, 0x6c, 0x71, 0xae, 0x38, 0x5f, 0x2f, 0xa7, 0x83, 0xb1, 0x41,
  0xff, 0x66, 0x8f, 0xcf, 0x0d, 0x8b, 0x70, 0xef, 0x1e, 0x5a, 0x16, 0xd7,
  0x3e, 0x81, 0xf1, 0x84, 0xb3, 0x49, 0xa3, 0x20, 0x3b, 0x13, 0xde, 0x9f,
  0x00, 0xee, 0x1f, 0x00, 0x03, 0x09, 0x19, 0xbf, 0x5f, 0xc7, 0x5e, 0xa9,
  0x79, 0x8f, 0x45, 0x60, 0x01, 0x53, 0x58, 0x8f, 0x9d, 0x4c, 0x6d, 0xa8,
  0x92, 0x81, 0x27, 0xbd, 0x8e, 0x6b, 0x20, 0x7a, 0x0a, 0x64, 0x11, 0xe2,
  0x3a, 0x73, 0xb7, 0xa4, 0xc8, 0x79, 0x81, 0x62, 0x0b, 0xfb, 0x73, 0xc2,
  0x78, 0x26, 0x49, 0x4e, 0xdc, 0xec, 0xb5, 0x3a, 0x39, 0xcc, 0xd9, 0xab,
  0x9b, 0x20, 0xca, 0x86, 0x99, 0x79, 0xc7, 0x2a, 0xee, 0x1a, 0x1f, 0xfb,
  0xe2, 0x51, 0x81, 0x3e, 0x5a, 0x12, 0x45, 0xf6, 0x1f, 0x85, 0xe4, 0x55,
  0xcc, 0x5e, 0xa1, 0x77, 0x00, 0x5b, 0xe5, 0x58, 0x4f, 0x7b, 0x63, 0x52,
  0x12, 0x7a, 0x15, 0x91, 0x24, 0xe1, 0x56, 0x80, 0x15, 0xf7, 0xad, 0x50,
  0x48, 0xa7, 0xbf, 0x6a, 0xdb, 0xc9, 0x41, 0x57, 0xa6, 0xa3, 0xea, 0x02,
  0x39, 0xa7, 0x65, 0xaf, 0x69, 0x4c, 0xeb, 0x4b, 0x01, 0x41, 0x8e, 0x9c,
  0xe1, 0x10, 0x07, 0x5b, 0xe4, 0x33, 0xe2, 0x5a, 0x2a, 0x36, 0xcc, 0x20,
  0x41, 0x0e, 0xef, 0x1e, 0xe3, 0x47, 0xd4, 0x2b, 0xa3, 0xa7, 0x32, 0xfd,
  0xdd, 0x5c, 0xaf, 0x4d, 0x3b, 0x29, 0xe3, 0x61, 0x08, 0xa4, 0x0e, 0x94,
  0xb4, 0xca, 0xb8, 0xd4, 0x59, 0x83, 0x71, 0x86, 0x1d, 0x44, 0x2f, 0xc8,
  0xa0, 0x5d, 0x59, 0x7c, 0x02, 0x5d, 0xae, 0x45, 0x35, 0x70, 0x0d, 0xe1,
  0x0b, 0x24, 0x4e, 0x82, 0x48, 0x59, 0x02, 0x81, 0x81, 0x00, 0xd6, 0xf5,
  0x81, 0x31, 0x99, 0x04, 0x96, 0xf2, 0x3e, 0xd9, 0x77, 0x44, 0x62, 0xcc,
  0x8b, 0xf3, 0xdb, 0xd9, 0x5f, 0x11, 0xa6, 0xd5, 0x58, 0xd1, 0xe0, 0x83,
  0x64, 0x8a, 0x11, 0x35, 0x9e, 0x8d, 0xa8, 0x0e, 0x64, 0x3f, 0x17, 0x0a,
  0x87, 0xeb, 0x8f, 0x93, 0xab, 0xfb, 0xda, 0x78, 0x67, 0x3e, 0x02, 0xf1,
  0xd7, 0x6d, 0x6d, 0x9d, 0x29, 0x14, 0x62, 0x27, 0x64, 0x7b, 0xdb, 0x9b,
  0x52, 0x30, 0x41, 0x0f, 0x01, 0xc3, 0xa4, 0x61, 0x9d, 0xdf, 0x58, 0x34,
  0x2c, 0xd0, 0x7e, 0x50, 0x2b, 0x75, 0x3a, 0x4f, 0x58, 0x5f, 0x41, 0x0c,
  0xf6, 0x38, 0xc1, 0x27, 0x1c, 0x75, 0xa6, 0x47, 0xc7, 0xc5, 0x6b, 0x4e,
  0x77, 0xef, 0x06, 0x28, 0x3a, 0x7e, 0x6f, 0xd5, 0xec, 0x2e, 0x71, 0xde,
  0xf0, 0xf2, 0xcf, 0x9a, 0x48, 0x71, 0xab, 0x3b, 0x99, 0x1d, 0x83, 0x3b,
  0x5b, 0x31, 0x15, 0x00, 0x9d, 0x55, 0x02, 0x81, 0x81, 0x00, 0xc9, 0xee,
  0xf8, 0x47, 0x8b, 0x8f, 0xfb, 0x2e, 0xae, 0xd9, 0x8e, 0x28, 0xd8, 0x32,
  0xa9, 0x6d, 0x1e, 0x7d, 0xbc, 0xfe, 0xe8, 0x82, 0x6e, 0x68, 0x05, 0x35,
  0xfb, 0xff, 0x70, 0xd6, 0x6c, 0xa7, 0xf6, 0x46, 0xc0, 0xef, 0xf0, 0x62,
  0xdf, 0x27, 0x51, 0x20, 0x3e, 0xf9, 0xaa, 0x8b, 0x6d, 0x0e, 0xb2, 0x52,
  0xb3, 0xa8, 0xfb, 0x16, 0x73, 0x66, 0xea, 0xfd, 0x1f, 0xea, 0x06, 0x52,
  0x51, 0x0c, 0xe0, 0xdc, 0x2b, 0xc2, 0x20, 0x18, 0x92, 0x5d, 0xdf, 0x13,
  0x2a, 0xc6, 0x9c, 0x27, 0xfb, 0x7a, 0x29, 0x3e, 0xff, 0xf4, 0x5f, 0xe5,
  0xfc, 0x23, 0x64, 0xce, 0xc1, 0x50, 0xd6, 0x63, 0x60, 0x50, 0x7b, 0x3c,
  0x46, 0xeb, 0xa4, 0x6b, 0x57, 0x46, 0xef, 0x08, 0x95, 0x23, 0xde, 0x5c,
  0xf9, 0x51, 0xbb, 0xb8, 0x80, 0xb9, 0x05, 0x66, 0x8b, 0xfe, 0xb6, 0xbd,
  0x06, 0x6e, 0xc8, 0x76, 0x5e, 0x6b, 0x02, 0x81, 0x81, 0x00, 0xb4, 0xf8,
  0xd5, 0xfe, 0xf2, 0xab, 0x99, 0x85, 0x73, 0x02, 0x54, 0xd5, 0xff, 0x33,
  0xe4, 0x33, 0xb7, 0x08, 0xc7, 0x70, 0x2d, 0xfb, 0xfa, 0x1e, 0x20, 0x1d,
  0x9e, 0x9c, 0x5a, 0xa6, 0xc0, 0xc8, 0xd4, 0x0e, 0xe1, 0xb8, 0xf7, 0xe6,
  0x06, 0xce, 0x7b, 0xff, 0x40, 0x50, 0xf5, 0xfa, 0x5e, 0x39, 0x27, 0xf3,
  0x81, 0x82, 0x00, 0x41, 0xcb, 0x1e, 0xfd, 0x0f, 0xdb, 0x1a, 0x27, 0xa6,
  0x19, 0x48, 0xc4, 0xcd, 0x24, 0x98, 0x18, 0xa1, 0x92, 0x6f, 0x41, 0x6c,
  0x13, 0xba, 0xa8, 0x4d, 0x48, 0x79, 0x16, 0x51, 0x4c, 0xbe, 0x4d, 0x1e,
  0xe3, 0x80, 0x9e, 0xa5, 0x15, 0xe1, 0xba, 0xcf, 0x3d, 0xd1, 0xe8, 0x68,
  0x94, 0xb2, 0x68, 0x85, 0x9f, 0xd1, 0x68, 0xc8, 0x3a, 0x62, 0x53, 0xbd,
  0xf5, 0x2f, 0x07, 0x37, 0x05, 0xfc, 0xa4, 0xc3, 0xb5, 0x41, 0xd2, 0x85,
  0x3b, 0x5e, 0x14, 0x27, 0x83, 0x4d, 0x02, 0x81, 0x81, 0x00, 0x95, 0xb4,
  0x2e, 0x28, 0x8c, 0x54, 0xdf, 0xb8, 0xca, 0x33, 0xcb, 0x6a, 0x88, 0x6d,
  0x76, 0xa1, 0xc8, 0xfb, 0x1a, 0xc4, 0x38, 0x07, 0x8a, 0x66, 0x5f, 0x86,
  0x98, 0x1d, 0xd5, 0xbf, 0x81, 0xaa, 0x3b, 0xb0, 0x54, 0x95, 0x0d, 0x37,
  0x9f, 0x8c, 0x7c, 0x5e, 0x55, 0x91, 0xae, 0x57, 0xd3, 0x30, 0x14, 0x0f,
  0xaf, 0xd5, 0xd4, 0xdf, 0xde, 0x0a, 0x2c, 0xa8, 0x1f, 0xa2, 0xd5, 0xb0,
  0xed, 0x19, 0x89, 0x12, 0x70, 0xf6, 0x67, 0xe9, 0x0f, 0x89, 0xbc, 0x39,
  0x6f, 0x7a, 0xf2, 0x85, 0xc9, 0xaf, 0xd5, 0x28, 0x39, 0x85, 0x28, 0x1b,
  0x4e, 0x83, 0xc6, 0xd6, 0x69, 0x06, 0xcf, 0x09, 0xb9, 0x7b, 0xb1, 0x01,
  0x0c, 0xea, 0xe1, 0x68, 0x1a, 0xba, 0x21, 0xb7, 0xd1, 0x29, 0x58, 0x4e,
  0xc1, 0x1f, 0x50, 0xf6, 0x05, 0xa8, 0x25, 0x52, 0xd2, 0xf2, 0xb0, 0xf3,
  0x0d, 0xf3, 0xcf, 0x75, 0xc1, 0xa5, 0x02, 0x81, 0x81, 0x00, 0x90, 0xca,
  0x37, 0x5e, 0xbe, 0x04, 0x7c, 0x43, 0xeb, 0xa6, 0x5e, 0x8c, 0xba, 0x30,
  0x98, 0xde, 0x8e, 0x8e, 0xc7, 0x2e, 0x5d, 0x07, 0x15, 0x7d, 0xe8, 0xa0,
  0x51, 0x81, 0xb5, 0xd9, 0x99, 0x5d, 0x2b, 0x16, 0x91, 0x60, 0x63, 0x87,
  0x4d, 0x6b, 0xc0, 0xe4, 0xdf, 0xf4, 0x60, 0x60, 0x89, 0x58, 0x0b, 0x2c,
  0x50, 0x7a, 0x6e, 0x18, 0xe1, 0x85, 0x5f, 0x9b, 0x75, 0x49, 0xc4, 0xca,
  0xe1, 0xa2, 0xd1, 0x05, 0xae, 0x28, 0x1d, 0x57, 0x67, 0x95, 0xfd, 0x5b,
  0x73, 0x82, 0x63, 0x54, 0x97, 0x84, 0xb2, 0x51, 0xfa, 0x99, 0x99, 0x16,
  0x2b, 0x4f, 0xe7, 0x45, 0x2e, 0x39, 0xb0, 0x6d, 0x4e, 0x54, 0x70, 0xd9,
  0xd1, 0x0b, 0x4f, 0xf7, 0x2b, 0x16, 0xf1, 0x3e, 0xcb, 0x27, 0x97, 0xce,
  0xa7, 0xfd, 0x78, 0x9a, 0xbf, 0xf4, 0x4f, 0x77, 0xd3, 0xda, 0xfd, 0xec,
  0xe2, 0xaf, 0x1f, 0xe3, 0x15, 0xbf
};

const uint8_t SCE_PSM_WHOLE_SIGNATURE_PUB_KEY[] = {
  0x30, 0x82, 0x01, 0x0a, 0x02, 0x82, 0x01, 0x01, 0x00, 0xd4, 0x52, 0xc1,
  0x87, 0x52, 0xbd, 0xe6, 0x28, 0x9a, 0xce, 0xb8, 0x62, 0xad, 0x32, 0x14,
  0x53, 0x22, 0xc1, 0x3e, 0xec, 0x82, 0xf5, 0x67, 0x5e, 0x9d, 0xa9, 0x6b,
  0x51, 0xcc, 0xaa, 0x68, 0x48, 0x8f, 0x2b, 0x5e, 0x09, 0xe1, 0xc1, 0xde,
  0xfe, 0x7a, 0x27, 0xec, 0xb5, 0xea, 0xcf, 0x47, 0x3a, 0x9d, 0x15, 0x17,
  0x1f, 0x43, 0xee, 0x32, 0xda, 0x03, 0xe7, 0xba, 0x07, 0x18, 0x2b, 0x40,
  0x85, 0x40, 0xc3, 0x7c, 0xd8, 0xaa, 0x35, 0x7f, 0x4d, 0xcd, 0x12, 0x29,
  0x5a, 0xd3, 0x90, 0x1d, 0x6a, 0x0d, 0x6d, 0x41, 0x66, 0x5b, 0xa7, 0x08,
  0x4b, 0x1a, 0x98, 0xdf, 0xe1, 0x5a, 0x1f, 0x0b, 0x3a, 0x2a, 0x4b, 0x4d,
  0x0a, 0x00, 0xa1, 0xcd, 0x8b, 0xa5, 0xb0, 0x9e, 0x80, 0xbc, 0x4e, 0x2c,
  0x58, 0x83, 0x57, 0xc0, 0xf2, 0xe2, 0x85, 0xc0, 0x50, 0x55, 0x6d, 0xc9,
  0x71, 0xa4, 0x3f, 0xea, 0x4c, 0x05, 0x6c, 0xf2, 0xdf, 0xd8, 0xbb, 0x2e,
  0xe9, 0x75, 0xf6, 0x7f, 0x76, 0x87, 0x8e, 0x1f, 0xb0, 0x1e, 0x7a, 0x23,
  0xf8, 0x7f, 0xd5, 0x73, 0x28, 0x64, 0xdd, 0x62, 0xb2, 0xc3, 0xff, 0xd4,
  0xbc, 0xf1, 0x84, 0x92, 0x3a, 0x37, 0x06, 0x81, 0x94, 0x67, 0x72, 0x3a,
  0xa5, 0x08, 0xfc, 0x53, 0xe8, 0x0f, 0x6e, 0x5a, 0x57, 0xcf, 0x3e, 0x7b,
  0x1b, 0xb0, 0xa3, 0x98, 0x80, 0x37, 0x65, 0x6c, 0xbb, 0x2f, 0xc7, 0x0b,
  0xdf, 0x34, 0x4b, 0x56, 0x83, 0xe4, 0x94, 0x3d, 0x08, 0xc6, 0x09, 0xd4,
  0x4d, 0xfd, 0xae, 0x90, 0xc5, 0x30, 0x0c, 0x5c, 0xde, 0x7c, 0x2d, 0x89,
  0x03, 0x5b, 0x20, 0xfc, 0x18, 0x9f, 0x9d, 0xbc, 0x34, 0xbe, 0xb6, 0x47,
  0x8d, 0x6b, 0x32, 0x18, 0x3f, 0xb8, 0x86, 0x13, 0x3b, 0x04, 0xc1, 0x96,
  0x2e, 0xee, 0xda, 0x7f, 0xfd, 0x47, 0xdb, 0x80, 0x65, 0x5f, 0x4c, 0xde,
  0x0f, 0x02, 0x03, 0x01, 0x00, 0x01
};

const uint8_t SCE_PSM_WHOLE_SIGNATURE_PRIV_KEY[] = {
  0x30, 0x82, 0x04, 0xa4, 0x02, 0x01, 0x00, 0x02, 0x82, 0x01, 0x01, 0x00,
  0xd4, 0x52, 0xc1, 0x87, 0x52, 0xbd, 0xe6, 0x28, 0x9a, 0xce, 0xb8, 0x62,
  0xad, 0x32, 0x14, 0x53, 0x22, 0xc1, 0x3e, 0xec, 0x82, 0xf5, 0x67, 0x5e,
  0x9d, 0xa9, 0x6b, 0x51, 0xcc, 0xaa, 0x68, 0x48, 0x8f, 0x2b, 0x5e, 0x09,
  0xe1, 0xc1, 0xde, 0xfe, 0x7a, 0x27, 0xec, 0xb5, 0xea, 0xcf, 0x47, 0x3a,
  0x9d, 0x15, 0x17, 0x1f, 0x43, 0xee, 0x32, 0xda, 0x03, 0xe7, 0xba, 0x07,
  0x18, 0x2b, 0x40, 0x85, 0x40, 0xc3, 0x7c, 0xd8, 0xaa, 0x35, 0x7f, 0x4d,
  0xcd, 0x12, 0x29, 0x5a, 0xd3, 0x90, 0x1d, 0x6a, 0x0d, 0x6d, 0x41, 0x66,
  0x5b, 0xa7, 0x08, 0x4b, 0x1a, 0x98, 0xdf, 0xe1, 0x5a, 0x1f, 0x0b, 0x3a,
  0x2a, 0x4b, 0x4d, 0x0a, 0x00, 0xa1, 0xcd, 0x8b, 0xa5, 0xb0, 0x9e, 0x80,
  0xbc, 0x4e, 0x2c, 0x58, 0x83, 0x57, 0xc0, 0xf2, 0xe2, 0x85, 0xc0, 0x50,
  0x55, 0x6d, 0xc9, 0x71, 0xa4, 0x3f, 0xea, 0x4c, 0x05, 0x6c, 0xf2, 0xdf,
  0xd8, 0xbb, 0x2e, 0xe9, 0x75, 0xf6, 0x7f, 0x76, 0x87, 0x8e, 0x1f, 0xb0,
  0x1e, 0x7a, 0x23, 0xf8, 0x7f, 0xd5, 0x73, 0x28, 0x64, 0xdd, 0x62, 0xb2,
  0xc3, 0xff, 0xd4, 0xbc, 0xf1, 0x84, 0x92, 0x3a, 0x37, 0x06, 0x81, 0x94,
  0x67, 0x72, 0x3a, 0xa5, 0x08, 0xfc, 0x53, 0xe8, 0x0f, 0x6e, 0x5a, 0x57,
  0xcf, 0x3e, 0x7b, 0x1b, 0xb0, 0xa3, 0x98, 0x80, 0x37, 0x65, 0x6c, 0xbb,
  0x2f, 0xc7, 0x0b, 0xdf, 0x34, 0x4b, 0x56, 0x83, 0xe4, 0x94, 0x3d, 0x08,
  0xc6, 0x09, 0xd4, 0x4d, 0xfd, 0xae, 0x90, 0xc5, 0x30, 0x0c, 0x5c, 0xde,
  0x7c, 0x2d, 0x89, 0x03, 0x5b, 0x20, 0xfc, 0x18, 0x9f, 0x9d, 0xbc, 0x34,
  0xbe, 0xb6, 0x47, 0x8d, 0x6b, 0x32, 0x18, 0x3f, 0xb8, 0x86, 0x13, 0x3b,
  0x04, 0xc1, 0x96, 0x2e, 0xee, 0xda, 0x7f, 0xfd, 0x47, 0xdb, 0x80, 0x65,
  0x5f, 0x4c, 0xde, 0x0f, 0x02, 0x03, 0x01, 0x00, 0x01, 0x02, 0x82, 0x01,
  0x00, 0x4a, 0x70, 0x8d, 0x3b, 0x65, 0x8e, 0x00, 0xa0, 0xa1, 0xcd, 0xf2,
  0x25, 0x5e, 0x75, 0x9d, 0x5c, 0x9c, 0x65, 0xc6, 0x2a, 0xe3, 0xab, 0x28,
  0x47, 0xaa, 0xdd, 0x18, 0x2c, 0x40, 0xa6, 0x4a, 0x13, 0x8e, 0x66, 0x74,
  0xfc, 0xdf, 0xf2, 0xb9, 0xbc, 0xdc, 0x95, 0x1c, 0xcf, 0x96, 0xf8, 0x7f,
  0x0f, 0x94, 0xbd, 0x2d, 0x33, 0x1f, 0xfc, 0xe6, 0x45, 0x3b, 0x73, 0x45,
  0xec, 0x70, 0xd3, 0xd1, 0x36, 0x26, 0xc3, 0xa3, 0x04, 0xcf, 0x80, 0x1c,
  0x16, 0xe9, 0xdc, 0x01, 0x35, 0xbf, 0xd0, 0xda, 0x0f, 0x31, 0x8f, 0xe9,
  0x8a, 0xfa, 0x7d, 0x30, 0x52, 0x2c, 0x8c, 0x06, 0x8a, 0x1a, 0xaf, 0xa1,
  0x9f, 0x0d, 0xef, 0x02, 0x9e, 0x8c, 0x24, 0x2e, 0x4d, 0x54, 0x94, 0xfc,
  0xad, 0x43, 0xd7, 0xe0, 0x82, 0x53, 0xe2, 0x33, 0x5a, 0xb4, 0x82, 0x92,
  0x2f, 0x58, 0x14, 0x3a, 0xb9, 0x26, 0x0d, 0xe6, 0x95, 0x86, 0xef, 0x69,
  0xcb, 0xec, 0xc8, 0x49, 0x9e, 0x91, 0x60, 0xde, 0x15, 0xc7, 0xec, 0xd0,
  0x19, 0x68, 0x3f, 0x6f, 0x61, 0xe1, 0x99, 0x90, 0xad, 0x38, 0x72, 0x6a,
  0x81, 0x4a, 0xb8, 0x04, 0x42, 0xe8, 0x4a, 0xbe, 0x36, 0xa3, 0x64, 0x72,
  0x57, 0x1c, 0x76, 0x9b, 0xc1, 0x74, 0x15, 0xcf, 0x96, 0x61, 0x36, 0x4c,
  0x31, 0x4e, 0x14, 0x73, 0xf1, 0xb6, 0xdf, 0xb2, 0x7c, 0x51, 0x7d, 0x8a,
  0x13, 0x3d, 0x6b, 0x6a, 0x59, 0x44, 0x2d, 0x3d, 0x99, 0xfb, 0x7b, 0xd3,
  0xf1, 0x7a, 0x07, 0x92, 0x9e, 0xb4, 0x11, 0x01, 0x82, 0xf8, 0x12, 0x3b,
  0x72, 0x4f, 0x75, 0x04, 0x44, 0x61, 0x29, 0x5a, 0xa3, 0x3f, 0xa8, 0x75,
  0xbf, 0x72, 0xd4, 0xf5, 0x4b, 0x15, 0x11, 0xbe, 0xdf, 0x6e, 0x9d, 0xcb,
  0xc0, 0x2c, 0x72, 0x05, 0x5a, 0xc5, 0x77, 0x9a, 0x4c, 0xdd, 0x3a, 0x8c,
  0xc1, 0x8d, 0x46, 0x71, 0x21, 0x02, 0x81, 0x81, 0x00, 0xf4, 0xfb, 0xe3,
  0x49, 0x5f, 0x9b, 0x77, 0xe7, 0x8e, 0x80, 0x3f, 0xa1, 0x82, 0x45, 0x89,
  0x75, 0x2d, 0x8c, 0x3c, 0xfa, 0xcd, 0xef, 0x06, 0xe4, 0xe0, 0x62, 0x19,
  0xf4, 0xba, 0xcb, 0x58, 0x5c, 0x09, 0x8c, 0xae, 0x03, 0x45, 0x43, 0xb1,
  0x64, 0x78, 0x8c, 0x61, 0xa7, 0xc8, 0x76, 0xe1, 0x99, 0x6b, 0x49, 0xdc,
  0x53, 0x96, 0x8b, 0x36, 0xa8, 0xa3, 0xda, 0xad, 0x44, 0x42, 0x6a, 0x59,
  0xfe, 0x1e, 0xdc, 0xe2, 0x3e, 0xca, 0x02, 0xc3, 0x1b, 0xa7, 0xda, 0x3d,
  0xe7, 0x0c, 0xe6, 0xd4, 0x47, 0x15, 0x54, 0xb5, 0x2e, 0x4c, 0x2b, 0x4a,
  0xd1, 0xe1, 0xa7, 0x4e, 0x62, 0xb4, 0xb5, 0x6f, 0xcf, 0xa2, 0xce, 0xe8,
  0xef, 0xa9, 0x94, 0x2f, 0xab, 0xd4, 0xd6, 0x58, 0x68, 0x90, 0x10, 0x46,
  0xd0, 0xde, 0xc9, 0x73, 0x69, 0x70, 0x1b, 0x36, 0xf6, 0x56, 0xa5, 0x81,
  0xf2, 0x6c, 0xb1, 0x6d, 0x7f, 0x02, 0x81, 0x81, 0x00, 0xdd, 0xde, 0xe5,
  0xc5, 0x09, 0xd9, 0xc0, 0x9f, 0xcd, 0x76, 0xb9, 0x28, 0x1a, 0x6f, 0x4d,
  0xb5, 0x0f, 0x61, 0x88, 0xa1, 0x24, 0x5d, 0x19, 0x92, 0xc6, 0xfd, 0x5c,
  0xd2, 0x9c, 0xa9, 0x0c, 0x9b, 0x6a, 0x5f, 0x8c, 0x0c, 0x0d, 0xbf, 0x68,
  0x29, 0xcb, 0xdf, 0x31, 0x93, 0x43, 0x95, 0x0f, 0x3b, 0xf2, 0xa6, 0x52,
  0x0e, 0x66, 0xdf, 0xa7, 0xb8, 0x10, 0x19, 0xb6, 0xad, 0xe1, 0x3d, 0x4d,
  0xb6, 0x9e, 0xe8, 0x23, 0x2d, 0xdf, 0xb8, 0xa1, 0x0d, 0x99, 0x7b, 0x77,
  0x1f, 0x84, 0x78, 0x4d, 0xcd, 0xa1, 0xdc, 0x8a, 0xc1, 0xef, 0x49, 0x31,
  0xa4, 0x04, 0xc9, 0xfe, 0xc2, 0x6a, 0x59, 0x02, 0xb9, 0x78, 0x37, 0x1b,
  0x1c, 0x9c, 0x21, 0x91, 0x78, 0x01, 0x76, 0xdb, 0x83, 0x9f, 0xcb, 0x87,
  0x61, 0xbb, 0xf7, 0x55, 0xfa, 0xff, 0xba, 0xa4, 0x4e, 0x0a, 0xb8, 0x73,
  0x69, 0x82, 0xaa, 0xf7, 0x71, 0x02, 0x81, 0x81, 0x00, 0x91, 0x8d, 0xde,
  0xfa, 0xc7, 0x3d, 0x3d, 0xbe, 0x6c, 0x62, 0x32, 0x6c, 0x29, 0x54, 0x5b,
  0x59, 0x2d, 0x98, 0xb6, 0xda, 0x64, 0xe4, 0x71, 0x7a, 0x26, 0xfe, 0xe2,
  0x61, 0x0f, 0x62, 0xa5, 0xba, 0xf9, 0x49, 0x86, 0x52, 0x17, 0x23, 0x23,
  0x10, 0x88, 0xb7, 0x0f, 0x86, 0x7a, 0x8a, 0x77, 0x7b, 0x89, 0xcd, 0x36,
  0x84, 0xcb, 0x5b, 0x27, 0x3c, 0x87, 0x2d, 0xf3, 0xe8, 0x2c, 0x75, 0xb7,
  0xc6, 0x4e, 0x5b, 0xfa, 0x68, 0x47, 0xe9, 0xe0, 0x36, 0x5c, 0x42, 0x44,
  0xa9, 0x34, 0x77, 0x29, 0x04, 0x9a, 0xdd, 0xdb, 0x50, 0x08, 0x9d, 0x68,
  0x34, 0xcf, 0x17, 0x72, 0x71, 0x1e, 0xe0, 0xf5, 0xef, 0xad, 0xd1, 0xb5,
  0x80, 0x3f, 0x86, 0xf5, 0xd3, 0xe7, 0xfe, 0xfa, 0x44, 0x15, 0xe4, 0x35,
  0xce, 0xff, 0xaf, 0x3d, 0x4d, 0x15, 0xf8, 0x75, 0x6d, 0x63, 0x09, 0xae,
  0xed, 0x74, 0x3a, 0xee, 0xcd, 0x02, 0x81, 0x80, 0x40, 0x12, 0x94, 0xac,
  0x38, 0x52, 0x08, 0x0c, 0x9e, 0x1b, 0x41, 0x11, 0x51, 0xc0, 0xfe, 0xe1,
  0xe0, 0xd5, 0x3b, 0xcd, 0xbd, 0x60, 0x9d, 0x78, 0x03, 0xbb, 0x3b, 0x49,
  0x1f, 0x30, 0xba, 0x91, 0x4f, 0x40, 0xd4, 0x82, 0xce, 0x9d, 0x8e, 0x09,
  0x33, 0xf4, 0xfa, 0xae, 0x1a, 0x80, 0x3b, 0x6c, 0x06, 0x80, 0xfd, 0x85,
  0x67, 0x34, 0x03, 0x8d, 0x66, 0x28, 0xe6, 0xd6, 0x84, 0x0b, 0x5e, 0x1b,
  0xf4, 0xfb, 0xf8, 0xdc, 0xd0, 0x94, 0xd2, 0xfd, 0xc8, 0x6b, 0x1d, 0x55,
  0x9e, 0xbd, 0xd7, 0x4a, 0x21, 0x0a, 0x3d, 0x90, 0x0f, 0xf8, 0x45, 0x3b,
  0xa6, 0x9e, 0x66, 0xd1, 0xe2, 0x40, 0x5e, 0x47, 0x0d, 0x6e, 0x6c, 0x87,
  0xf0, 0x96, 0xc9, 0x19, 0xac, 0xe2, 0x94, 0x36, 0x08, 0xb9, 0x90, 0x19,
  0x2b, 0x5d, 0x1c, 0x19, 0x66, 0x2c, 0x92, 0x32, 0x6f, 0x6a, 0x20, 0xfa,
  0x41, 0x5f, 0xfa, 0x21, 0x02, 0x81, 0x81, 0x00, 0xe6, 0x3d, 0x19, 0x98,
  0x6e, 0xaf, 0x6f, 0x6d, 0x6d, 0xa1, 0x3c, 0xd7, 0xbd, 0xfc, 0xae, 0xb2,
  0x96, 0x8a, 0xed, 0x9c, 0x1a, 0xcf, 0xf6, 0x23, 0x07, 0x3d, 0xf5, 0xb0,
  0xae, 0x0f, 0x3b, 0x17, 0x81, 0x8f, 0x13, 0xb7, 0x7c, 0x16, 0x8c, 0xa0,
  0x41, 0x22, 0xb5, 0x09, 0xc5, 0x70, 0x5c, 0x85, 0xd9, 0xc4, 0x6a, 0x7b,
  0x1f, 0x80, 0xe6, 0x45, 0x6a, 0xcd, 0x91, 0x1b, 0x13, 0x10, 0x76, 0x55,
  0x54, 0x7f, 0xb7, 0xde, 0xae, 0x10, 0xf3, 0x8c, 0xc5, 0xa1, 0xfd, 0x2a,
  0x9a, 0xe8, 0x5b, 0xe1, 0xfc, 0xfa, 0xbf, 0x09, 0xb4, 0x9c, 0xa9, 0xe4,
  0xdf, 0x70, 0x79, 0x88, 0xe2, 0x00, 0x30, 0x89, 0x18, 0xc9, 0x29, 0xf7,
  0x43, 0x3c, 0xbf, 0x98, 0x87, 0x0b, 0xa7, 0x05, 0x19, 0x22, 0xdd, 0x00,
  0x25, 0x50, 0x19, 0x9d, 0xe4, 0x1c, 0x81, 0xeb, 0x11, 0x6d, 0x1e, 0x6f,
  0x90, 0x0d, 0xa6, 0xa9
};

int get_edata_header_private_key(const uint8_t** der_key, size_t* der_len) {
	*der_key = SCE_PSM_HEADER_SIGNATURE_PRIV_KEY;
	*der_len = sizeof(SCE_PSM_HEADER_SIGNATURE_PRIV_KEY);

	return 0;
}
int get_edata_whole_file_private_key(const uint8_t** der_key, size_t* der_len) {
	*der_key = SCE_PSM_WHOLE_SIGNATURE_PRIV_KEY;
	*der_len = sizeof(SCE_PSM_WHOLE_SIGNATURE_PRIV_KEY);

	return 0;
}

int get_edata_header_public_key(const uint8_t** der_key, size_t* der_len) {
	*der_key = SCE_PSM_HEADER_SIGNATURE_PUB_KEY;
	*der_len = sizeof(SCE_PSM_HEADER_SIGNATURE_PUB_KEY);

	return 0;
}
int get_edata_whole_file_public_key(const uint8_t** der_key, size_t* der_len) {
	*der_key = SCE_PSM_WHOLE_SIGNATURE_PUB_KEY;
	*der_len = sizeof(SCE_PSM_WHOLE_SIGNATURE_PUB_KEY);

	return 0;
}