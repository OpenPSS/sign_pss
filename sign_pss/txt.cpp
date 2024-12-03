#include <cstring>
#include <cstdint>
#include <cstdlib>
#include <cstdio>
#include <string>

void hex2bin(unsigned char* v, unsigned char* s, std::size_t n) {
	int i;
	char _t[3];
	unsigned char* p = s;

	memset(v, 0, n);
	std::size_t dstrlen = strlen((const char*)s) / 2;
	if (dstrlen > n) dstrlen = n;

	for (i = 0; i < dstrlen; ++i) {
		memcpy(_t, p, 2);
		_t[2] = '\0';
		v[i] = (int)strtol(_t, NULL, 16);
		p += 2;

	}
}

void printBuffer(const char* header, unsigned char* buffer, std::size_t bufferLen) {
	printf("%s", header);
	for (std::size_t i = 0; i < bufferLen; i++) printf("%02X", buffer[i]);
	printf("\n");
}

std::string stripNonAscii(const std::string in) {
	std::string s = "";
	for (int i = 0; i < in.length(); i++) {
		if (in[i] >= 0x20 && in[i] < 0x7f) {
			s += in[i];
		}
	}
	return s;
}