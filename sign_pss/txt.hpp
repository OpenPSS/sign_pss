#ifndef _TXT_H
#define _TXT_H 1
#include <string>

void hex2bin(unsigned char* v, unsigned char* s, std::size_t n);
void printBuffer(const char* header, unsigned char* buffer, std::size_t bufferLen);
std::string stripNonAscii(const std::string in);

#endif