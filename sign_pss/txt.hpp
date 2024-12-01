#ifndef _TXT_H
#define _TXT_H 1

void hex2bin(unsigned char* v, unsigned char* s, std::size_t n);
void printBuffer(const char* header, unsigned char* buffer, std::size_t bufferLen);

#endif