#include <cstdint>
#include <cstdio>
#include "HexKey.hpp"

uint64_t hex2bin(const char* hexEncoded, int dataSize, uint8_t* data)
{
    char* hexStr; // r9
    unsigned int i; // ebx
    int iii; // r11d
    uint64_t ii; // r10
    char c; // cl
    char subtract_by; // cl

    hexStr = (char*)hexEncoded;
    if (!data || !hexEncoded)
        return 0xFFFFFFFFLL;
    i = 0;
    iii = 0;
    ii = 0LL;
    if (*hexEncoded)
    {
        do
        {
            c = *hexStr;
            if (*hexStr < '0' || c > '9')
            {
                if (c < 'a' || c > 'f')
                {
                    if (c < 'A' || c > 'F')
                        subtract_by = 0;
                    else
                        subtract_by = c - 0x37;
                }
                else
                {
                    subtract_by = c - 0x57;
                }
            }
            else
            {
                subtract_by = c - 0x30;
            }
            if (((iii >> 0x1F) ^ iii & 1) == iii >> 0x1F)
            {
                data[ii] = 0x10 * subtract_by;
            }
            else
            {
                data[ii++] += subtract_by;
                ++i;
                if (ii >= dataSize)
                    return i;
            }
            ++hexStr;
            ++iii;
        } while (*hexStr);
    }
    return i;
}
