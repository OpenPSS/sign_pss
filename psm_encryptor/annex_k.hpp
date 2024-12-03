#ifndef _ANNEX_K_H
#define _ANNEX_K_H 1

#include <cstddef>
#include <cstring>

#ifndef _WIN32
#include <ctype.h>

#define MIN(a,b) (a) <= (b) ? (a) : (b)

#define sprintf_s snprintf

static inline void strncpy_s(char *strDest, std::size_t numberOfElements, const char *strSource, std::size_t count)
{
    std::size_t min_len = MIN(numberOfElements, count);
    strlcpy(strDest, strSource, min_len);
}

static inline void memcpy_s(void *dest, std::size_t destsz, const void *src, std::size_t count)
{
    std::size_t min_len = MIN(destsz, count);
    memcpy(dest, src, min_len);
}

static inline int fopen_s(FILE** pFile, const char *filename, const char *mode)
{
    if(!pFile)
    {
        return -1;
    }

    FILE* fd = fopen(filename, mode);

    if (!fd)
    {
        return -1;
    }

    *pFile = fd;
    return 0;
}

static inline void _strlwr_s(char *str, std::size_t numberOfElements)
{
    for(std::size_t i = 0; str[i] && i < numberOfElements; i++)
    {
        str[i] = tolower(str[i]);
    }
}

#endif  /* _WIN32 */

#endif /* _PLATFORM_H */