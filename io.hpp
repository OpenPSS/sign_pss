#ifndef _IO_H
#define _IO_H 1

#include <string>

void createDirectory(std::string path);
void* openDirectory(std::string path);
bool readDirectory(void* dfd, std::string& outputFilename, bool* isDirectory);
void closeDirectory(void* dfd);

bool fileExist(std::string file);
void copyFile(std::string src, std::string dst);
void createDirectories(const std::string path);

#endif