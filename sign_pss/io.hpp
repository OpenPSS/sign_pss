#ifndef _IO_H
#define _IO_H 1

#include <string>

void create_directory(std::string path);
void* open_directory(std::string path);
bool read_directory(void* dfd, std::string& outputFilename, bool* isDirectory);
void close_directory(void* dfd);

bool fileExist(std::string file);
void copyFile(std::string src, std::string dst);
void createDirectories(const std::string path);

#endif