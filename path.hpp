#ifndef _PATH_H
#define _PATH_H

#include <string>

std::string switchSlashesToPsmStyle(const std::string path);
std::string getExtension(const std::string path);
std::string getFilename(const std::string path);

#endif