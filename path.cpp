#include <string>
#include <iostream>
#include <cstdint>

std::string  switchSlashesToPsmStyle(const std::string path) {
	std::string pathCpy = path;
	for (std::size_t i = 0; i < pathCpy.length(); i++) if (pathCpy[i] == '\\') pathCpy[i] = '/';
	return pathCpy;
}

std::string getExtension(const std::string path) {
	std::size_t lastDot = 0;
	for (std::size_t i = 0; i < path.length(); i++) {
		if (path[i] == '.') lastDot = i;
	}
	return path.substr(lastDot);
}

std::string getFilename(const std::string path) {
	std::size_t lastSlash = 0;
	for (std::size_t i = 0; i < path.length(); i++) {
		if (path[i] == '/' || path[i] == '\\') lastSlash = i + 1;
	}
	return path.substr(lastSlash);
}