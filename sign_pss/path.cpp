#include <string>

std::string  switchSlashesToPsmStyle(const std::string path) {
	std::string pathCpy = path;
	for (int i = 0; i < pathCpy.length(); i++) if (pathCpy[i] == '\\') pathCpy[i] = '/';
	return pathCpy;
}

std::string getExtension(const std::string path) {
	int lastDot = 0;
	for (int i = 0; i < path.length(); i++) {
		if (path[i] == '.') lastDot = i;
	}
	return path.substr(lastDot);
}

std::string getFilename(const std::string path) {
	int lastSlash = 0;
	for (int i = 0; i < path.length(); i++) {
		if (path[i] == '/' || path[i] == '\\') lastSlash = i + 1;
	}
	return path.substr(lastSlash);
}