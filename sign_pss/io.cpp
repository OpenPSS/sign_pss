#include <cstdio>
#include <cstdint>
#include <string>
#include "io.hpp"

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN 1
#include <Windows.h>

typedef struct {
	HANDLE handle;
	WIN32_FIND_DATAA findData;
} directoryHandle;


void createDirectory(std::string path) {
	CreateDirectoryA(path.c_str(), NULL);
}

void* openDirectory(std::string path) {
	directoryHandle* handle = new directoryHandle();
	memset(handle, 0, sizeof(directoryHandle));

	if (path[path.length() - 1] != '/' || path[path.length() - 1] != '\\') path += "/";
	if (path[path.length() - 1] != '*') path += "*";

	handle->handle = FindFirstFileA(path.c_str(), &handle->findData);

	return handle;
}

bool readDirectory(void* dfd, std::string& outputFilename, bool* isDirectory) {
	directoryHandle* handle = (directoryHandle*)dfd;
	if (handle == NULL) return false;
	if (handle->handle == NULL) return false;

	outputFilename = std::string(handle->findData.cFileName, strlen(handle->findData.cFileName));
	if (outputFilename.empty()) return false;

	if (outputFilename[0] != '.') {
		*isDirectory = (((handle->findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) || ((handle->findData.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0));

		if (FindNextFileA(handle->handle, &handle->findData) == TRUE) return true;
		return false;
	}
	else {
		if (FindNextFileA(handle->handle, &handle->findData) == FALSE) return false;
		return readDirectory(handle, outputFilename, isDirectory);
	}
}

void closeDirectory(void* dfd) {
	directoryHandle* handle = (directoryHandle*)dfd;

	if (handle == NULL) return;
	if (handle->handle == NULL) return;

	FindClose(handle->handle);
	delete handle;
}
#else
// TODO: implement linux
#endif


void copyFile(std::string src, std::string dst) {

	uint8_t buffer[0x8000];

	FILE* fd;
	FILE* wfd;

	fopen_s(&fd, src.c_str(), "rb");
	fopen_s(&wfd, dst.c_str(), "wb");

	size_t rd = 0;

	do {
		rd = fread(buffer, 1, sizeof(buffer), fd);
		fwrite(buffer, 1, rd, wfd);
	} while (rd != 0);

	fclose(fd);
	fclose(wfd);

}
void createDirectories(const std::string path) {
	std::string partialPath;

	for (int i = 0; i < path.length(); i++) {
		if (path[i] == '/' || path[i] == '\\') {
			partialPath = path.substr(0, i);
			createDirectory(partialPath);
		}
	}
	createDirectory(path);
}

bool fileExist(const std::string path) {
	FILE* fd = NULL;
	
	fopen_s(&fd, path.c_str(), "rb");
	if (fd == NULL) return false;
	fclose(fd);

	return true;
}