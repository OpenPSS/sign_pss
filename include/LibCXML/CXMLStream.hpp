#ifndef LIB_CXML_STREAM_H
#define LIB_CXML_STREAM_H 1
#include "CXMLFile.hpp"
#include <cstdint>
#include <string>
#include <cstdint>
#include <vector>
namespace LibCXML {
	class CXMLStream {
	private:
		std::vector<uint8_t> buffer;
		size_t pos = 0;
	public:
		CXMLStream() = default;
		~CXMLStream() = default;

		CXMLStream(std::fstream& fd, CxmlTableDeclaration dec);
		CXMLStream(uint8_t* srcbuffer, size_t size);
		CXMLStream(std::fstream& fd, size_t offset, size_t size);

		void Open(uint8_t* srcbuffer, size_t size);
		void Open(std::fstream& fd, size_t offset, size_t size);

		size_t Length();
		size_t Read(void* buf, size_t sz);
		int ReadInt();
		float ReadFloat();
		double ReadDouble();
		char* ReadStr();
		wchar_t* ReadWStr();
		char* ReadStrLen(size_t sz);
		wchar_t* ReadWStrLen(size_t sz);
		void Seek(size_t pos);
		bool Empty();
	};
}

#endif
