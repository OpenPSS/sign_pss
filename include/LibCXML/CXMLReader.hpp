#ifndef LIB_CXML_READER_H
#define LIB_CXML_READER_H 1
#include <string>
#include <fstream>
#include <filesystem>
#include <memory>

#include "CXMLFile.hpp"
#include "CXMLStream.hpp"
#include <memory>

namespace LibCXML {
	class CXMLReader {
	private: 
		bool checkMagicNumber(const char* magic);
		CXMLStream& readTable(CxmlTableDeclaration dec);
		std::fstream cxmlFile;
		CxmlFileHeader cxmlHeader;
	public:

		std::unique_ptr<CXMLStream> TreeTable = nullptr;
		std::unique_ptr<CXMLStream> IdTable = nullptr;
		std::unique_ptr<CXMLStream> HashIdTable = nullptr;
		std::unique_ptr<CXMLStream> StringTable = nullptr;
		std::unique_ptr<CXMLStream> WStringTable = nullptr;
		std::unique_ptr<CXMLStream> HashTable = nullptr;
		std::unique_ptr<CXMLStream> IntArrayTable = nullptr;
		std::unique_ptr<CXMLStream> FloatArrayTable = nullptr;
		std::unique_ptr<CXMLStream> FileTable = nullptr;

		CXMLReader(const std::string& cxmlFilePath, const char* magic);
		~CXMLReader();
	};

}

#endif