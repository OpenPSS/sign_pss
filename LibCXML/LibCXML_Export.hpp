#ifndef LIB_CXML_EXP_H
#define LIB_CXML_EXP_H 1

#include <cstdint>
#include <string>
#include <fstream>
#include <filesystem>
#include <vector>

#ifdef __cplusplus
extern "C" {
#endif

#ifdef _MSC_VER
	typedef wchar_t wchar;
#endif

#define MAGIC_LEN 4

	typedef enum CxmlAttributeType : uint32_t
	{
		TYPE_NONE = 0,
		TYPE_INT = 1,
		TYPE_FLOAT = 2,
		TYPE_STRING = 3,
		TYPE_WSTRING = 4,
		TYPE_HASH = 5,
		TYPE_INTEGER_ARRAY = 6,
		TYPE_FLOAT_ARRAY = 7,
		TYPE_FILE = 8,
		TYPE_ID_REF = 9,
		TYPE_ID = 10,
		TYPE_ID_HASH_REF = 11,
		TYPE_ID_HASH = 12
	} CxmlAttributeType;
	
	typedef struct CxmlAttributeRefId {
		uint32_t ref;
		uint32_t id;
	} CxmlAttributeValueSz;

	typedef struct CxmlAttributeHeader {
		uint32_t name;
		CxmlAttributeType type;
		uint32_t value;
		uint32_t sz;
	} CxmlAttributeHeader;

	typedef struct CxmlElementHeader {
		uint32_t elementName;
		uint32_t numAttributes;
		
		uint32_t parentElement;
		uint32_t prevSibling;
		uint32_t nextSibling;

		uint32_t firstChild;
		uint32_t lastChild;
	} CxmlElementHeader;

	typedef struct CxmlTableDeclaration {
		uint32_t tableOffset;
		uint32_t tableSize;
	} CxmlTableDeclaration;

	typedef struct CxmlFileHeader {
		char magic[MAGIC_LEN];
		uint32_t version;

		CxmlTableDeclaration treeTable;
		CxmlTableDeclaration idTable;
		CxmlTableDeclaration hashIdTable;
		CxmlTableDeclaration stringTable;
		CxmlTableDeclaration wstringTable;
		CxmlTableDeclaration hashTable;
		CxmlTableDeclaration intArrayTable;
		CxmlTableDeclaration floatArrayTable;
		CxmlTableDeclaration fileTable;
	} CxmlFileHeader;



#ifdef __cplusplus
}
#endif



namespace LibCXML {
	class CXMLReader {
	private: 
		bool checkMagicNumber(const char* magic);
		CXMLStream* readTable(CxmlTableDeclaration dec);
		std::fstream* cxmlFile;
		CxmlFileHeader cxmlHeader;
	public:

		CXMLStream* TreeTable;
		CXMLStream* IdTable;
		CXMLStream* HashIdTable;
		CXMLStream* StringTable;
		CXMLStream* WStringTable;
		CXMLStream* HashTable;
		CXMLStream* IntArrayTable;
		CXMLStream* FloatArrayTable;
		CXMLStream* FileTable;

		CXMLReader(const std::string& cxmlFilePath, const char* magic);
		~CXMLReader();
	};


	class CXMLStream {
		char* buffer;
		size_t length;
		size_t pos;
	public:
		CXMLStream(char* srcbuffer, size_t size);
		~CXMLStream();
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
	};
	
	class CXMLElement {
	private:
		void readCurrentElement();
		void readCurrentAttribute();

		CXMLReader* reader;
		CxmlElementHeader curElemPtr;
		std::string elementName;

		std::vector<CXMLAttributeBase*> attributes;
	public:
		CXMLElement(const std::string& cxmlFile, const std::string& magic);
		~CXMLElement();
		std::string ElementName();
		template <typename T> T GetAttribute(const std::string& attributeName) {
			for (CXMLAttributeBase* attribute : this->attributes) {
				if (attribute->AttributeName() == attributeName) {
					return (T)attribute;
				}
			}
			return NULL;
		}

		bool HasParentElement();
		bool HasPrevSibling();
		bool HasNextSibling();
		bool HasFirstChild();
		bool HasLastChild();


		CXMLElement* ParentElement();
		CXMLElement* PrevSibling();
		CXMLElement* NextSibling();
		CXMLElement* FirstChild();
		CXMLElement* LastChild();
	};


	class CXMLAttributeBase {
	protected:
		std::string attributeName;
	public:
		std::string AttributeName();
	};


	template <typename T> class CXMLAttribute : public CXMLAttributeBase {
	private:
		T attributeValue;
	public:
		CXMLAttribute(const std::string& cxmlAttributeName, T cxnlAttributeValue) {
			this->attributeName = cxmlAttributeName;
			this->attributeValue = cxnlAttributeValue;
		}
		~CXMLAttribute();
		T AttributeValue() {
			return attributeValue;
		}
	};
}

#endif
