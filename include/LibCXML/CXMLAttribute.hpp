#ifndef LIB_CXML_ATTRIBUTE_H
#define LIB_CXML_ATTRIBUTE_H 1
#include "CXMLFile.hpp"
#include "CXMLReader.hpp"
#include "CXMLAttributeBase.hpp"

#include <string>

namespace LibCXML {

	template <typename T> class CXMLAttribute : public CXMLAttributeBase {
	private:
		T attributeValue;
	public:
		template <typename... Args, typename = T> CXMLAttribute(const std::string& cxmlAttributeName, Args&&... args) {
			this->attributeName = cxmlAttributeName;
			this->attributeValue = T(std::forward<Args>(args)...);
		}

		CXMLAttribute(const std::string& cxmlAttributeName, T cxmlAttributeValue) {
			this->attributeName = cxmlAttributeName;
			this->attributeValue = cxmlAttributeValue;
		}
		~CXMLAttribute() override = default;
		T AttributeValue() {
			return attributeValue;
		}

	};
}

#endif