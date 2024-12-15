// definitely not stolen from SnowPME

#include "appinfo.hpp"

#include <string>
#include <iostream>
#include "subprojects/LibCXML/LibCXML.hpp"


bool AppInfo::nextElement() {
	// goto next element

	if (element->HasFirstChild()) {
		element->FirstChild();
		return true;
	}
	else if (element->HasNextSibling()) {
		element->NextSibling();
		return true;
	}

	while (element->HasParentElement()) {
		element->ParentElement();
		if (element->HasNextSibling()) {
			element->NextSibling();
			return true;
		}
	}

	return false;
}

bool AppInfo::IsPsmUnity() {
	if (this->SdkType == "Unity for PSM") return true;
	if (this->SdkType == "PSM SDK") return false;
	return false;
}

bool AppInfo::Validate() {
	if (this->SdkType != "PSM SDK" && this->SdkType != "Unity for PSM") {
		std::cerr << "[APP.INFO] SDK Type is " << this->SdkType << ", expected either \"PSM SDK\" or \"Unity for PSM\"" << std::endl;
		return false;
	}

	if (this->TargetRuntimeVersion.empty()) {
		std::cerr << "[APP.INFO] Missing runtime version!" << std::endl;
		return false;
	}

	if (this->Icon128x128 == nullptr || this->Icon256x256 == nullptr || this->Icon512x512 == nullptr || this->Splash854x480 == nullptr) {
		std::cerr << "[APP.INFO] Missing one or more images (icon256x256, icon512x512  or splash854x480)" << std::endl;
		return false;
	}

	if (this->CopyrightText == nullptr) {
		std::cerr << "[APP.INFO] Copyright.txt is missing!" << std::endl;
		return false;
	}

	if (this->Author.empty()) {
		std::cerr << "[APP.INFO] Author is missing!" << std::endl;
	}

	if (this->Website.empty()) {
		std::cerr << "[APP.INFO] Website entry is missing!" << std::endl;
		return false;
	}

	if (this->Names.empty()) {
		std::cerr << "[APP.INFO] Name entry is missing!" << std::endl;
		return false;
	}

	if (this->ShortNames.empty()) {
		std::cerr << "[APP.INFO] Short Name entry is missing!" << std::endl;
		return false;
	}

	if (this->ProjectName == "*" || this->ProjectName == "_PSM_DEFUALT_") {
		std::cerr << "[APP.INFO] Project Name is \"" << this->ProjectName << "\", which is usually reserved for developer packages." << std::endl;
		return false;
	}

	if (this->ManagedHeapSize == 0 && this->ResourceHeapSize == 0) {
		std::cerr << "[APP.INFO] Managed heap size (or resource heap size) is missing!" << std::endl;
		return false;
	}

	return true;

}


AppInfo::AppInfo(std::string& appInfoFile) {

	this->element = new LibCXML::CXMLElement(appInfoFile, "PSMA");
	std::string parserMode = "";
	ProductInfo productInfo = ProductInfo();

	if (this->element != nullptr) {
		do {
			if (element->ElementName() == "name") parserMode = element->ElementName();
			else if (element->ElementName() == "short_name") parserMode = element->ElementName();
			else if (element->ElementName() == "product") parserMode = element->ElementName();
			else if (element->ElementName() == "unity") parserMode = element->ElementName();
			else if (element->ElementName() == "application") {
				READATTRIBUTE(std::string, "default_locale", this->DefaultLocale);
				READATTRIBUTE(std::string, "sdk_version", this->TargetSdkVerison);
				READATTRIBUTE(std::string, "project_name", this->ProjectName);
				READATTRIBUTE(std::string, "version", this->AppVersion);
				READATTRIBUTE(std::string, "runtime_version", this->TargetRuntimeVersion);
			}
			else if (element->ElementName() == "app_xml_format") {
				READATTRIBUTE(std::string, "sdk_type", this->SdkType);
				READATTRIBUTE(std::string, "version", this->AltVersion);
			}
			else if (parserMode == "name" && element->ElementName() == "localized_item") {
				LocaleInfo locale;
				READATTRIBUTE(std::string, "locale", locale.Locale);
				READATTRIBUTE(std::string, "value", locale.Name);
				Names.push_back(locale);
			}
			else if (parserMode == "short_name" && element->ElementName() == "localized_item") {
				LocaleInfo locale;
				READATTRIBUTE(std::string, "locale", locale.Locale);
				READATTRIBUTE(std::string, "value", locale.Name);
				ShortNames.push_back(locale);
			}
			else if (parserMode == "product" && element->ElementName() == "localized_item") {
				LocaleInfo locale;
				READATTRIBUTE(std::string, "locale", locale.Locale);
				READATTRIBUTE(std::string, "value", locale.Name);
				productInfo.Names.push_back(locale);
			}
			else if (parserMode == "unity" && element->ElementName() == "unity_original_runtime_version") {
				READATTRIBUTE(std::string, "value", this->UnityRuntimeVersion);
			}
			else if (parserMode == "unity" && element->ElementName() == "app_ver") {
				READATTRIBUTE(std::string, "value", this->UnityApplicationVer);
			}
			else if (element->ElementName() == "parental_control") {
				READATTRIBUTE(int, "lock_level", this->LockLevel);
			}
			else if (element->ElementName() == "rating_list") {
				std::string strHasOnlineFeatures;
				std::string strHighesAgeLimit;
				READATTRIBUTE(std::string, "has_online_features", strHasOnlineFeatures);
				READATTRIBUTE(int, "highest_age_limit", this->HighestAgeLimit);

				this->HasOnlineFeatures = (strHasOnlineFeatures == "true");
			}
			else if (element->ElementName() == "online_features") {
				std::string strPersonalInfo;
				std::string strUserLocation;
				std::string strExchangeContent;
				std::string strChat;

				READATTRIBUTE(std::string, "personal_info", strPersonalInfo);
				READATTRIBUTE(std::string, "user_location", strUserLocation);
				READATTRIBUTE(std::string, "exchange_content", strExchangeContent);
				READATTRIBUTE(std::string, "chat", strChat);

				this->PersonalInfo = strPersonalInfo == "true";
				this->UserLocation = strUserLocation == "true";
				this->ExchangeContent = strExchangeContent == "true";
				this->Chat = strChat == "true";
			}
			else if (element->ElementName() == "rating") {
				std::string strAge;
				std::string strValue;

				RatingInfo ratingInfo;
				READATTRIBUTE(std::string, "code", ratingInfo.Code);
				READATTRIBUTE(std::string, "type", ratingInfo.Type);

				READATTRIBUTE(int, "age", ratingInfo.Age);
				READATTRIBUTE(int, "value", ratingInfo.Value);

				this->RatingList.push_back(ratingInfo);
			}
			else if (element->ElementName() == "images") {
				READATTRIBUTE(LibCXML::CXMLStream*, "splash_854x480", this->Splash854x480);
				READATTRIBUTE(LibCXML::CXMLStream*, "icon_128x128", this->Icon128x128);
				READATTRIBUTE(LibCXML::CXMLStream*, "icon_512x512", this->Icon512x512);
				READATTRIBUTE(LibCXML::CXMLStream*, "icon_256x256", this->Icon256x256);
			}
			else if (element->ElementName() == "genre") {
				std::string strGenre;
				READATTRIBUTE(std::string, "value", strGenre);
				this->GenreList.push_back(strGenre);
			}
			else if (element->ElementName() == "website") {
				READATTRIBUTE(std::string, "href", this->Website);
			}
			else if (element->ElementName() == "copyright") {
				READATTRIBUTE(LibCXML::CXMLStream*, "text", this->CopyrightText);
				READATTRIBUTE(std::string, "author", this->Author);
			}
			else if (element->ElementName() == "product") {
				if (!productInfo.Label.empty())
					this->ProductList.push_back(productInfo);
				productInfo = ProductInfo();
				READATTRIBUTE(std::string, "label", productInfo.Label);
				READATTRIBUTE(std::string, "type", productInfo.Type);
			}
			else if (element->ElementName() == "memory") {
				READATTRIBUTE(int, "managed_heap_size", this->ManagedHeapSize);
				READATTRIBUTE(int, "resource_heap_size", this->ResourceHeapSize);
			}
			else if (element->ElementName() == "display") {
				READATTRIBUTE(std::string, "max_screen_size", this->MaxScreenSize);
			}
			else if (element->ElementName() == "camera") {
				READATTRIBUTE(std::string, "max_capture_resolution", this->MaxCaptureResolution);
			}
			else if (element->ElementName() == "feature") {
				std::string featureName;
				READATTRIBUTE(std::string, "value", featureName);
				this->FeatureList.push_back(featureName);
			}


		} while (this->nextElement());
	}
}

AppInfo::~AppInfo() {
	delete element;
}