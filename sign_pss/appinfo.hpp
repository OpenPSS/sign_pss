// definitely not stolen from SnowPME

#ifndef _APPINFO_H
#define _APPINFO_H 1
#include <string>
#include <vector>
#include <LibCXML/LibCXML.hpp>

#define READATTRIBUTE(TYPE, VALUE, SET) { \
		LibCXML::CXMLAttribute<TYPE>* attribute = element->GetAttribute<LibCXML::CXMLAttribute<TYPE>*>(VALUE); \
		if (attribute != nullptr) { \
			SET = attribute->AttributeValue(); \
		} \
	}
typedef struct LocaleInfo {
	std::string Locale;
	std::string Name;
} LocaleInfo;

typedef struct ProductInfo {
	std::string Type;
	std::string Label;
	std::vector<LocaleInfo> Names;
} ProductInfo;


typedef struct RatingInfo {
	int Age;
	std::string Code;
	std::string Type;
	int Value;
} RatingInfo;

class AppInfo {
private:
	LibCXML::CXMLElement* element;
	bool nextElement();
public: 
	AppInfo(std::string& appInfoFile);
	~AppInfo();
	bool IsPsmUnity();
	bool Validate();

	// <application>
	std::string DefaultLocale = "";
	std::string TargetSdkVerison = "";
	std::string ProjectName = "";
	std::string AppVersion = "";
	std::string TargetRuntimeVersion = "";

	// <app_xml_format>
	std::string SdkType = "";
	std::string AltVersion = "";

	// <name>
	std::vector<LocaleInfo> Names;

	// <short_name>
	std::vector<LocaleInfo> ShortNames;

	// <parental_control>
	int LockLevel = 0;

	// <rating_list>
	bool HasOnlineFeatures = false;
	int HighestAgeLimit = 0;

	bool PersonalInfo = false;
	bool UserLocation = false;
	bool ExchangeContent = false;
	bool Chat = false;

	std::vector<RatingInfo> RatingList;

	// <images>
	LibCXML::CXMLStream* Splash854x480 = nullptr;
	LibCXML::CXMLStream* Icon128x128 = nullptr;
	LibCXML::CXMLStream* Icon512x512 = nullptr;
	LibCXML::CXMLStream* Icon256x256 = nullptr;

	// <genre_list>
	std::vector<std::string> GenreList;

	// <developer>
	std::vector<std::string> DeveloperList;
	std::string Website = "";

	// <copyright> 
	LibCXML::CXMLStream* CopyrightText = nullptr;
	std::string Author = "";

	// <purchase>
	// <product_list>
	std::vector<ProductInfo> ProductList;

	// <runtime_config>
	int ManagedHeapSize = 0x2000000;
	int ResourceHeapSize = 0x4000000;

	std::string MaxScreenSize = "";
	std::string MaxCaptureResolution = "800x600";

	// <feature_list>

	std::vector<std::string> FeatureList;

	// <unity>
	std::string UnityRuntimeVersion = "";
	std::string UnityApplicationVer = "";
};

#endif