project('CXML', 'cpp',
  version : '0.1',
  default_options : ['warning_level=3', 'cpp_std=c++14'])


cpp = meson.get_compiler('cpp')
dirbase = meson.current_source_dir()

static_library('CXML',
        'CXMLAttribute.cpp',
        'CXMLAttributeBase.cpp',
        'CXMLElement.cpp',
        'CXMLReader.cpp',
        'CXMLStream.cpp',
        install : true)
