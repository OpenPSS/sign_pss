project('sign_pss', 'cpp',
  version : '0.1',
  default_options : ['warning_level=3', 'cpp_std=c++14'])

cpp = meson.get_compiler('cpp')

dirbase = meson.current_source_dir()

external_libs_dir = join_paths(dirbase, '../lib/unix')
external_include = include_directories('../include/unix')
project_include = include_directories('../')

libcrypto_dep = cpp.find_library('libcrypto', dirs : external_libs_dir, static: true)
libssl_dep = cpp.find_library('libssl', dirs : external_libs_dir, static: true)

psm_lib_dir = join_paths(dirbase, '../psm_encryptor/build')
cxml_lib_dir = join_paths(dirbase, '../LibCXML/build')

libpsm_encryptor_dep = cpp.find_library('libpsm_encryptor', dirs : psm_lib_dir, static: true)
libcxml_dep = cpp.find_library('libCXML', dirs : cxml_lib_dir, static: true)

executable('sign_pss',
	   'appinfo.cpp',
	   'io.cpp',
	   'path.cpp',
	   'sign_pss.cpp',
	   'ScePsmDrm.cpp',
	   'txt.cpp',
	   include_directories : [
		  external_include,
		  project_include
	   ],
        dependencies : [
          libpsm_encryptor_dep,
		  libcxml_dep,
          libcrypto_dep,
          libssl_dep,
        ])

