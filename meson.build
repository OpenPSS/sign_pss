project('sign_pss', 'cpp',
  version : '0.1',
  default_options : ['warning_level=3', 'cpp_std=c++14'])

cpp = meson.get_compiler('cpp')

dirbase = meson.current_source_dir()
inc = include_directories('include')

libCXML_proj = subproject('LibCXML')
libCXML_dep = libCXML_proj.get_variable('libCXML_dep')

libpsm_encryptor = subproject('psm_encryptor')
libpsm_encryptor_dep = libpsm_encryptor.get_variable('libpsm_encryptor_dep')

executable('sign_pss',
		   'appinfo.cpp',
		   'io.cpp',
		   'path.cpp',
		   'sign_pss.cpp',
		   'ScePsmDrm.cpp',
		   'txt.cpp',
		   include_directories : inc,
			dependencies : [
			  libpsm_encryptor_dep,
			  libCXML_dep
			])

