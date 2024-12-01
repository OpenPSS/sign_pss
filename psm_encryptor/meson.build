project('psm_encryptor', 'cpp',
  version : '0.1',
  default_options : ['warning_level=3', 'cpp_std=c++14'],)

inc = include_directories('include/x64')

cpp = meson.get_compiler('cpp')

#libdir = meson.current_source_dir() + 'lib/unix'

libdir = '/home/flunitrazepam/REPOS/sign_pss/psm_encryptor/lib/unix'

libcrypto_dep = cpp.find_library('libcrypto', dirs : libdir, static: true)
libssl_dep = cpp.find_library('libssl', dirs : libdir, static: true)
libdl_dep = cpp.find_library('dl')

static_library('psm_encryptor',
        'HexKey.cpp',
        'PsmEdata.cpp',
        'PsmKeys.cpp',
        'OpenSSL.cpp',
        'psm_encryptor.cpp',
        include_directories : inc,
        install : true,
        dependencies : [
          libcrypto_dep,
          libssl_dep,
          libdl_dep
        ],
        cpp_args : '-D_PSM_SIGNTOOL_BUILD')
