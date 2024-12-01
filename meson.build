project('sign_pss', 'cpp',
  version : '0.1',
  default_options : ['warning_level=3', 'cpp_std=c++14'])

cpp = meson.get_compiler('cpp')

libdir = '/home/flunitrazepam/REPOS/sign_pss/psm_encryptor/builddir/'
libdir2 = '/home/flunitrazepam/REPOS/sign_pss/psm_encryptor/lib/unix'

libcrypto_dep = cpp.find_library('libcrypto', dirs : libdir2, static: true)
libssl_dep = cpp.find_library('libssl', dirs : libdir2, static: true)

libpsm_encryptor_dep = cpp.find_library('libpsm_encryptor', dirs : libdir, static: true)

executable('sign_pss',
           'sign_pss/io.cpp',
           'sign_pss/path.cpp',
           'sign_pss/sign_pss.cpp',
           'sign_pss/txt.cpp',
        dependencies : [
          libpsm_encryptor_dep,
          libcrypto_dep,
          libssl_dep,
        ])

