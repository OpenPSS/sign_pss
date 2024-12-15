#/bin/sh
cd psm_encryptor
meson build
cd build && ninja && cd ../..

cd LibCXML
meson build
cd build && ninja && cd ../..

cd sign_pss
meson build
cd build && ninja && cd ../..
