#!/bin/bash
# export gcc env
export PKG_CONFIG_PATH=/usr/local/lib64/pkgconfig:/usr/local/lib/pkgconfig:/usr/local/share/pkgconfig
export PATH=/usr/local/bin:$PATH
export LD_LIBRARY_PATH=/usr/local/lib64:/usr/local/lib
export CC=/usr/local/bin/gcc
export CXX=/usr/local/bin/g++
export DISTRO_LIBDIR=/usr/local/lib64

# compile
cd build
../configure --prefix=/usr \
            --target-list="x86_64-softmmu" \
            --enable-debug-info \
            --disable-rbd \
            --disable-spice \
            --disable-strip \
            --disable-gnutls \
            --disable-vnc-png \
            --disable-nettle \
            --disable-gcrypt \
            --enable-debug \
            --enable-modules \
            --enable-fdt \
            --disable-virglrenderer \
            --with-git-submodules=ignore \
            --enable-trace-backends="log"
make -j$(nproc --ignore=1)
