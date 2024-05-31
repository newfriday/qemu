#!/bin/sh

PROJECT_TOP_DIR=$(git rev-parse --show-toplevel)
OUTPUT_DIR=$PROJECT_TOP_DIR/binary-build/output
make -p $OUTPUT_DIR

pushd $PROJECT_TOP_DIR/binary-build

../configure --prefix=/usr \
            --target-list="x86_64-softmmu" \
            --enable-debug-info \
            --enable-debug \
            --enable-modules \
            --disable-rbd \
            --disable-spice \
            --disable-strip \
            --disable-gnutls \
            --disable-nettle \
            --disable-gcrypt \
            --disable-fdt \
            --disable-virglrenderer \
            --enable-trace-backends="log"

make -j$(nproc --ignore=1) -f Makefile

popd
