#!/bin/bash -ex

TARGET="client"
REPO="oss"
FFMPEG_REPO=FFmpeg

cd ..
if [ "${REPO}" != "oss" ] ; then
    mkdir ${FFMPEG_REPO} && cd ${FFMPEG_REPO}
    cd -
    if [ ! -f "${FFMPEG_REPO}/libavcodec/distributed_encoder.c" ] ; then
        cd ${FFMPEG_REPO}
        patch -p1 < ../ffmpeg/patches/FFmpeg_OMAF.patch
        cd ..
    fi
fi

if [ "${TARGET}" == "server" ] ; then

    mkdir -p build/external/ffmpeg_server
    cd build/external/ffmpeg_server
    ../../../${FFMPEG_REPO}/configure --prefix=/usr --libdir=/usr/local/lib \
        --enable-static --enable-shared --enable-gpl --enable-nonfree \
        --disable-optimizations --disable-vaapi
    make -j $(nproc)
    sudo make install

elif [ "${TARGET}" == "client" ] ; then

    mkdir -p build/external/ffmpeg_client
    cd build/external/ffmpeg_client
    ../../../${FFMPEG_REPO}/configure --enable-shared
    make -j $(nproc)

fi
