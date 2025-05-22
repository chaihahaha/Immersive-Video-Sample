#!/bin/bash -x
OS=$(awk -F= '/^NAME/{print $2}' /etc/os-release)
TARGET=$1
LTTNGFLAG=$2
EX_PATH=${PWD}




#program_exists gcc
#
#program_exists cmake
#if [ $? != 0 ];then
#    if [ ! -f "./cmake-3.12.4.tar.gz" ];then
#        wget https://cmake.org/files/v3.12/cmake-3.12.4.tar.gz
#    fi
#    tar xf cmake-3.12.4.tar.gz
#    cd cmake-3.12.4
#    ./bootstrap --prefix=/usr && make -j $(nproc) && sudo make install && cd ..
#fi
#
#mkdir -p ../build/external && cd ../build/external
#if [ ! -f "./zlib-1.3.1.tar.gz" ];then
#    wget http://zlib.net/zlib-1.3.1.tar.gz
#fi
#tar xf zlib-1.3.1.tar.gz
#cd zlib-1.3.1 && ./configure && make -j $(nproc) && sudo make install && cd ..
#
#program_exists yasm
#if [ $? != 0 ];then
#    if [ ! -f "./yasm-1.3.0.tar.gz" ];then
#        wget http://www.tortall.net/projects/yasm/releases/yasm-1.3.0.tar.gz
#    fi
#    tar zxf yasm-1.3.0.tar.gz
#    cd yasm-1.3.0
#    ./configure && make -j $(nproc) && sudo make install && cd ..
#fi
#
#if [ ! -f "./curl-7.66.0.tar.xz" ];then
#    wget https://curl.haxx.se/download/curl-7.66.0.tar.xz
#fi
#tar xf curl-7.66.0.tar.xz
#cd curl-7.66.0 && ./configure --with-darwinssl && make -j $(nproc) && sudo make install
 
cd ${EX_PATH}
./install_glog.sh
./install_safestringlib.sh
./prebuild_player.sh
./install_FFmpeg.sh client
