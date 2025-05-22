#!/bin/bash -ex

EX_PATH=${PWD}
SRC_PATH=${PWD}/..

parameters_usage(){
    echo 'Usage: 1. <target>:           [ server, client, test ]'
    echo '       2. <prebuild_flag>:    [ y, n ]'
    echo '       3. <hardware>:         [ SG1, ATSM ]'
}

cd ${EX_PATH}
# install zlib yasm curl opengl lzma glog safestringlib ffmpeg
mkdir -p ../build/client
cd ../build/client
emcmake cmake -DTARGET=client ../../
emmake make 
