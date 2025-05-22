#!/bin/bash -e

mkdir -p ../build/external
cd ../build/external
if [ ! -d "./glog" ] ; then
    git clone https://gitee.com/mirrors/glog.git
fi

cd glog
git checkout v0.5.0
# cmake --build build --target test
#cmake --build build --target install
