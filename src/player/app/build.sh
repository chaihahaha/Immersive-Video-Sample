emcmake cmake -DCMAKE_C_COMPILER=$(which emcc) -DCMAKE_CXX_COMPILER=$(which em++) \
              -DUSE_OMAF=ON -DUSE_WEBRTC=OFF -D_LINUX_OS_=ON .
make VERBOSE=1
