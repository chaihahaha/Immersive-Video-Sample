emcmake cmake -DCMAKE_C_COMPILER=$(which emcc) -DCMAKE_CXX_COMPILER=$(which em++) \
                  -DUSE_OMAF=ON -DUSE_WEBRTC=OFF -DLINUX_OS=ON .
make VERBOSE=1
