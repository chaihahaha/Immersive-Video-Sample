CMAKE_MINIMUM_REQUIRED(VERSION 2.12)
PROJECT(immersive-media)

SET(CMAKE_SKIP_INSTALL_ALL_DEPENDENCY TRUE)

IF(NOT CMAKE_BUILD_TYPE)
  SET(CMAKE_BUILD_TYPE Release)
ENDIF()

MESSAGE("Build type: " ${CMAKE_BUILD_TYPE})


SET(CMAKE_CXX_FLAGS_DEBUG   "${CMAKE_CXX_FLAGS_DEBUG} \
                             -std=c++20 -D_GLIBCXX_USE_CXX11_ABI=0 \
                             -I${CMAKE_CURRENT_SOURCE_DIR}/360SCVP")
SET(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} \
-Wno-error -Wno-unused-result -Wno-inconsistent-missing-override -Wno-format-nonliteral -pedantic -Wno-undef -Wno-unused-but-set-variable -Wno-unused-parameter -Wno-sign-conversion -Wno-implicit-int-conversion -Wall -std=c++20 -D_GLIBCXX_USE_CXX11_ABI=0 \
                             -I${CMAKE_CURRENT_SOURCE_DIR}/360SCVP")
SET(CMAKE_CXX_STANDARD 20)
SET(CMAKE_CXX_STANDARD_REQUIRED ON)
SET(UTILS_DIR "utils")
SET(PLAYER_LIB_DIR "player/player_lib")
SET(PLAYER_LIB_FLAGS "-DCMAKE_CXX_FLAGS= \
                      -L${CMAKE_BINARY_DIR}/OmafDashAccess \
                      -I/opt/homebrew/include \
                      -L${CMAKE_BINARY_DIR}/360SCVP")
SET(PLAYER_MEDIASOURCE_DIR "player/player_lib/MediaSource")
SET(PLAYER_APP_DIR "player/app")
SET(PLAYER_APP_FLAGS "-DCMAKE_CXX_FLAGS= \
                      -L${CMAKE_BINARY_DIR}/OmafDashAccess \
                      -L${CMAKE_BINARY_DIR}/360SCVP \
                      -L${CMAKE_BINARY_DIR}/player/player_lib")
SET(PLAYER_COMMON_DIR "player/player_lib/Common")
ADD_SUBDIRECTORY(360SCVP)
ADD_SUBDIRECTORY(isolib)
ADD_SUBDIRECTORY(OmafDashAccess)
#ADD_SUBDIRECTORY(glog)
target_compile_options(360SCVP PRIVATE "-Wno-unused-but-set-variable")

ADD_CUSTOM_TARGET(player ALL
    COMMAND echo "Target player"
    VERBATIM)
ADD_CUSTOM_COMMAND(TARGET player
    COMMAND export LD_LIBRARY_PATH=${CMAKE_BINARY_DIR}/OmafDashAccess:${CMAKE_BINARY_DIR}/360SCVP:$LD_LIBRARY_PATH &&
            cp ${CMAKE_CURRENT_SOURCE_DIR}/${UTILS_DIR}/ns_def.h ${CMAKE_CURRENT_SOURCE_DIR}/${PLAYER_LIB_DIR} &&
            cp ${CMAKE_CURRENT_SOURCE_DIR}/${UTILS_DIR}/error.h ${CMAKE_CURRENT_SOURCE_DIR}/${PLAYER_LIB_DIR} &&
            cp ${CMAKE_CURRENT_SOURCE_DIR}/${UTILS_DIR}/OmafStructure.h ${CMAKE_CURRENT_SOURCE_DIR}/${PLAYER_LIB_DIR} &&
            cp ${CMAKE_CURRENT_SOURCE_DIR}/OmafDashAccess/OmafDashAccessApi.h ${CMAKE_CURRENT_SOURCE_DIR}/${PLAYER_MEDIASOURCE_DIR} &&
            cp ${CMAKE_CURRENT_SOURCE_DIR}/${UTILS_DIR}/data_type.h ${CMAKE_CURRENT_SOURCE_DIR}/${PLAYER_LIB_DIR} &&
            cp ${CMAKE_CURRENT_SOURCE_DIR}/${UTILS_DIR}/data_type.h ${CMAKE_CURRENT_SOURCE_DIR}/${PLAYER_COMMON_DIR} &&
            cp ${CMAKE_CURRENT_SOURCE_DIR}/${UTILS_DIR}/pose.h ${CMAKE_CURRENT_SOURCE_DIR}/${PLAYER_LIB_DIR} &&
            cp ${CMAKE_CURRENT_SOURCE_DIR}/${UTILS_DIR}/pose.h ${CMAKE_CURRENT_SOURCE_DIR}/${PLAYER_MEDIASOURCE_DIR} &&
            cp ${CMAKE_CURRENT_SOURCE_DIR}/${UTILS_DIR}/pose.h ${CMAKE_CURRENT_SOURCE_DIR}/${PLAYER_COMMON_DIR} &&
            cp ${CMAKE_CURRENT_SOURCE_DIR}/360SCVP/360SCVPAPI.h ${CMAKE_CURRENT_SOURCE_DIR}/${PLAYER_LIB_DIR} &&
            cp ${CMAKE_CURRENT_SOURCE_DIR}/360SCVP/360SCVPAPI.h ${CMAKE_CURRENT_SOURCE_DIR}/${PLAYER_MEDIASOURCE_DIR} &&
            cp ${CMAKE_CURRENT_SOURCE_DIR}/360SCVP/360SCVPAPI.h ${CMAKE_CURRENT_SOURCE_DIR}/${PLAYER_COMMON_DIR} &&
        mkdir -p ${PLAYER_LIB_DIR} && cd ${PLAYER_LIB_DIR} &&
            emcmake cmake -DUSE_OMAF=ON
                  -DUSE_WEBRTC=OFF
                  -DUSE_VCD=OFF
                  -DLINUX_OS=ON
                  ${PLAYER_LIB_FLAGS}
                  ${CMAKE_CURRENT_SOURCE_DIR}/${PLAYER_LIB_DIR} &&
            make   &&
            make install &&
            
            mkdir -p ../../${PLAYER_APP_DIR} && cd ../../${PLAYER_APP_DIR} &&
            emcmake cmake -DLINUX_OS=ON
                    -DUSE_TRACE=${USE_TRACE}
                    ${PLAYER_APP_FLAGS}
                    ${CMAKE_CURRENT_SOURCE_DIR}/${PLAYER_APP_DIR} &&
            make

    COMMENT "Building player..."
    VERBATIM)
ADD_DEPENDENCIES(player OmafDashAccess)

