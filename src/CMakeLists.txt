CMAKE_MINIMUM_REQUIRED(VERSION 3.5)
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

# Whether player/app bakes webcontent/ into render.data with --preload-file.
# player/app is built by a nested, separate CMake project (see the custom
# command below), so this has to be forwarded explicitly:
#     emcmake cmake ../.. -DCMAKE_BUILD_TYPE=Release \
#         -DCMAKE_POLICY_VERSION_MINIMUM=3.5 -DIVS_PRELOAD_CONTENT=OFF
# See WASM_BUILD_AND_RUN.md section 7.
OPTION(IVS_PRELOAD_CONTENT "Bake webcontent/ into render.data" ON)

# Where the FFmpeg wasm static libraries are, and whether to link libx265.
# Forwarded to the nested player/app project below, for the same reason.
# Build a fresh set without Docker using tools/build_ffmpeg_wasm.sh.
SET(IVS_FFMPEG_WASM_LIB_DIR "$ENV{HOME}/source/ffmpeg_wasm_lib"
    CACHE PATH "Directory holding the FFmpeg wasm include/ and lib/")
OPTION(IVS_FFMPEG_WITH_X265 "Link libx265 (only needed for an x265-enabled FFmpeg)" ON)

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
                    -DIVS_PRELOAD_CONTENT=${IVS_PRELOAD_CONTENT}
                    -DIVS_FFMPEG_WASM_LIB_DIR=${IVS_FFMPEG_WASM_LIB_DIR}
                    -DIVS_FFMPEG_WITH_X265=${IVS_FFMPEG_WITH_X265}
                    ${PLAYER_APP_FLAGS}
                    ${CMAKE_CURRENT_SOURCE_DIR}/${PLAYER_APP_DIR} &&
            make

    COMMENT "Building player..."
    VERBATIM)
ADD_DEPENDENCIES(player OmafDashAccess)


# ---------------------------------------------------------------------------
# Rebuild the FFmpeg wasm static libraries natively with the local emsdk -- no
# Docker, no OrbStack. See tools/build_ffmpeg_wasm.sh.
#
# Deliberately NOT part of the default build: it takes a few minutes and the
# libraries almost never change. It also always writes to the script's own
# default prefix (build/ffmpeg-wasm/prefix) rather than to
# IVS_FFMPEG_WASM_LIB_DIR, so that running it can never overwrite an existing
# library directory by surprise. Point the player at the result with:
#     -DIVS_FFMPEG_WASM_LIB_DIR=<repo>/build/ffmpeg-wasm/prefix
# ---------------------------------------------------------------------------
ADD_CUSTOM_TARGET(ffmpeg-wasm
    COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/../tools/build_ffmpeg_wasm.sh
    COMMENT "Building FFmpeg wasm static libraries (native emsdk, no Docker)"
    VERBATIM)
