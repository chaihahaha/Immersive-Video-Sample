CMAKE_MINIMUM_REQUIRED(VERSION 2.8)

OPTION(USE_OMAF
       "Use omaf"
       OFF
)

OPTION(USE_WEBRTC
       "Use webrtc"
       OFF
)

OPTION(USE_TRACE
       "Use trace"
       OFF
)

OPTION(LINUX_OS
       "Use linux os"
       OFF
)

OPTION(ANDROID_OS
       "Use android os"
       OFF
)

PROJECT(player_lib)

ADD_DEFINITIONS("-D_ENABLE_DASH_SOURCE_")

ADD_DEFINITIONS("-D_LINUX_OS_")


set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS}  -Wno-deprecated-declarations")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-deprecated-declarations")

AUX_SOURCE_DIRECTORY(. DIR_SRC)
AUX_SOURCE_DIRECTORY(./Decoder DEC_SRC)
AUX_SOURCE_DIRECTORY(./MediaSource MEDSRC_SRC)
AUX_SOURCE_DIRECTORY(./Render RNDR_SRC)
AUX_SOURCE_DIRECTORY(./Mesh MESH_SRC)
AUX_SOURCE_DIRECTORY(./Api API_SRC)
#AUX_SOURCE_DIRECTORY(./Common COMMON_SRC)
AUX_SOURCE_DIRECTORY(./Common COMMON_SRC)

set(DIR_SRC
    ${DIR_SRC}
    ${DEC_SRC}
    ${MEDSRC_SRC}
    ${RNDR_SRC}
    ${MESH_SRC}
    ${API_SRC}
    ${COMMON_SRC}
)


SET(LINK_LIB ${LINK_LIB} OmafDashAccess)



SET(LINK_LIB ${LINK_LIB}
    avfilter avformat avcodec avdevice avutil swscale swresample
    360SCVP GLU X11 lzma z EGL dl /Users/hasee/source/ffmpeg_wasm_lib/lib/libavcodec.a /Users/hasee/source/ffmpeg_wasm_lib/lib/libavutil.a /Users/hasee/source/ffmpeg_wasm_lib/lib/libswscale.a)


ADD_LIBRARY(MediaPlayer STATIC ${DIR_SRC} ../../utils/Log.cpp ../../utils/tinyxml2.cpp)
ADD_COMPILE_OPTIONS(
    "-Werror"
    "-Wno-implicit-function-declaration"
    "-matomics"
    "-mbulk-memory"
)
#ADD_COMPILE_OPTIONS("-s USE_GLFW=3" "-s USE_WEBGL2=1" "-s FULL_ES2=1" "-s MIN_WEBGL_VERSION=2")
ADD_LINK_OPTIONS(
    "-pthread"
    "SHELL:-s PROXY_TO_PTHREAD"
    "SHELL:-s USE_PTHREADS=1"
    "SHELL:-s PTHREAD_POOL_SIZE=10"
    "SHELL:-s FULL_ES3=1"
    "SHELL:-s MIN_WEBGL_VERSION=2"
    "SHELL:-s USE_GLFW=3"
    "SHELL:-s USE_WEBGL2=1"
    "SHELL:-s ASSERTIONS=2"
    "SHELL:-s DEMANGLE_SUPPORT=1"
)

include_directories(MediaPlayer PRIVATE /Users/hasee/source/ffmpeg_wasm_lib/include /opt/homebrew/include)
target_link_directories(MediaPlayer PRIVATE /Users/hasee/source/ffmpeg_wasm_lib/lib /opt/homebrew/lib)
TARGET_LINK_LIBRARIES(MediaPlayer ${LINK_LIB})

INSTALL(TARGETS MediaPlayer
        RUNTIME DESTINATION bin
        LIBRARY DESTINATION lib
        ARCHIVE DESTINATION lib/static)

INSTALL(FILES ${PROJECT_SOURCE_DIR}/Api/MediaPlayerAPI.h DESTINATION include)
INSTALL(FILES ${PROJECT_SOURCE_DIR}/Api/MediaPlayer.pc DESTINATION lib/pkgconfig)
