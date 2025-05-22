CMAKE_MINIMUM_REQUIRED(VERSION 2.8)

OPTION(USE_TRACE
       "Use trace"
       OFF
)

OPTION(LINUX_OS
       "Use linux os"
       ON
)

OPTION(ANDROID_OS
       "Use android os"
       OFF
)

PROJECT(app)

IF(USE_SAFE_MEM)
ADD_DEFINITIONS("-D_SAFE_MEM_")
ENDIF()

SET(LINUX_OS ON)

ADD_DEFINITIONS("-g -c -fPIC -std=c++11 -fpermissive")

ADD_DEFINITIONS("-D_LINUX_OS_")

IF(ANDROID_OS)
  ADD_DEFINITIONS("-D_ANDROID_OS_")
ENDIF()

IF(DEFINED WEBRTC_LINUX_SDK)
    INCLUDE_DIRECTORIES("${WEBRTC_LINUX_SDK}/include")
    LINK_DIRECTORIES("${WEBRTC_LINUX_SDK}/lib")
ENDIF()
INCLUDE_DIRECTORIES(/Users/hasee/source/emsdk/upstream/emscripten/cache/sysroot/include ../../utils)
LINK_DIRECTORIES(/Users/hasee/source/emsdk/upstream/emscripten/cache/sysroot/lib ../build/client/isolib/dash_parser)
#INCLUDE_DIRECTORIES(/opt/homebrew/include)
#LINK_DIRECTORIES(/opt/homebrew/lib)

#AUX_SOURCE_DIRECTORY(../player_lib/ffmpeg FFMPEG_SRC)
AUX_SOURCE_DIRECTORY(. DIR_SRC)
AUX_SOURCE_DIRECTORY(. DIR_SRC)
AUX_SOURCE_DIRECTORY(android ANDROID_SRC)
AUX_SOURCE_DIRECTORY(linux LINUX_SRC)
#SET(DIR_SRC ${DIR_SRC} ${LINUX_SRC} ${FFMPEG_SRC})
SET(DIR_SRC ${DIR_SRC} ${LINUX_SRC})
SET(LINK_LIB ${LINK_LIB} OmafDashAccess)


ADD_COMPILE_OPTIONS(
    "-matomics"
    "-mbulk-memory"
    "-D_LINUX_OS_"
    "-sUSE_SDL=2")
ADD_LINK_OPTIONS(
    "-pthread"
    "-lwebsocket"
    #"SHELL:-s PROXY_TO_PTHREAD"
    "SHELL:-s USE_PTHREADS=1"
    "SHELL:-s ASYNCIFY=1"
    "-g4"
    "SHELL:-s ASSERTIONS=2"
    "SHELL:-s DEMANGLE_SUPPORT=1"
    "SHELL:-s FULL_ES3=1"
    "SHELL:-s MIN_WEBGL_VERSION=2"
    "SHELL:-s USE_GLFW=3"
    "SHELL:-s USE_WEBGL2=1"
    "SHELL:-s FETCH=1"
    -lidbfs.js
    -lwebsocket.js
    "SHELL:-s EXPORTED_RUNTIME_METHODS=['ccall']"
    #"SHELL:-s EXPORTED_FUNCTIONS=['_start_app','_main']"
    "SHELL:--preload-file /Users/hasee/source/IVS_webpage/gaslamp@/"
    "SHELL:-s FORCE_FILESYSTEM=1"
    "SHELL:-s PTHREAD_POOL_SIZE=51"
    "SHELL:-s SAFE_HEAP=1"
    "SHELL:-s PROXY_POSIX_SOCKETS"
    "SHELL:-s NO_EXIT_RUNTIME=1"
    #"SHELL:-s GL_PREINITIALIZED_CONTEXT=1"
)

ADD_EXECUTABLE(render ${DIR_SRC})


SET(LINK_LIB ${LINK_LIB} MediaPlayer GLU dl /Users/hasee/source/ffmpeg_wasm_lib/lib/libavcodec.a /Users/hasee/source/ffmpeg_wasm_lib/lib/libavutil.a /Users/hasee/source/ffmpeg_wasm_lib/lib/libswscale.a /Users/hasee/source/Immersive-Video-Sample/src/build/client/isolib/dash_parser/libdashparser.a /Users/hasee/source/Immersive-Video-Sample/src/build/client/360SCVP/lib360SCVP.a x264 x265 avcodec swscale swresample avformat avfilter avdevice avutil curl)
IF(USE_SAFE_MEM)
  SET(LINK_LIB ${LINK_LIB} safestring_shared)
ENDIF()
target_include_directories(render PRIVATE /Users/hasee/source/ffmpeg_wasm_lib/include /opt/homebrew/include)
target_link_directories(render PRIVATE /Users/hasee/source/ffmpeg_wasm_lib/lib /opt/homebrew/lib)

TARGET_LINK_LIBRARIES(render ${LINK_LIB})
