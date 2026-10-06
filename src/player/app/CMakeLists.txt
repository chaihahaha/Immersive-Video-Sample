CMAKE_MINIMUM_REQUIRED(VERSION 3.5)

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
# NOTE: see src/OmafDashAccess/CMakeLists.txt -- never -I the emsdk sysroot explicitly.
INCLUDE_DIRECTORIES(../../utils)
LINK_DIRECTORIES(../../build/client/isolib/dash_parser)
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
    # Leak hunting: ASan replaces the allocator wholesale and gives
    # __lsan_do_leak_check() a way to report what is still reachable.
    
    # PROXY_TO_PTHREAD / USE_PTHREADS are not used: -pthread is enough on
    # emsdk 3.1.40, and main() now drives the frame loop via
    # emscripten_set_main_loop instead of blocking.
    # ASYNCIFY is kept because parts of the OMAF reader still block on
    # condition variables; it is no longer load-bearing for networking.
    "SHELL:-s ASYNCIFY=1"
    # TEMPORARY (diagnostics): emit render.wasm.map so worker-thread crashes can
    # be symbolised. Remove once the GL-from-pthread issue is resolved.
    "SHELL:-g4"
    "SHELL:-s FULL_ES3=1"
    "SHELL:-s MIN_WEBGL_VERSION=2"
    "SHELL:-s USE_GLFW=3"
    "SHELL:-s USE_WEBGL2=1"
    "SHELL:-s EXPORTED_RUNTIME_METHODS=['ccall']"
    # Only the content the player actually reads: the MPD plus tile tracks 1..36.
    # The 189 MB of OMAF extractor tracks (AdaptationSet 1000..1049) are unused
    # with <enableExtractor>0</enableExtractor> and would otherwise be resident in
    # WebAssembly memory. Run tools/stage_content.sh to (re)create this directory.
    "SHELL:--preload-file ${CMAKE_CURRENT_SOURCE_DIR}/../../../webcontent@/"
    "SHELL:-s FORCE_FILESYSTEM=1"
    "SHELL:-s NO_EXIT_RUNTIME=1"

    # --- memory configuration -------------------------------------------------
    # The previous build died with
    #   "Cannot enlarge memory arrays to size 17420288 bytes (OOM)"
    # followed by a stack overflow with the default 64 KiB stack. A tiled 360
    # decoder needs far more than that.
    "SHELL:-s ALLOW_MEMORY_GROWTH=1"
    "SHELL:-s INITIAL_MEMORY=268435456"
    # Software HEVC decoding of an 8192x4096 picture needs a lot of headroom.
    # (Combined with the smaller preload and 4 decode threads this is now
    # comfortable; it used to abort with "Cannot enlarge memory".)
    "SHELL:-s MAXIMUM_MEMORY=4GB"
    "SHELL:-s STACK_SIZE=4194304"
    "SHELL:-s DEFAULT_PTHREAD_STACK_SIZE=2097152"
    # A small pre-spawned pool is enough: the download worker threads are
    # created on demand, and 51 pre-spawned threads wasted hundreds of MB.
    "SHELL:-s PTHREAD_POOL_SIZE=32"

    # Removed on purpose (they are debug-only and cost 10-50x runtime):
    #   -g4, -sASSERTIONS=2, -sSAFE_HEAP=1, -sDEMANGLE_SUPPORT=1
    # Removed because there is no network any more: -sPROXY_POSIX_SOCKETS,
    #   -lwebsocket, -lwebsocket.js, -sFETCH=1, -lidbfs.js
)

ADD_EXECUTABLE(render ${DIR_SRC})


# NOTE: libcurl is intentionally absent. OmafDashAccess now carries
# local_curl/local_curl.cpp, which serves the same API from the Emscripten
# virtual filesystem instead of from sockets that WebAssembly cannot open.
SET(LINK_LIB ${LINK_LIB} MediaPlayer GLU dl /Users/hasee/source/ffmpeg_wasm_lib/lib/libavcodec.a /Users/hasee/source/ffmpeg_wasm_lib/lib/libavutil.a /Users/hasee/source/ffmpeg_wasm_lib/lib/libswscale.a /Users/hasee/source/Immersive-Video-Sample/src/build/client/isolib/dash_parser/libdashparser.a /Users/hasee/source/Immersive-Video-Sample/src/build/client/360SCVP/lib360SCVP.a x264 x265 avcodec swscale swresample avformat avfilter avdevice avutil)
IF(USE_SAFE_MEM)
  SET(LINK_LIB ${LINK_LIB} safestring_shared)
ENDIF()
target_include_directories(render PRIVATE /Users/hasee/source/ffmpeg_wasm_lib/include /opt/homebrew/include)
target_link_directories(render PRIVATE /Users/hasee/source/ffmpeg_wasm_lib/lib /opt/homebrew/lib)

TARGET_LINK_LIBRARIES(render ${LINK_LIB})
