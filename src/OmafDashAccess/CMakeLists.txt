CMAKE_MINIMUM_REQUIRED(VERSION 3.5)

OPTION(USE_ANDROID_NDK
	"Use android ndk"
	OFF
)

PROJECT(OmafDashAccess)

AUX_SOURCE_DIRECTORY(. DIR_SRC)
AUX_SOURCE_DIRECTORY(OmafDashDownload/. DOWN_SRC)
AUX_SOURCE_DIRECTORY(OmafDashParser/. PARSE_SRC)
AUX_SOURCE_DIRECTORY(OmafViewportPredict/. PREDICT_SRC)

IF(USE_SAFE_MEM)
ADD_DEFINITIONS("-D_SAFE_MEM_")
ENDIF()

file(GLOB curl_sources )
#INCLUDE_DIRECTORIES(fake_curl/include)

  ADD_DEFINITIONS("-g -c -fPIC -lstdc++fs -std=c++20 -D_GLIBCXX_USE_CXX11_ABI=0
                   -fPIE -fPIC -pie -O2 -D_FORTIFY_SOURCE=2 -Wformat
                   -Wformat-security -Wall")

IF(USE_ANDROID_NDK)
  ADD_DEFINITIONS("-D_ANDROID_NDK_OPTION_")
ENDIF()

IF(USE_TRACE)
  ADD_DEFINITIONS("-D_USE_TRACE_")
ENDIF()

# NOTE: do NOT add an explicit -I to the emsdk sysroot here. emcc already supplies its
# own sysroot; adding <emsdk>/cache/sysroot/include as a plain -I hijacks stddef.h /
# math.h and makes every C++20 TU fail to compile ("no member named 'nullptr_t'").
INCLUDE_DIRECTORIES(../utils ../isolib)
LINK_DIRECTORIES(../isolib/dash_parser ${CMAKE_BINARY_DIR}/isolib/dash_parser)
#ADD_SUBDIRECTORY("curl")
#INCLUDE_DIRECTORIES("curl/include")
#LINK_DIRECTORIES("curl/lib")
ADD_COMPILE_OPTIONS(
    "-matomics"
    "-mbulk-memory"
    # Leak hunting for the wasm heap: interpose the allocator so
    # __lsan_do_leak_check() can name what is being leaked on the reader path.
    
)
ADD_LINK_OPTIONS(
    "-pthread"
    "SHELL:-s PROXY_TO_PTHREAD"
    "SHELL:-s USE_PTHREADS=1"
    "SHELL:-s FULL_ES3=1"
    "SHELL:-s MIN_WEBGL_VERSION=2"
    "SHELL:-s USE_GLFW=3"
    "SHELL:-s USE_WEBGL2=1"
    "SHELL:-s FETCH=1"
    #"SHELL:-s ASYNCIFY=1"
)

set(DIR_SRC
    ${DIR_SRC}
    ${DOWN_SRC}
    ${PARSE_SRC}
    ${PREDICT_SRC}
    # Note: fake_curl/src/curl.cpp (the emscripten_fetch shim) stays disabled.
    # It is replaced by local_curl/local_curl.cpp below.
)

# local_curl implements the libcurl subset OmafDashAccess uses directly on top of
# the Emscripten virtual filesystem. It is compiled into this library, and the
# real libcurl is deliberately NOT linked any more: the WebAssembly build has no
# usable POSIX socket backend (see commit 189987d and local_curl.cpp's header).
ADD_LIBRARY(OmafDashAccess SHARED  ${DIR_SRC} local_curl/local_curl.cpp
            ../utils/Log.cpp ../utils/tinyxml2.cpp)

TARGET_LINK_LIBRARIES(OmafDashAccess glog)
TARGET_LINK_LIBRARIES(OmafDashAccess dashparser)
TARGET_LINK_LIBRARIES(OmafDashAccess 360SCVP)
IF(USE_SAFE_MEM)
TARGET_LINK_LIBRARIES(OmafDashAccess safestring_shared)
ENDIF()
IF(NOT USE_ANDROID_NDK)
  IF(USE_TRACE)
    TARGET_LINK_LIBRARIES(OmafDashAccess trace)
    TARGET_LINK_LIBRARIES(OmafDashAccess lttng-ust)
  ENDIF()
  TARGET_LINK_LIBRARIES(OmafDashAccess dl)
ENDIF()
IF(USE_ANDROID_NDK)
  TARGET_LINK_LIBRARIES(OmafDashAccess log)
ENDIF()
target_include_directories(OmafDashAccess PRIVATE /Users/hasee/source/ffmpeg_wasm_lib/include)
target_link_directories(OmafDashAccess PRIVATE /Users/hasee/source/ffmpeg_wasm_lib/lib)

INSTALL(TARGETS OmafDashAccess
        RUNTIME DESTINATION bin
        LIBRARY DESTINATION lib
        ARCHIVE DESTINATION lib/static)

INSTALL(FILES ${PROJECT_SOURCE_DIR}/../utils/error.h DESTINATION include)
INSTALL(FILES ${PROJECT_SOURCE_DIR}/../utils/pose.h DESTINATION include)
INSTALL(FILES ${PROJECT_SOURCE_DIR}/../utils/data_type.h DESTINATION include)
INSTALL(FILES ${PROJECT_SOURCE_DIR}/../utils/ns_def.h DESTINATION include)
INSTALL(FILES ${PROJECT_SOURCE_DIR}/../utils/OmafStructure.h DESTINATION include)
INSTALL(FILES ${PROJECT_SOURCE_DIR}/../utils/common_data.h DESTINATION include)
INSTALL(FILES ${PROJECT_SOURCE_DIR}/../utils/Log.h DESTINATION include)
INSTALL(FILES ${PROJECT_SOURCE_DIR}/OmafDashAccessApi.h DESTINATION include)
INSTALL(FILES ${PROJECT_SOURCE_DIR}/OmafDashAccess.pc DESTINATION lib/pkgconfig)
