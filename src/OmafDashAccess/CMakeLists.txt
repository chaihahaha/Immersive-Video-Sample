CMAKE_MINIMUM_REQUIRED(VERSION 2.8)

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

INCLUDE_DIRECTORIES(/Users/hasee/source/emsdk/upstream/emscripten/cache/sysroot/include ../utils ../isolib)
LINK_DIRECTORIES(/Users/hasee/source/emsdk/upstream/emscripten/cache/sysroot/lib ../isolib/dash_parser ../build/client/isolib/dash_parser /Users/hasee/source/Immersive-Video-Sample/src/build/client/isolib/dash_parser/libdashparser.a)
#ADD_SUBDIRECTORY("curl")
#INCLUDE_DIRECTORIES("curl/include")
#LINK_DIRECTORIES("curl/lib")
ADD_COMPILE_OPTIONS(
    "-matomics"
    "-mbulk-memory"
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
    #"fake_curl/src/curl.cpp"
)

ADD_LIBRARY(OmafDashAccess SHARED  ${DIR_SRC} ../utils/Log.cpp ../utils/tinyxml2.cpp)

TARGET_LINK_LIBRARIES(OmafDashAccess glog)
TARGET_LINK_LIBRARIES(OmafDashAccess dashparser)
TARGET_LINK_LIBRARIES(OmafDashAccess 360SCVP)
TARGET_LINK_LIBRARIES(OmafDashAccess curl)
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
