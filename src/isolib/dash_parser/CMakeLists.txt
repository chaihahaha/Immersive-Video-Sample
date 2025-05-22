CMAKE_MINIMUM_REQUIRED(VERSION 2.8)

option(USE_ANDROID_NDK
      "Use android ndk"
      OFF
)

PROJECT(dashparser)

AUX_SOURCE_DIRECTORY(../atoms DIR_ATOMS_SRCS)
AUX_SOURCE_DIRECTORY(../common DIR_COMMON_SRCS)
AUX_SOURCE_DIRECTORY(. DIR_DASHPARSER_SRCS)

if(NOT USE_ANDROID_NDK)
ADD_DEFINITIONS("-g -c -fPIC -std=c++20 -D_GLIBCXX_USE_CXX11_ABI=0
                -fPIE -fPIC -O2 -D_FORTIFY_SOURCE=2 -Wformat -Wno-unused-result
                 -Wformat-security -Wall ")
else()
ADD_DEFINITIONS("-g -c -fPIC -std=c++20 -D_GLIBCXX_USE_CXX11_ABI=0
                   -fPIE -fPIC -O2 -D_FORTIFY_SOURCE=2 -Wformat
                   -Wformat-security -Wall")
endif()

ADD_COMPILE_OPTIONS(
    "-matomics"
    "-mbulk-memory"
)

INCLUDE_DIRECTORIES(/usr/local/include ../include ./atoms ../common ../../utils)

LINK_DIRECTORIES(/usr/local/lib ./atoms ../common)

set(DIR_DASHPARSER_SRCS
    ${DIR_DASHPARSER_SRCS}
    ${DIR_ATOMS_SRCS}
    ${DIR_COMMON_SRCS}
   )

ADD_LIBRARY(dashparser STATIC ${DIR_DASHPARSER_SRCS})

#TARGET_LINK_LIBRARIES(dashparser glog)
