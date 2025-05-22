cmake_minimum_required(VERSION 2.8)

project(isolib)

ADD_DEFINITIONS("-g -c -fPIC -std=c++20 -D_GLIBCXX_USE_CXX11_ABI=0
                -fPIE -fPIC -O2 -D_FORTIFY_SOURCE=2 -Wformat -Wno-unused-result
                 -Wformat-security -Wall ")
add_subdirectory(dash_parser)
