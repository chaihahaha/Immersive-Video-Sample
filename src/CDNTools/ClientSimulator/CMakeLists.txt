cmake_minimum_required(VERSION 2.8)

project(ClientSimulator)

AUX_SOURCE_DIRECTORY(. DIR_SRC)

SET(DIR_SRC
    ${DIR_SRC}
)


INCLUDE_DIRECTORIES(/usr/local/include ../../utils)
LINK_DIRECTORIES(/usr/local/lib)

ADD_EXECUTABLE(ClientSimulator ${DIR_SRC} ../../utils/Log.cpp)

TARGET_LINK_LIBRARIES(ClientSimulator glog 360SCVP OmafDashAccess)
