cmake_minimum_required(VERSION 3.16)
project(fingerprint_patient_router_cpp LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_executable(fingerprint_router main.cpp)

if(WIN32)
  target_link_libraries(fingerprint_router PRIVATE winbio bcrypt)
endif()
