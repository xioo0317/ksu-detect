cmake_minimum_required(VERSION 3.16)
project(ksu-detect-cpp VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Source files
set(SOURCES
    src/main.cpp
    src/detector.cpp
)

# Executable
add_executable(ksu-detect-cpp ${SOURCES})

# Include directories
target_include_directories(ksu-detect-cpp PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

# Compiler flags
target_compile_options(ksu-detect-cpp PRIVATE
    -Wall
    -Wextra
    -Wpedantic
    -O2
    -fPIE
)

# Linker flags
target_link_options(ksu-detect-cpp PRIVATE
    -pie
    -fPIE
)

# Android-specific: need log for Android logging
if(ANDROID)
    target_compile_definitions(ksu-detect-cpp PRIVATE ANDROID=1)
    target_link_libraries(ksu-detect-cpp PRIVATE log)
endif()

install(TARGETS ksu-detect-cpp DESTINATION bin)
