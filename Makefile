# ksu-detect-cpp build system
#
# Android NDK cross-compile (recommended):
#   make NDK_HOME=/path/to/ndk                 # default arm64-v8a
#   make NDK_HOME=/path/to/ndk ABI=arm64-v8a
#   make NDK_HOME=/path/to/ndk ABI=armeabi-v7a
#   make NDK_HOME=/path/to/ndk ABI=x86_64
#   make all-abis NDK_HOME=/path/to/ndk
#
# Host build (for testing / Linux desktop):
#   make host
#   make host-cmake
#
# Clean:
#   make clean

NDK_HOME ?= $(ANDROID_NDK_HOME)
ABI      ?= arm64-v8a
API      ?= 21

UNAME_S  := $(shell uname -s)
ifeq ($(UNAME_S),Linux)
    HOST_TAG := linux-x86_64
else ifeq ($(UNAME_S),Darwin)
    HOST_TAG := darwin-x86_64
else
    HOST_TAG := windows-x86_64
endif

TOOLCHAIN := $(NDK_HOME)/toolchains/llvm/prebuilt/$(HOST_TAG)

ifeq ($(ABI),arm64-v8a)
    TARGET   := aarch64-linux-android
    CXX_ABI  := $(TARGET)$(API)-clang++
else ifeq ($(ABI),armeabi-v7a)
    TARGET   := armv7a-linux-androideabi
    CXX_ABI  := $(TARGET)$(API)-clang++
else ifeq ($(ABI),x86_64)
    TARGET   := x86_64-linux-android
    CXX_ABI  := $(TARGET)$(API)-clang++
else
    $(error Unsupported ABI: $(ABI))
endif

CXX      := $(TOOLCHAIN)/bin/$(CXX_ABI)
INCLUDES := -Iinclude
SRC_DIR  := src
BUILD    := build
OUT      := $(BUILD)/ksu-detect-cpp_$(ABI)

SRCS     := $(SRC_DIR)/main.cpp $(SRC_DIR)/detector.cpp
ABIS     := arm64-v8a armeabi-v7a x86_64

CXXFLAGS := -Wall -Wextra -O2 -std=c++17 -fPIE $(INCLUDES)
LDFLAGS  := -pie -fPIE

.PHONY: all all-abis host host-cmake clean check-ndk

all: check-ndk $(OUT)

$(OUT): $(SRCS) include/*.hpp
	@mkdir -p $(BUILD)
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -o $@ $(SRCS)

all-abis:
	@for abi in $(ABIS); do \
		$(MAKE) ABI=$$abi NDK_HOME=$(NDK_HOME) || exit 1; \
	done

host:
	@mkdir -p $(BUILD)
	g++ $(CXXFLAGS) $(LDFLAGS) -o $(BUILD)/ksu-detect-cpp_host $(SRCS)

host-cmake:
	@mkdir -p $(BUILD)/cmake
	cd $(BUILD)/cmake && cmake ../.. && make

check-ndk:
	@if [ -z "$(NDK_HOME)" ]; then \
		echo "Error: NDK_HOME is not set. Use: make NDK_HOME=/path/to/ndk"; exit 1; \
	fi
	@if [ ! -x "$(CXX)" ]; then \
		echo "Error: compiler not found: $(CXX)"; exit 1; \
	fi

clean:
	rm -rf $(BUILD)
