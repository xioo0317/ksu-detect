# ksu-detect build
#
# 本地交叉编译（Android NDK）：
#   make NDK_HOME=/path/to/ndk                 # 默认 arm64-v8a
#   make NDK_HOME=/path/to/ndk ABI=arm64-v8a
#   make NDK_HOME=/path/to/ndk ABI=armeabi-v7a
#   make NDK_HOME=/path/to/ndk ABI=x86_64
#   make all-abis NDK_HOME=/path/to/ndk
# 本机调试（gcc）：
#   make host
# 清理：
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
    CC_ABI   := $(TARGET)$(API)-clang
else ifeq ($(ABI),armeabi-v7a)
    TARGET   := armv7a-linux-androideabi
    CC_ABI   := $(TARGET)$(API)-clang
else ifeq ($(ABI),x86_64)
    TARGET   := x86_64-linux-android
    CC_ABI   := $(TARGET)$(API)-clang
else
    $(error Unsupported ABI: $(ABI))
endif

CC       := $(TOOLCHAIN)/bin/$(CC_ABI)
SRC      := src/main.c
BUILD    := build
OUT      := $(BUILD)/ksu-detect_$(ABI)

ABIS     := arm64-v8a armeabi-v7a x86_64

CFLAGS   := -Wall -Wextra -O2 -fPIE
LDFLAGS  := -pie -fPIE

.PHONY: all all-abis host clean check-ndk

all: check-ndk $(OUT)

$(OUT): $(SRC)
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(SRC)

all-abis:
	@for abi in $(ABIS); do \
		$(MAKE) ABI=$$abi NDK_HOME=$(NDK_HOME) || exit 1; \
	done

host:
	@mkdir -p $(BUILD)
	cc -Wall -Wextra -O2 -o $(BUILD)/ksu-detect_host $(SRC)

check-ndk:
	@if [ -z "$(NDK_HOME)" ]; then \
		echo "Error: NDK_HOME is not set. Use: make NDK_HOME=/path/to/ndk"; exit 1; \
	fi
	@if [ ! -x "$(CC)" ]; then \
		echo "Error: compiler not found: $(CC)"; exit 1; \
	fi

clean:
	rm -rf $(BUILD)
