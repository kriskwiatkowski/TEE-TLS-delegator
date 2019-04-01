# Constants and makefile shit used in build
MK_FILE_PATH = $(lastword $(MAKEFILE_LIST))
PRJ_DIR      = $(abspath $(dir $(MK_FILE_PATH))/../..)
TA_KEYLESS_TZ := $(PRJ_DIR)/projects/keyless_tz
# Configurables end

NAME := keyless
CC := $(PRJ_DIR)/toolchains/aarch64/bin/aarch64-linux-gnu-gcc
CXX := $(PRJ_DIR)/toolchains/aarch64/bin/aarch64-linux-gnu-c++

BUILD_DIR = src/build
MAKE = cmake --build .

all: prepare build build-native

clean:
	rm -rf $(BUILD_DIR)

build:
	#patch -d src/ -p1 < boringssl_arm64.patch
	make -C $(BUILD_DIR)

build-native:
	rm -rf src/build.native
	mkdir -p src/build.native
	cd src/build.native; cmake ..
	cd src/build.native; make

prepare: clean
	rm -rf $(BUILD_DIR)
	mkdir -p $(BUILD_DIR)
	cd  $(BUILD_DIR); \
	CC=$(CC) CXX=$(CXX) cmake \
		-DCMAKE_BUILD_TYPE=Debug \
		-DOPENSSL_SMALL=1 \
		-DCMAKE_TOOLCHAIN_FILE=$(PRJ_DIR)/projects/bssl/aarch64.cmake \
	  	..
