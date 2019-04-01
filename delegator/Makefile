# Configurables
MK_FILE_PATH = $(lastword $(MAKEFILE_LIST))
PRJ_DIR      = $(abspath $(dir $(MK_FILE_PATH))/../..)
# Configurables end

TA_DEV_KIT_DIR 		= $(PRJ_DIR)/optee_os/out/arm/export-ta_arm64
TEEC_EXPORT 		= $(PRJ_DIR)/optee_client/public
HOST_CROSS_COMPILE 	= $(PRJ_DIR)/toolchains/aarch64/bin/aarch64-linux-gnu-
TA_CROSS_COMPILE	= ${HOST_CROSS_COMPILE}

CC 					= $(PRJ_DIR)/toolchains/aarch64/bin/aarch64-linux-gnu-gcc
CXX 				= $(PRJ_DIR)/toolchains/aarch64/bin/aarch64-linux-gnu-c++

BSSL_DIR 			= -I$(PRJ_DIR)/projects/bssl/src/include
BSSL_CRYPTO_DIR		= $(PRJ_DIR)/projects/bssl/src/build/crypto
BSSL_SSL_DIR 		= $(PRJ_DIR)/projects/bssl/src/build/ssl

CXXFLAGS 			= -g -std=c++11 
CXXFLAGS 			+= -I$(PRJ_DIR)/optee_client/public 
CXXFLAGS 			+= -I$(PRJ_DIR)/projects/delegator/src/ta/include
CXXFLAGS 			+= $(BSSL_DIR) -L$(BSSL_SSL_DIR) -L$(BSSL_CRYPTO_DIR) -lssl -lcrypto 
LDFLAGS				+= -lpthread
LDFLAGS 			+= -L$(PRJ_DIR)/out-br/build/optee_client-1.0/libteec -lteec

OUT_DIR				= out
TEE_SHARED_DIR		= /tmp/tee_share

all: server admin_cli ta
	cp -rf etc $(OUT_DIR)/
	cp -rf $(PRJ_DIR)/projects/bssl/src/build/tool/bssl $(OUT_DIR)
	cp -rf $(OUT_DIR) $(TEE_SHARED_DIR)/

admin_cli:
	#$(MAKE) -C admin_cli CROSS_COMPILE="$(HOST_CROSS_COMPILE)" PRJ_DIR="$(PRJ_DIR)" --no-builtin-variables
	mkdir -p $(OUT_DIR)/admin_cli
	$(CC) -o $(OUT_DIR)/admin_cli/main.o -c src/admin_cli/main.c $(CXXFLAGS) 
	$(CC) -o $(OUT_DIR)/admin_cli/admin_cli $(OUT_DIR)/admin_cli/main.o $(CXXFLAGS) $(LDFLAGS)

server:	
	mkdir -p $(OUT_DIR)/server
	$(CXX) -o $(OUT_DIR)/server/server.o -c src/server/server.c $(CXXFLAGS)
	$(CXX) -o $(OUT_DIR)/server/server $(OUT_DIR)/server/server.o $(CXXFLAGS) $(LDFLAGS)

clean:
	rm -rf out
	$(MAKE) -C src/ta clean

ta:
	mkdir -p $(OUT_DIR)/ta
	$(MAKE) -C src/ta CROSS_COMPILE="$(TA_CROSS_COMPILE)" PRJ_DIR="$(PRJ_DIR)"
	cp -rf src/ta/8aaaf200-2450-11e4-6969-696969696969.ta $(OUT_DIR)/ta/
