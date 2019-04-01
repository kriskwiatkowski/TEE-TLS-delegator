CFG_TEE_TA_LOG_LEVEL = 4
CPPFLAGS += -DCFG_TEE_TA_LOG_LEVEL=$(CFG_TEE_TA_LOG_LEVEL)
# The UUID for the Trusted Application
BINARY=8aaaf200-2450-11e4-6969-696969696969
TA_DEV_KIT_DIR=$(PRJ_DIR)/optee_os/out/arm/export-ta_arm64
TEEC_EXPORT=$(PRJ_DIR)/optee_client/public
HOST_CROSS_COMPILE=$(PRJ_DIR)/toolchains/aarch64/bin/aarch64-linux-gnu-
TA_CROSS_COMPILE=${HOST_CROSS_COMPILE}


-include $(TA_DEV_KIT_DIR)/mk/ta_dev_kit.mk

ifeq ($(wildcard $(TA_DEV_KIT_DIR)/mk/ta_dev_kit.mk), )
clean:
	@echo 'Note: $$(TA_DEV_KIT_DIR)/mk/ta_dev_kit.mk not found, cannot clean TA'
	@echo 'Note: TA_DEV_KIT_DIR=$(TA_DEV_KIT_DIR)'
	rm 8aaaf200-2450-11e4-6969-696969696969.*
	rm *.o
endif

#define TA_DELEGATOR_TZ_UUID \
	{ 0x8aaaf200, 0x2450, 0x11e4, \
	{ 0x69, 0x69, 0x69, 0x69, 0x69, 0x69, 0x69, 0x69}}
