LOCAL_PATH:= $(call my-dir)
include $(CLEAR_VARS)

80211_CSRC = print-android.c print-ascii.c util.c addrtoname.c cpack.c in_cksum.c oui.c setsignal.c packet_802_11.c

LOCAL_SRC_FILES:=\
	$(80211_CSRC)

LOCAL_CFLAGS += -DHAVE_CONFIG_H -D_U_="__attribute__((unused))"

LOCAL_C_INCLUDES += \
	external/libpcap

LOCAL_C_INCLUDES += $(JNI_H_INCLUDE) \
                    frameworks/base/include/utils \
                    frameworks/base/include/ui \
                    
LOCAL_STATIC_LIBRARIES += libpcap

LOCAL_SHARED_LIBRARIES := libcutils libutils \
    libnetutils \
    libnativehelper \
	
LOCAL_MODULE := libpcap80211
LOCAL_MODULE_TAGS := debug
LOCAL_PRELINK_MODULE := false
LOCAL_CERTIFICATE := platform
LOCAL_ARM_MODE := arm

##include $(BUILD_EXECUTABLE)
include $(BUILD_SHARED_LIBRARY)