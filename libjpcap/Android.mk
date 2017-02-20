LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE    := libjpcap

80211_CSRC = src80211/print-android.c src80211/print-ascii.c src80211/util.c src80211/addrtoname.c src80211/cpack.c src80211/in_cksum.c src80211/oui.c src80211/setsignal.c src80211/packet_802_11.c

LOCAL_SRC_FILES := JpcapCaptor.c JpcapSender.c JpcapWriter.c\
             packet_arp.c packet_datalink.c packet_icmp.c packet_ip.c\
             packet_ipv6.c packet_tcp.c packet_udp.c $(80211_CSRC)

	
LOCAL_CFLAGS += -DHAVE_CONFIG_H -D_U_="__attribute__((unused))"

LOCAL_PRELINK_MODULE := false
LOCAL_PACKAGE_NAME := jpcap
LOCAL_MODULE_TAGS := debug
LOCAL_CERTIFICATE := platform
LOCAL_ARM_MODE := arm


LOCAL_C_INCLUDES += \
	external/libpcap

LOCAL_C_INCLUDES += $(JNI_H_INCLUDE) \
                    frameworks/base/include/utils \
                    frameworks/base/include/ui \
                    $(LOCAL_PATH)/include \
                    $(LOCAL_PATH)/src80211 \
           
LOCAL_SHARED_LIBRARIES := libcutils libutils libc \
    libnetutils \
	libnativehelper \


	
LOCAL_STATIC_LIBRARIES := libpcap \

include $(BUILD_SHARED_LIBRARY)




