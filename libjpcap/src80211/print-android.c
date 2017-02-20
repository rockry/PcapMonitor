#include <android/log.h>
#include <stdio.h>
#include <string.h>
#ifndef LOG_TAG
#define LOG_TAG "Jpcap"
#define LOG_T_TAG "JpcapTrace"
#endif

#define LOGV(...) __android_log_print(ANDROID_LOG_VERBOSE, LOG_TAG, __VA_ARGS__)
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG  , LOG_TAG, __VA_ARGS__)
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO   , LOG_TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN   , LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR  , LOG_TAG, __VA_ARGS__)
#define LOGT(...) __android_log_print(ANDROID_LOG_INFO   , LOG_T_TAG, __VA_ARGS__)

#define MAX_OUTPUT_BUFFER 4096
#define MAX_TEMP_OUTPUT_BUFFER 256
#define MAX_COPY_LIMIT (MAX_OUTPUT_BUFFER - MAX_TEMP_OUTPUT_BUFFER) 
static char dbgmsgbuf[MAX_OUTPUT_BUFFER];
static char tempbuf[MAX_TEMP_OUTPUT_BUFFER];
static int curlen = 0;

int android_printf(const char *format, ...)
{
	int ret;
    va_list args;
    va_start(args, format);
	ret = vsprintf(tempbuf, format, args);
	if (curlen > MAX_COPY_LIMIT) return 0;
	memcpy(dbgmsgbuf+curlen, tempbuf, ret);
	curlen += ret;
	va_end(args);
	return ret;
}

int android_putchar(int ch)
{
	if (ch != '\0'){
		*(dbgmsgbuf+curlen) = ch; 
		curlen++;
	}
	return ch;
}

void android_printf_flush()
{
	*(dbgmsgbuf+curlen) = '\0'; 
    LOGD(dbgmsgbuf);
	curlen = 0;
}
