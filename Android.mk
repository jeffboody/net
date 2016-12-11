# don't include LOCAL_PATH for submodules

include $(CLEAR_VARS)
LOCAL_MODULE    := net
LOCAL_CFLAGS    := -Wall
LOCAL_SRC_FILES := net/net_socket.c net/net_socket_wget.c net/net_log.c net/http_stream.c

LOCAL_LDLIBS    := -Llibs/armeabi \
                   -llog

include $(BUILD_SHARED_LIBRARY)
