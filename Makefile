TARGET   = libnet.a
CLASS    = net_socket net_socket_wget http_stream
ifeq ($(NET_SOCKET_USE_SSL),1)
	CLASS += net_socketSSL
endif
SOURCE   = $(CLASS:%=%.c)
OBJECTS  = $(SOURCE:.c=.o)
HFILES   = $(CLASS:%=%.h)
OPT      = -O2 -Wall
CFLAGS   = $(OPT) -I.
LDFLAGS  = -lm
AR       = ar

ifeq ($(NET_SOCKET_USE_SSL),1)
	LDFLAGS += -lssl -lcrypto
endif

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(AR) rcs $@ $(OBJECTS)

clean:
	rm -f $(OBJECTS) *~ \#*\# $(TARGET)

$(OBJECTS): $(HFILES)
