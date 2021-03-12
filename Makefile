TARGET   = libnet.a
CLASS    = net_socket http_stream
SOURCE   = $(CLASS:%=%.c)
OBJECTS  = $(SOURCE:.c=.o)
HFILES   = $(CLASS:%=%.h)
OPT      = -O2 -Wall
CFLAGS   = $(OPT) -I.
LDFLAGS  = -lm
AR       = ar

ifeq ($(NET_SOCKET_USE_SSL),1)
	CFLAGS  += -DNET_SOCKET_USE_SSL
	LDFLAGS += -lssl -lcrypto
endif

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(AR) rcs $@ $(OBJECTS)

clean:
	rm -f $(OBJECTS) *~ \#*\# $(TARGET)

$(OBJECTS): $(HFILES)
