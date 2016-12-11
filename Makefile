TARGET   = libnet.a
CLASS    = net_socket net_socket_wget net_log http_stream
SOURCE   = $(CLASS:%=%.c)
OBJECTS  = $(SOURCE:.c=.o)
HFILES   = $(CLASS:%=%.h)
OPT      = -O2 -Wall
CFLAGS   = $(OPT) -I.
LDFLAGS  = -lm -L/usr/lib
AR       = ar

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(AR) rcs $@ $(OBJECTS)

clean:
	rm -f $(OBJECTS) *~ \#*\# $(TARGET)

$(OBJECTS): $(HFILES)
