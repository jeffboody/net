export NET_SOCKET_USE_SSL = 1

TARGET   = wget-ssl
CLASSES  =
SOURCE   = $(TARGET).c $(CLASSES:%=%.c)
OBJECTS  = $(TARGET).o $(CLASSES:%=%.o)
HFILES   = $(CLASSES:%=%.h)
OPT      = -O2 -Wall
CFLAGS   = $(OPT) -I.
LDFLAGS  = -Lnet -lnet -Llibcc -lcc -lssl -lcrypto
CCC      = gcc

all: $(TARGET)

$(TARGET): $(OBJECTS) libcc net
	$(CCC) $(OPT) $(OBJECTS) -o $@ $(LDFLAGS)

.PHONY: libcc net

libcc:
	$(MAKE) -C libcc

net:
	$(MAKE) -C net

clean:
	rm -f $(OBJECTS) *~ \#*\# $(TARGET)
	$(MAKE) -C libcc clean
	$(MAKE) -C net clean
	rm libcc net

$(OBJECTS): $(HFILES)
