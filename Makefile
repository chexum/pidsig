CFLAGS=-Os -Wall
CC=diet gcc
TARGET=pidsig

all: $(TARGET)

clean:
	rm -f $(TARGET) *.o

pidsig: pidsig.o
	$(CC) $(LDFLAGS) -o $@ $<

.c.o:
	$(CC) $(CFLAGS) -c -o $@ $<


