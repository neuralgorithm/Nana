CC=gcc
CFLAGS=-Wall -O2
#LIBDAEMON_STATICINC=./libdaemon/include
#LIBDAEMON_STATICLIB=./libdaemon/lib/libdaemon.a

all: nana

clean:
	nana *.o

nana: nana.c
#	$(CC) $(CFLAGS) -I$(LIBDAEMON_STATICINC) -o nana nana.c $(LIBDAEMON_STATICLIB)
	$(CC) $(CFLAGS) -o nana nana.c -ldaemon
