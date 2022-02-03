CC=gcc
CFLAGS=-ansi -Wall -Wextra -pedantic -pedantic-errors
OLEVEL=-O3
OEXTRA=-fexpensive-optimizations -flto

bin/xsli: src/xsli.c
	$(CC) $(CFLAGS) $(OEXTRA) $(OLEVEL) -s -o bin/xsli src/xsli.c

.PHONY: clean

clean:
	rm -rf bin/*
