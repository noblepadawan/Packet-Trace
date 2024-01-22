# Example makefile for CPE464 program 1
#
# 

CC = gcc
CFLAGS = -g -Wall -fsanitize=address
#CFLAGS = -g

all:  trace

trace: trace.c
	$(CC) $(CFLAGS) -o trace trace.c checksum.c  -lpcap 

clean:
	rm -f trace
