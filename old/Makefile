CFLAGS=$(shell pkg-config --cflags --libs openssl)
all:
	gcc https.c -o main ${CFLAGS}
