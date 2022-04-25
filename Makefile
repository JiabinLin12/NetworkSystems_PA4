CC = gcc
#CFLAGS = -g -Wall -Werror
CFLAGS = -g -Werror

all: touchclient touchserver client server

client: client/client.c
	$(CC) $(CFLAGS) client/client.c -o client/client -lcrypto -lssl -lz
	clear
	

server: server/server.c
	$(CC) $(CFLAGS) server/server.c -o server/server -lcrypto -lssl -lz
	clear

update:
	touch client/client.c
	touch server/server.c
cleanclient:
	rm client/client
cleanserver:
	rm server/server
touchclient:
	touch client/client.c
touchserver:
	touch server/server.c
clean:
	rm server/server client/client

