/* server.c */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include "message.h"

#define BACKLOG 10

int open_listenfd(char *port);
void encrypt(char *str, uint8_t shift);
void decrypt(char *str, uint8_t shift);

int main (int argc, char *argv[]) {
	int listenfd, connfd, numbytes;
	struct sockaddr_storage clientaddr;
	socklen_t clientlen;

	if (argc != 3) {
		fprintf(stderr, "usage: %s -p <port>\n", argv[0]);
		return argc;
	}

	listenfd = open_listenfd(argv[2]);

	while(1) {
		clientlen = sizeof(struct sockaddr_storage);
		connfd = accept(listenfd, (struct sockaddr *)&clientaddr, &clientlen);
		if (connfd == -1) {
			continue;
		}

		if (!fork()) {
			struct message *msg;
			msg = (struct message *)calloc(1, sizeof(struct message));
			if ((numbytes = recv(connfd, msg, MAXDATASIZE+63, 0)) == -1) {
				perror("recv");
				exit(1);
			}

			printf("server: received '%s'\n", msg->data);
			if (msg->op == 0)
				encrypt(msg->data, msg->shift);
			else if (msg->op == 1)
				decrypt(msg->data, msg->shift);
			else
				fprintf(stderr, "op - 0: encrypt, 1: decrypt\n");
			send(connfd, msg, msg->length, 0);
			
			close(connfd);
			free(msg);
			exit(0);
		}
		close(connfd);
	}

	return 0;
}

int open_listenfd(char *port) {
	struct addrinfo hints, *listp, *p;
	int listenfd, optval=1, gai;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;

	if ((gai = getaddrinfo(NULL, port, &hints, &listp)) != 0) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(gai));
		return 1;
	}

	for (p = listp; p != NULL; p = p->ai_next) {
		if ((listenfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
			continue;
		}

		if (setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(int)) == -1) {
			perror("setsockopt");
			exit(1);
		}

		if (bind(listenfd, p->ai_addr, p->ai_addrlen) == -1) {
			close(listenfd);
			continue;
		}

		break;
	}

	freeaddrinfo(listp);

	if (p == NULL) {
		fprintf(stderr, "server: failed to bind\n");
		exit(1);
	}

	if (listen(listenfd, BACKLOG) == -1) {
		perror("listen");
		exit(1);
	}

	return listenfd;
}

void encrypt(char *str, uint8_t shift) {
	int i;
	char c;
	for (int i = 0; i < MAXDATASIZE; i++) {
		c = str[i];
		if (c == '\0')
			break;
		
		c = tolower(c);

		if (c >= 97 && c <= 122)
			c = 97 + (c-97+shift) % 26;

		str[i] = c;
	}
}

void decrypt(char *str, uint8_t shift) {
	int i;
	char c;
	for (int i = 0; i < MAXDATASIZE; i++) {
		c = str[i];
		if (c == '\0')
			break;

		c = tolower(c);

		if (c >= 97 && c <= 122)
			c = 97 + (c-97-shift >= 0 ? (c-97-shift) % 26 : (c-97-shift+26) % 26);

		str[i] = c;
	}
}
