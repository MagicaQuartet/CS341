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
int check_valid(struct message *msg);
void encrypt(char *str, uint8_t shift);
void decrypt(char *str, uint8_t shift);

int main (int argc, char *argv[]) {
	int listenfd, connfd, numbytes, readbytes;
	struct sockaddr_storage clientaddr;
	socklen_t clientlen;
	char buffer[1024];

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
			while (1) {
				readbytes = 0;
				while (1) {
					memset(buffer, 0, 1024);
					numbytes = read(connfd, buffer, 1024);
					if (numbytes == -1) {
						perror("read");
						exit(1);
					}
					memcpy(((void *)msg)+readbytes, buffer, numbytes);
					readbytes += numbytes;
					if (readbytes == 0)
						break;

					if (readbytes >= 8 && (readbytes >= ntohl(msg->length) || ntohl(msg->length) < 8 || ntohl(msg->length > MAXDATASIZE)))
						break;
				}
	
				if (check_valid(msg) || readbytes < 8 || readbytes != ntohl(msg->length)) {
					break;
				}
	
				if (msg->op == 0)
					encrypt(msg->data, msg->shift);
				else if (msg->op == 1)
					decrypt(msg->data, msg->shift);
				write(connfd, msg, ntohl(msg->length));

				memset(msg->data, 0, MAXDATASIZE-7);
			}
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

int check_valid(struct message *msg) {
	uint32_t sum = 0;
	uint16_t *p = (uint16_t *)msg;
	
	if (msg->op != 0 && msg->op != 1) {
		return -1;
	}

	if (ntohl(msg->length) < 8 || ntohl(msg->length) > MAXDATASIZE) {
		return -1;
	}

	for (int i = 0; i < MAXDATASIZE / sizeof(uint16_t); i++) {
		sum += *p;
		p++;
		while (sum >> 16)
			sum = (sum >> 16) + (sum & 0xffff);
	}

	if(sum+1 & 0xffff) {
		return -1;
	}

	return 0;
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
