/* client.c */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include "message.h"

int open_clientfd(char *hostname, char *port);

int main (int argc, char *argv[]) {
	int clientfd, numbytes;
	struct message msg;
	
	if (argc != 9) {
		fprintf(stderr, "usage: %s -h <host> -p <port> -o <operation> -s <shift>\n", argv[0]);
		return argc;
	}

	if ((clientfd = open_clientfd(argv[2], argv[4])) == -1) {
		perror("open_clientfd");
		exit(1);
	}

	memset(&msg, 0, sizeof(msg));
	while (fgets(msg.data, MAXDATASIZE, stdin) != NULL) {
		msg.op = (uint8_t)atoi(argv[6]);
		msg.shift = (uint8_t)atoi(argv[8]);
		msg.checksum = 0x00;
		
		if (msg.data[strlen(msg.data)-1] == '\n')
			msg.data[strlen(msg.data)-1] = '\0';

		msg.length = 64 + strlen(msg.data);

		send(clientfd, &msg, msg.length, 0);
		if ((numbytes = recv(clientfd, &msg, MAXDATASIZE+63, 0)) == -1) {
			perror("recv");
			exit(1);
		}

		msg.data[numbytes] = '\0';
		printf("client: received '%s'\n", msg.data);

		memset(&msg, 0, sizeof(msg));
		break;
	}

	close(clientfd);

	return 0;	
}

int open_clientfd(char *hostname, char *port) {
	int clientfd, gai;
	struct addrinfo hints, *listp, *p;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	if ((gai = getaddrinfo(hostname, port, &hints, &listp)) != 0) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(gai));
		return 1;
	}

	for (p = listp; p != NULL; p = p->ai_next) {
		if ((clientfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
			continue;
		}

		if (connect(clientfd, p->ai_addr, p->ai_addrlen) == -1) {
			close(clientfd);
			continue;
		}

		break;
	}

	freeaddrinfo(listp);

	if (p == NULL) {
		fprintf(stderr, "client: failed to connect\n");
		return -1;
	}
	else {
		return clientfd;
	}
}
