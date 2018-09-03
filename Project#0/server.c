/* server.c */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>

#define BACKLOG 10
#define MAXDATASIZE 1000

int main (int argc, char *argv[]) {
	int listenfd, connfd;
	struct addrinfo hints, *servinfo, *p;
	struct sockaddr_storage clientaddr;
	socklen_t clientlen;
	int gai, yes=1;

	if (argc != 3) {
		fprintf(stderr, "usage: %s -p <port>\n", argv[0]);
		return argc;
	}

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;

	if ((gai = getaddrinfo(NULL, argv[2], &hints, &servinfo)) != 0) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(gai));
		return argc;
	}

	for (p = servinfo; p != NULL; p = p->ai_next) {
		if ((listenfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
			continue;
		}

		if (setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1) {
			perror("setsockopt");
			exit(1);
		}

		if (bind(listenfd, p->ai_addr, p->ai_addrlen) == -1) {
			close(listenfd);
			continue;
		}

		break;
	}

	freeaddrinfo(servinfo);

	if (p == NULL) {
		fprintf(stderr, "server: failed to bind\n");
		exit(1);
	}

	if (listen(listenfd, BACKLOG) == -1) {
		perror("listen");
		exit(1);
	}

	while(1) {
		clientlen = sizeof(struct sockaddr_storage);
		connfd = accept(listenfd, (struct sockaddr *)&clientaddr, &clientlen);
		if (connfd == -1) {
			continue;
		}

		if (!fork()) {
			if (send(connfd, "Hello, world!", 13, 0) != -1)
				perror("sent");
			close(connfd);
			exit(0);
		}
		close(connfd);
	}

	return 0;
}
