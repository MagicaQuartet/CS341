/* client.c */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>

#define MAXDATASIZE 1000

int main (int argc, char *argv[]) {
	int clientfd;
	struct addrinfo hints, *servinfo, *p;
	char buf[MAXDATASIZE];
	int gai, numbytes;
	
	if (argc != 9) {
		fprintf(stderr, "usage: %s -h <host> -p <port> -o <operation> -s <shift>\n", argv[0]);
		return argc;
	}
	
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	if ((gai = getaddrinfo(argv[2], argv[4], &hints, &servinfo)) != 0) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(gai));
		return 1;
	}

	for (p = servinfo; p != NULL; p = p->ai_next) {
		if ((clientfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
			continue;
		}

		if (connect(clientfd, p->ai_addr, p->ai_addrlen) == -1) {
			close(clientfd);
			continue;
		}

		break;
	}

	if (p == NULL) {
		fprintf(stderr, "client: failed to connect\n");
		return 2;
	}

	freeaddrinfo(servinfo);

	if ((numbytes = recv(clientfd, buf, MAXDATASIZE-1, 0)) == -1) {
		perror("recv");
		exit(1);
	}

	buf[numbytes] = '\0';

	printf("client: received '%s'\n", buf);

	close(clientfd);

	return 0;	
}
