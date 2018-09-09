/* client.c */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include "message.h"

int open_clientfd(char *hostname, char *port);
uint16_t calculate_checksum(uint16_t *p);

int main (int argc, char *argv[]) {
	int clientfd, numbytes, pos, i;
	long long readbytes;
	struct message *msg, *buf;
	char c;
	char buffer[1024];
	char *host = NULL, *port = NULL, *op = NULL, *shift = NULL;
	
	if (argc != 9) {
		fprintf(stderr, "usage: %s -h <host> -p <port> -o <operation> -s <shift>\n", argv[0]);
		return argc;
	}
	
	for (i = 1; i < argc; i++) {
		if (!strncmp(argv[i], "-h", 2))
			host = argv[i+1];
		else if (!strncmp(argv[i], "-p", 2))
			port = argv[i+1];
		else if (!strncmp(argv[i], "-o", 2))
			op = argv[i+1];
		else if (!strncmp(argv[i], "-s", 2))
			shift = argv[i+1];
		else
			continue;
	}

	if ((clientfd = open_clientfd(host, port)) == -1) {
		perror("open_clientfd");
		exit(1);
	}

	msg = (struct message *)calloc(1, sizeof(struct message));
	buf = (struct message *)calloc(1, sizeof(struct message));
	memset(msg, 0, sizeof(struct message));
	msg->op = (uint8_t)atoi(op);
	msg->shift = (uint8_t)atoi(shift);

	while (1) {
		pos = 0;

		while ((c=getchar()) != EOF) {
			if (c == '\n')
				break;

			msg->data[pos] = c;
			pos++;
			if (pos >= MAXDATASIZE - 8)
				break;
		}
		if (pos > 0) {
			msg->length = htonl(pos + 8);
			msg->checksum = calculate_checksum((uint16_t *)msg);
	
			write(clientfd, msg, pos + 8);
			readbytes = 0;
			while (1) {
				memset(buffer, 0, 1024);
				numbytes = read(clientfd, buffer, 1024);
				if (numbytes == -1) {
					perror("read");
					exit(1);
				}
				memcpy(((void *)buf)+readbytes, buffer, numbytes);
				readbytes += numbytes;
				if (readbytes == 0 || readbytes >= pos + 8)
					break;
			}

			if (pos + 8 != readbytes)
				break;
	
			printf("%s", buf->data);
			fflush(stdout);
		}
		if ((pos > 0 && readbytes != pos + 8) || c == EOF)
			break;
		memset(msg->data, 0, MAXDATASIZE-7);
		memset(buf->data, 0, MAXDATASIZE-7);
		msg->checksum = 0x00;
	}
	close(clientfd);
	free(msg);
	free(buf);

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

uint16_t calculate_checksum(uint16_t *p) {
	uint32_t checksum = 0;
	int i;

	for (i = 0; i < MAXDATASIZE / sizeof(uint16_t); i++) {
		checksum += *p;
		p++;
		while (checksum >> 16)
			checksum = (checksum >> 16) + (checksum & 0xffff);
	}

	checksum = ~checksum;

	return (uint16_t)checksum;
}
