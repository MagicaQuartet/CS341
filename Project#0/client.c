/* client.c */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#define MAXDATASIZE 10000000

struct message {
	uint8_t 	op;									/* 0: encrypt, 1: decrypt */
	uint8_t 	shift;							/* # of shifts */
	uint16_t 	checksum;						/* TCP checksum */
	uint32_t 	length;							/* total length of message */
	char 			data[MAXDATASIZE-7];	
};

int open_clientfd(char *hostname, char *port);
uint16_t calculate_checksum(uint16_t *p);

int main (int argc, char *argv[]) {
	int clientfd, numbytes, pos, i;
	long long readbytes;
	struct message *msg, *buf;
	char c;
	char buffer[1024];
	char *host = NULL, *port = NULL, *op = NULL, *shift = NULL;

	/* parse arguments */
	
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

	/* call socket(), connect() function */

	if ((clientfd = open_clientfd(host, port)) == -1) {
		perror("open_clientfd");
		exit(1);
	}

	msg = (struct message *)calloc(1, sizeof(struct message));		// written message in client
	buf = (struct message *)calloc(1, sizeof(struct message));		// read message from server
	memset(msg, 0, sizeof(struct message));
	msg->op = (uint8_t)atoi(op);
	msg->shift = (uint8_t)atoi(shift);

	while (1) {		// loop until EOF is received
		
		/* write message in client */
		
		pos = 0;
		while ((c=getchar()) != EOF) {			// get one char every time, and escape if EOF is received
			if (c == '\n')										// '\n' means end of one input string
				break;													// ... so exclude from message data and escape loop

			msg->data[pos] = c;
			pos++;
			if (pos >= MAXDATASIZE - 8)				// if there is no more space in the message
				break;													// ... escape loop
		}

		if (pos > 0) {																						// when empty string is received, i.e. enter key is pressed with no string, do nothing
			msg->length = htonl(pos + 8);
			msg->checksum = calculate_checksum((uint16_t *)msg);		// calcuate checksum
	
			write(clientfd, msg, pos + 8);													// send message to server

		/* read message from server  */

			readbytes = 0;
			while (1) {																							// in this loop, client reads (1024bytes or smaller) chunks of message from server
				memset(buffer, 0, 1024);
				numbytes = read(clientfd, buffer, 1024);
				if (numbytes == -1) {
					perror("read");
					exit(1);
				}
				memcpy(((void *)buf)+readbytes, buffer, numbytes);
				readbytes += numbytes;
				if (readbytes == 0 || readbytes >= pos + 8)						// if there is no more chunk from server or no more space in the message buffer
					break;																							// ... escape loop
			}

			if (pos + 8 != readbytes)																// if size of received message is different from that of message the client sent
				break;																								// ... probably client violate the protocol during writing message (thus server's response is 0byte)
																															// ... Therefore escape outmost loop and terminate
			printf("%s", buf->data);
			fflush(stdout);
		}
		if ((pos > 0 && readbytes != pos + 8) || c == EOF)				// (the former condition seems to be almost same with the very above lines)
			break;																									// if EOF is received, terminate
		memset(msg->data, 0, MAXDATASIZE-7);											// ... otherwise fill data part of new message and message buf with 0
		memset(buf->data, 0, MAXDATASIZE-7);
		msg->checksum = 0x00;																			// ... and set checksum as 0
	}
	close(clientfd);
	free(msg);
	free(buf);

	return 0;	
}

/* helper functions */

int open_clientfd(char *hostname, char *port) {
	int clientfd, gai;
	struct addrinfo hints, *listp, *p;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	if ((gai = getaddrinfo(hostname, port, &hints, &listp)) != 0) {											// getaddrinfo: converts information such as hostname and port number
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(gai));													// ... into socket address structures
		return 1;																																					// ... results are stored in the form of linked list (listp)
	}

	for (p = listp; p != NULL; p = p->ai_next) {																				// iterate socket address structures
		if ((clientfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {		// ... find one which can be used to make a new socket
			continue;
		}

		if (connect(clientfd, p->ai_addr, p->ai_addrlen) == -1) {													// ... and connect with server
			close(clientfd);
			continue;
		}

		break;
	}

	freeaddrinfo(listp);

	if (p == NULL) {																																		// if p is NULL, client could not find proper socket address structure to use
		fprintf(stderr, "client: failed to connect\n");
		return -1;
	}
	else {
		return clientfd;																																	// ... otherwise return created socket's fd
	}
}

uint16_t calculate_checksum(uint16_t *p) {
	uint32_t checksum = 0;
	int i;

	for (i = 0; i < MAXDATASIZE / sizeof(uint16_t); i++) {
		checksum += *p;																					// split message into 2byte-chunks and add them all
		p++;
		while (checksum >> 16)																	// ... if carry (beyond 2byte size) occurs, add it in this manner
			checksum = (checksum >> 16) + (checksum & 0xffff);		// ... and clear it
	}

	checksum = ~checksum;																			// make 1's complement of the result

	return (uint16_t)checksum;
}
