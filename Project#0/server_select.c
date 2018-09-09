/* server_select.c */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <ctype.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>

#define BACKLOG 10
#define MAXDATASIZE 10000000

struct message {
	uint8_t 	op;									/* 0: encrypt, 1: decrypt */
	uint8_t 	shift;							/* # of shifts */
	uint16_t 	checksum;						/* TCP checksum */
	uint32_t 	length;							/* total length of message */
	char 			data[MAXDATASIZE-7];	
};

int open_listenfd(char *port);
int check_valid(struct message *msg);
void encrypt(char *str, uint8_t shift);
void decrypt(char *str, uint8_t shift);

int main (int argc, char *argv[]) {
	int listenfd, connfd, numbytes, readbytes, fdmax, i;
	fd_set master;
	fd_set read_fds;
	struct sockaddr_storage clientaddr;
	socklen_t clientlen;
	char buffer[1024];

	if (argc != 3) {
		fprintf(stderr, "usage: %s -p <port>\n", argv[0]);
		return argc;
	}

	FD_ZERO(&master);			// clear master set
	FD_ZERO(&read_fds);
	
	/* call socket(), bind(), listen() functions */

	listenfd = open_listenfd(argv[2]);

	FD_SET(listenfd, &master);		// add listenfd into master set
	fdmax = listenfd;							// fdmax will be the highest value among file descriptors

	while(1) {			// main loop
		read_fds = master;					// set of file descriptors for which the server wait to read message
																// ... in this program, it is same with master set except listenfd

		if (select(fdmax+1, &read_fds, NULL, NULL, NULL) == -1) {			// after select() function returns, server can find file descriptor
			perror("select");																						// ... which is ready for doing something by calling FD_ISSET macro
			exit(1);
		} 

		for (i = 0; i <= fdmax; i++) {																// iterate file descriptors
			if (FD_ISSET(i, &read_fds)) {
				if (i == listenfd) {																											// listenfd is ready to accept new client
					clientlen = sizeof(struct sockaddr_storage);
					connfd = accept(listenfd, (struct sockaddr *)&clientaddr, &clientlen);
						
					if (connfd == -1) {
						perror("accept");
					}
					else {
						FD_SET(connfd, &master);																							// add new fd into master set
						if (connfd > fdmax)
							fdmax = connfd;
					}
				}
				else {																																		// fd connected with client is ready to read message
					struct message *msg;
					msg = (struct message *)calloc(1, sizeof(struct message));

					while (1) {

					/* read client's message */

						readbytes = 0;
						while (1) {																						// in this loop, server reads (1024byte or smaller) chunks of message from client
							memset(buffer, 0, 1024); 
							numbytes = read(i, buffer, 1024);
							if (numbytes == -1) {
								perror("read");
								close(i);
								FD_CLR(i, &master);																// error occurs, so close and remove fd i
								exit(1);
							}
							memcpy(((void *)msg)+readbytes, buffer, numbytes);
							readbytes += numbytes;
							if (readbytes == 0)																	// if there is no more chunks or connection is disconnected, escape loop
								break;

							if (readbytes >= 8 && (readbytes >= ntohl(msg->length) || ntohl(msg->length) < 8 || ntohl(msg->length) > MAXDATASIZE))
								break;																						// if the entire header is read escape loop
						}																											// ... escape loop when all message is read, length of message is invalid or there is no more space in message buf
						
						if (check_valid(msg) || readbytes < 8 || readbytes != ntohl(msg->length)) {		// if given message violate the protocol or length written in message is different from the actual one
							close(i);
							FD_CLR(i, &master);
							break;																																			// terminate this child process
						}

					/* write encrypted/decrypted message to client */

						if (msg->op == 0)
							encrypt(msg->data, msg->shift);
						else if (msg->op == 1)
							decrypt(msg->data, msg->shift);
						write(connfd, msg, ntohl(msg->length));

						memset(msg->data, 0, MAXDATASIZE-7);
						msg->checksum = 0x00;
					}	
				}
			}
		}
	}

	return 0;
}

/* helper functions */

int open_listenfd(char *port) {
	struct addrinfo hints, *listp, *p;
	int listenfd, optval=1, gai;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;

	if ((gai = getaddrinfo(NULL, port, &hints, &listp)) != 0) {														// getaddrinfo: convert information such as hostname and port number
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(gai));														// ... into socket address structures
		return 1;																																						// ... server does not need hostname because the server just waits other clients
	}

	for (p = listp; p != NULL; p = p->ai_next) {																					// iterate socket address structures to find proper one
		if ((listenfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {			// ... which can be used to call socket(), bind() and listen()
			continue;
		}

		if (setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(int)) == -1) {		// this function call eliminates "address already in use" error during bind
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
	
	if (msg->op != 0 && msg->op != 1) {																	// check op is either 0 or 
		return -1;
	}

	if (ntohl(msg->length) < 8 || ntohl(msg->length) > MAXDATASIZE) {		// check length is 8~10000000 (inclusive)
		return -1;
	}

	for (int i = 0; i < MAXDATASIZE / sizeof(uint16_t); i++) {					// check checksum is valid
		sum += *p;																												// ... split given message into 2byte chunks and add them all
		p++;
		while (sum >> 16)																									// ... if carry (beyond 2byte size) occurs
			sum = (sum >> 16) + (sum & 0xffff);															// ... add it in this manner and clear it
	}

	if(sum+1 & 0xffff) {																								// if result + 1 is not zero, checksum is invalid
		return -1;
	}

	return 0;
}

void encrypt(char *str, uint8_t shift) {
	int i;
	char c;
	for (int i = 0; i < MAXDATASIZE; i++) {
		c = str[i];
		if (c == '\0')															// end of string
			break;
		
		c = tolower(c);															// if c is uppercase, convert it into lowercase

		if (c >= 97 && c <= 122)										// if c is lowercase alphabet,
			c = 97 + (c-97+shift) % 26;								// ... shift it according to Caesar Cipher encryption

		str[i] = c;
	}
}

void decrypt(char *str, uint8_t shift) {
	int i;
	char c;
	for (int i = 0; i < MAXDATASIZE; i++) {
		c = str[i];
		if (c == '\0')															// end of string
			break;

		c = tolower(c);															// if c is uppercase, convert it into lowercase

		if (c >= 97 && c <= 122)										// if c is lowercase alphabet, shift it according to Caesar Cipher decrytion
			c = 97 + (c-97-shift >= 0 ? (c-97-shift) % 26 : (c-97-shift+26) % 26);

		str[i] = c;
	}
}