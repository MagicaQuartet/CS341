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

struct client_info {
	struct message *msg;
	int readbytes;
};

int open_listenfd(char *port);
int check_valid(struct message *msg);
void encrypt(char *str, uint8_t shift);
void decrypt(char *str, uint8_t shift);

int main (int argc, char *argv[]) {
	int listenfd, connfd, numbytes, fdmax, i;
	fd_set master;
	fd_set read_fds;
	struct sockaddr_storage clientaddr;
	socklen_t clientlen;
	char buffer[1000];
	struct client_info **info;
	int size = 10;

	if (argc != 3) {
		fprintf(stderr, "usage: %s -p <port>\n", argv[0]);
		return argc;
	}

	info = (struct client_info **)calloc(size, sizeof(struct client_info *));
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
						if (connfd > fdmax) {
							fdmax = connfd;
							if (fdmax >= size) {
								size += 5;
								info = (struct client_info **)realloc(info, size*sizeof(struct client_info *));
							}
						}
						info[connfd] = (struct client_info *)calloc(1, sizeof(struct client_info));
						info[connfd]->msg = (struct message *)calloc(1, sizeof(struct message));
						memset(info[connfd]->msg, 0, sizeof(struct message));
						info[connfd]->readbytes = 0;
					}
				}
				else {																																		// fd connected with client is ready to read message

					/* read client's message */
					
					memset(buffer, 0, 1000); 
					numbytes = read(i, buffer, 1000);

					if (numbytes <= 0) {
						free(info[i]->msg);
						free(info[i]);
						close(i);
						FD_CLR(i, &master);																// error occurs, so close and remove fd i
						continue;
					}
					memcpy((void *)(info[i]->msg) + info[i]->readbytes, buffer, numbytes);
					info[i]->readbytes += numbytes;

					if (info[i]->readbytes >= 8 && ntohl(info[i]->msg->length) <= info[i]->readbytes) {
						if (check_valid(info[i]->msg)) {
							free(info[i]->msg);
							free(info[i]);
							close(i);
							FD_CLR(i, &master);
							continue;
						}
						else {

					/* write encrypted/decrypted message to client */

							if (info[i]->msg->op == 0)
								encrypt(info[i]->msg->data, info[i]->msg->shift);
							else if (info[i]->msg->op == 1)
								decrypt(info[i]->msg->data, info[i]->msg->shift);
							write(i, info[i]->msg, ntohl(info[i]->msg->length));
							memset(info[i]->msg->data, 0, MAXDATASIZE-7);
							info[i]->msg->checksum = 0x00;
							info[i]->readbytes = 0;
						}
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
