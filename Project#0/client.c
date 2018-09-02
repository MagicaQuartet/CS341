#include <stdio.h>
#include <stdlib.h>

int main (int argc, char *argv[]) {
	int clientfd;
	char *host, *port, *operation, *shift;
	
	if (argc != 9) {
		fprintf(stderr, "usage: %s -h <host> -p <port> -o <operation> -s <shift>\n", argv[0]);
		exit(0);
	}

	host = argv[2];
	port = argv[4];
	operation = argv[6];
	shift = argv[8];

	exit(0);	
}
