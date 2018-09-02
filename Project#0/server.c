#include <stdio.h>
#include <stdlib.h>

int main (int argc, char *argv[]) {
	int listenfd, connfd;

	if (argc != 3) {
		fprintf(stderr, "usage: %s -p <port>\n", argv[0]);
		exit(0);
	}
}
