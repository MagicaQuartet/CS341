#include <stdint.h>

#define MAXDATASIZE 10000000

struct message {
	uint8_t 	op;									/* 0: encrypt, 1: decrypt */
	uint8_t 	shift;							/* # of shifts */
	uint16_t 	checksum;						/* TCP checksum */
	uint32_t 	length;							/* total length of message */
	char 			data[MAXDATASIZE];	
};
