all : client

client : client.o
	gcc -o client client.o

client.o : client.c
	gcc -c -o client.o client.c

clean : 
	rm *.o client
