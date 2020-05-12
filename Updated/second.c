#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>
//read
#include <unistd.h>
//bzero
#include <string.h>
#if !defined(ROEE_GCM_TEST_HEADER)
#include "../mbedtls/programs/test/roee_gcm_test.h"
#include <fcntl.h>
#include <unistd.h>
#endif
#define PORT 7777
#define KB 4
#define	 MAX 1024 * KB

/*
	TEMP PARAMS
*/
unsigned char iv[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWd";
unsigned char currTag[] = "123123";

//return 0 when send successfull and did not request quit
//return 1 when requesting to quit
int sendToServer(unsigned char buffP[], int sock, unsigned char key[]) {
	//creating buffer of size MAX
	unsigned char buff[MAX];

	//if valQ is 0, do nothing, else quit <--- takes care of server not responding when client wants to quit
	int valQ = 0;


/*
==============================
	Writing to Server
==============================
*/



	//clearing buff
	bzero(buff, sizeof(buff));

	//copy data to into buffer
	strcat((char * restrict) buff, (char * restrict) buffP);

	//if user sends 'QUIT', client will send a quit command to server and wait for a reply
	if(strncmp((char * restrict)buffP, "QUIT", 4) == 0) {
		printf("Sending Quit\n");
		valQ++;
	}

	//printinf final msg before encryption
	printf("Final msg: %s<\n", buff);


/*
========================================
	Encryption here -> encrypt msg
========================================
*/
	//pointer to buffer
	unsigned char * bOP = buff;
	//iv length
	int ivLength = strlen(iv);
	Encrypt(bOP,  buff, 2048, key, 128, iv, ivLength, currTag, (int) strlen((const char *) currTag));


	//final msg encrypted
	printf("Final msg Encrypted: %s\n", buff);

	//sending the message
	write(sock, buff, sizeof(buff));


	printf("-----------------------------\n");

	//return 0 when send successfull and did not request quit
	//return 1 when requesting to quit
	return valQ;
}

//return 0 if received nothing
//return 1 if received data
//return -1 if error occurs
int receive(char ** bOP, int sock, unsigned char key[], int valQ) {


	//if valQ is 0, do nothing, else quit <--- takes care of server not responding when client wants to quit
	//if server doesn't respond to client quit request, auto quit
	if(valQ != 0) {
		printf("\nVALQ");
		return -1;
	}


	//creating buffer of size MAX
	char buff[MAX];
	//if reading was valid
	int valread;

/*
================================
	Receiving from Server
================================
*/

	//clearing buff
	bzero(buff, sizeof(buff));


	//reading buffer sent from Server in into buff
	//fcntl prevents the program from getting stuck when their is nothing to read(no data received)
	//fcntl(sock, F_SETFL, O_NONBLOCK);
	fcntl(sock, F_SETFL, O_NONBLOCK);
	valread = read(sock, buff, sizeof(buff));


	//checking if read was valid
	//valread = -1 when client doesn't get message from  server
	if(valread < -1 || valread == 0) {
		printf("Could not read from socket\n");
		return -1;
	}

	//if no data was receive
	//valread = -1 when no data was received
	if(valread == -1) {
		return 0;
	}

/*
=========================================
	Decryption here -> decrypt msg
=========================================
*/

	//pointer to buffer
	unsigned char * bOPs = buff;
	//iv length
	int ivLength = strlen(iv);
	//tag length
	int tagLength = strlen((const char *) currTag);
	//Decrypt(bOPs, (const unsigned char *)buff, 2048, key, 128,iv, ivLength, currTag, strlen(currTag));
	Decrypt(bOPs, (const unsigned char *) buff, 2048, key, 128,iv, ivLength, currTag,tagLength);
	printf("Decrypted: %s<\n", buff);

	//checking if client received a quit message
	if(strncmp(buff, "QUIT", 4) == 0) {
		printf("Received quit\n");
 		return -1;
	}

	//responding to isAlive
	if(strncmp(buff, "isAlive", 7) == 0)
		write(sock, buff, sizeof(buff));
	else {
		//when a message is received
		*bOP = buff;
		printf("Message from server %s<--\n", *bOP);
		return 1;
	}
	return 1;
}
int startClient() {
	#if defined(MBEDTLS_GCM_C)

		 //0 = use the Internet Protocol
	        int sock = 0;

	        //creating a structure named "serv_addr" from type sockaddr_in
	        struct sockaddr_in serv_addr;

	        //declaring destination ip for connection
	        //char ip[] = "192.168.1.81";
	        char ip[] = "127.0.1.1";


	        // socket create and varification
	        //Communication type = Sock_Stream AKA (TCP)
	        //AF_INET = ipv4
	        //0 = use the Internet Protocol
	        if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0)
	        {
	                printf("\n was unable to create the socket \n");
	                return -1;
	        }
	        else {
	                printf("Socket successfully created\n");

	        }

	        //inserting variables such as the type of connectio(TCP) & the port to server_addr
	        serv_addr.sin_family = AF_INET;
	        serv_addr.sin_port = htons(PORT);

	        //Convert IPv4 and IPv6 addresses from text to binary form
	        if(inet_pton(AF_INET, ip, &serv_addr.sin_addr)<=0)
	        {
	                printf("\nInvalid address/ Address not supported \n");
	                return -1;
	        }

		//checking if connection was successful
		//if connection failed
	        if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
		{
	                printf("\nConnection Failed \n");
	                return -1;
	        }
		//if connection successful
	        else
	        {
	                printf("Connection successful!\n");

	        }
        #endif
	return sock;
}

//closing socket
void closeClientSock(int sock) {
	close(sock);
}
