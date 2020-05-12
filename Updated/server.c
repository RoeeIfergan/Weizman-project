#include<stdio.h>
#include<netdb.h>
#include<netinet/in.h>
#include<stdlib.h>
#include<string.h>
#include<sys/socket.h>
#include<sys/types.h>
#include "../mbedtls/programs/test/roee_gcm_test.h"
//read
#include <unistd.h>
#define		KB 4

#define		MAX 1024 * KB
#define		PORT 7777
#define SA struct sockaddr

/*
	TEMP PARAMS
*/
unsigned char iv[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWd";
char currTag[] = "123123";
unsigned char key[128] = "ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWX";



//function for communicating with client
void communicate(int sock) {
	//buff is the maximum buffer limit
	char buff[MAX];

	//if reading was valid
	int valread;

	//infinite loop for waiting for clients
	printf("Waiting for data\n");
	while(1 == 1) {

		//clearing  buff
		bzero(buff,MAX);

		//read the incoming message and input into 'buff'
		valread = read(sock, buff, sizeof(buff));


		//if reading was valid
		printf("valread %d\n", valread);
		if(valread < -1 || valread == 0) {
			printf("Could not read from socket\n");
			break;
		}

		//if no data was receive
	        //valread = -1 when no data was received
	        if(valread == -1) {
	                break;
	        }


		printf("before Decrypt: %s<\n", buff);

		char * bOPs = buff;
	        int ivLength = strlen(iv);

//		Decrypt(bOPs, buff, 2048, key, 128,iv, ivLength, currTag, strlen(currTag));

	        printf("Decrypted: %s<\n", buff);


		//if message is QUIT than server closes connection
		if((strncmp(buff, "QUIT", 4)) == 0) {
                        printf("\tQuit-=-\n");
			write(sock, buff, sizeof(buff));
                        printf("Sent Quit\n");
                        break;
                }

		//if no data was received
		if(valread != -1) {
			printf("Message from client: %s\n", buff);
		}

		//sending to client same message as a response
		if(valread != -1) {
			printf("Sent Client\n");
			write(sock, buff, sizeof(buff));
		}
	printf("------\n");
	}


}

int startServer()
{

	//0 = use the Internet Protocol
	int sock = 0;

	//valread checks if reading from socket is valid
	//int valread;
	//int len;

	//make a struct named " "serv_addr" from type sockaddr_in
	//struct sockaddr_in serv_addr;
	struct sockaddr_in serv_addr;

	// socket create and varification
	//Communication type = Sock_Stream AKA (TCP)
	//AF_INET = ipv4
	//0 = use the Internet Protocol
	sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0)
	{
		printf("\n was unable to create the socket \n");
		//returning -1 stops the program from running
		return -1;
	}
	else {
		printf("Socket successfully created..\n");
	}

	//setting all the bytes in servaddr to null
	bzero(&serv_addr, sizeof(serv_addr));

	// assign IP & port to servaddr
	//AF_INET = ipv4
	//INADDR_ANY allows any ip to connect
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	serv_addr.sin_port = htons(PORT);

	//Binding socket (sock) to given IP
	if(bind(sock,(SA*)&serv_addr, sizeof(serv_addr)) != 0) {
		printf("socket binding failed\n");
		exit(0);
	}
	else
		printf("Socket successfully binded.. \n");

return sock;
}

void closeServerSock(int sock) {
	close(sock);
}


int listenToSock(int sock) {

	//valread checks if reading from socket is valid
        int valread;
        int len;

	//Listen to socket
        //backLog is the maximum queue for pending connections  available before the client receives a error message
	int backLog = 4;

	//struct sockaddr_in cli;
        struct sockaddr_in cli;

       	int gotClient = 0;

       	while(gotClient == 0) {

		//listening for connections
	        if(listen(sock,backLog) != 0) {
	                printf("Listen failed\n");
	                exit(0);
	        }
	        else
	                printf("Server is listening..\n");


	        //length of cli
	        len = sizeof(cli);


		//accepting validation
	        valread = accept(sock, (SA*)&cli, &len);

	        //accept the data packet from client
	        if(valread < 0) {
	                printf("Server accept failed");
	                return(-1);
	        }
	        else {
	                printf("Server accepted client.. \n");
	        }
	        //Function for talking to client
	        communicate(valread);
        }
	closeServerSock(sock);
	return 0;
}

int main() {
	int sock = startServer();
	listenToSock(sock);
}
