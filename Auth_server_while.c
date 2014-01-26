/*
 * Auth_server_while.c
 *
 *  Created on: Dec 5, 2012
 *  Author: Turku TUAS
 */

// gcc -m64 -o Auth_server_while Auth_server_while.c -lssl -lcrypto -lpthread -lrt

#include <string.h>
#include <errno.h>
#include <openssl/x509.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/wait.h> 
#include <arpa/inet.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <time.h>

#define BILLION  1000000000L;

#define COMM_WHILE	0x00000011

/**
 * Initialize connection to head unit
 */
int initConnect(char * strSourceIP, char * strDestIP, int serverport)
{
	int sockfd;
	struct sockaddr_in source_addr,dest_addr;

	//get the sourceip
	source_addr.sin_addr.s_addr = inet_addr(strSourceIP);
	if(source_addr.sin_addr.s_addr == INADDR_NONE) {
		printf("sourcename is unavailable!\n");
		return -1;
	}

	//get the destip
	dest_addr.sin_addr.s_addr = inet_addr(strDestIP);
	if(dest_addr.sin_addr.s_addr == INADDR_NONE) {
		printf("destname is unavailable!\n");
		return -1;
	}

	//creacte a socket
	if((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) { 
		printf("socket create error!\n");
		return -1;
	}
	
	//set the address of dest
	dest_addr.sin_family = AF_INET;
	dest_addr.sin_port = htons(serverport);
	bzero(&(dest_addr.sin_zero),8); 

	//connect the sourceip and destip
	if(connect(sockfd, (struct sockaddr *)&dest_addr,sizeof(struct sockaddr)) != 0) {
		printf("connection error!\n ");
		return -1;
	} 

	return sockfd;
}

/**
 * Sebd message to head unit
 */
int sendMessage(int socketfd, char* strSourceIP, char* strDestIP, int dwCommTYPE, int dwTransLength, char * rgbBuffer)
{
	int dwSendbytes,dwData_type,dwData_length;
	char str_send_buf[65536];

	//switch the type of the data

	//compute the whole length of the data and the head
	dwData_length = dwTransLength+40;

	//write the head to the data
	memset(str_send_buf,0,65536);

	memcpy(str_send_buf,strSourceIP,16);
	memcpy(str_send_buf+16,strDestIP,16);
	memcpy(str_send_buf+32,&dwCommTYPE,4);
	memcpy(str_send_buf+36,&dwData_length,4);
	if((dwTransLength!=0)&&(rgbBuffer!=NULL)) {
		memcpy(str_send_buf+40,rgbBuffer,dwTransLength);
	}
	
	//send the message
	if((dwSendbytes=send(socketfd, str_send_buf, dwData_length, 0)) ==-1)  {
		printf("Send error!\n");
		exit(1);
	}

	//send the message succesfully
	if(dwSendbytes == dwData_length) {
		return 0;
	}
	else {
		return -1;
	}
}


int sendTimeReset(void) {
	
	int			clientfd;
	int			dwStatus = 0;
	char		srcIP[16] = {0};
	char		rcIP[16] = {0};
	int			serverport = 3333;
	
	// IPs to copy
	char * back_srcIP = "127.0.0.1";
	char * back_rcIP = "127.0.0.1";
	
	strcpy(srcIP, back_srcIP);
	strcpy(rcIP, back_rcIP);
	
	// Init the port, send the connection request message, and receive the returned message.
	printf("\n===== Start to Communicate with HEAD UNIT =====\n");
	if (0 > (clientfd = initConnect(srcIP, rcIP, serverport))) {
		printf("===== Connect to HEAD UNIT Failed =====\n");
	} else {
		printf("===== Connect to HEAD UNIT Success =====\n");
		
		// Send I'm here message to HEAD UNIT
		if (0 != (dwStatus = sendMessage(clientfd, srcIP, rcIP, COMM_WHILE, 0, NULL))) {
			printf("===== Send message to HEAD UNIT Failed! =====\n");
		}
		
	}
	close(clientfd);
	return 0;
}

int main(void) {
	
	struct timespec start, end;
	clock_gettime(CLOCK_REALTIME, &start);
	
	int timer;
	
	while(1) {
		
		clock_gettime(CLOCK_REALTIME, &end);
		
		timer = end.tv_sec - start.tv_sec;
		
		if(timer >= 15) {
			sendTimeReset();
			clock_gettime(CLOCK_REALTIME, &start);
		}
		
	}
	
	return 0;
}
