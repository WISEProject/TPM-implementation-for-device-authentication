/*
 * Auth_server.c
 *
 *  Created on: Dec 5, 2012
 *  Author: Turku TUAS
 */

// Complie: gcc -m64 -o Auth_server Auth_server.c -lssl -lcrypto -lpthread -lrt -lcurl

#include <string.h>
#include <errno.h>

#include <openssl/x509.h>
#include <openssl/sha.h>
#include <openssl/ui.h>

#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/wait.h> 
#include <arpa/inet.h>
#include <signal.h>

#include <sys/ioctl.h>
#include <linux/if.h>

#include <time.h>
#include <curl/curl.h>

//Const
#define RASERVERPORT	3333	// the num of RAServer port //
#define BACKLOG 10				// the max num of connection //

//Communication Type
#define COMM_REQ_CONNECT			0x00000001
#define COMM_RSP_ALLOW				0x00000002
#define COMM_PUB_AIK_ENROLLMENT		0x00000003
#define COMM_RSP_PUB_AIK_ENROLLMENT 0x00000004
#define COMM_REQ_CHALLENGE			0x00000005
#define COMM_RSP_CHALLENGE			0x00000006
#define COMM_QUOTE_SUCCESS			0x00000007
#define COMM_QUOTE_FAILED			0x00000008
#define COMM_TURNED_ON				0x00000009

#define COMM_WHILE	0x00000011

#define RA_RSP_ERROR_RECEIVEDATA	0x0000001C
#define RA_RSP_ERROR_READDATA		0x0000001D

// C-language does not have “primitive” byte type, so it is presentet as unsigned char
#ifndef BYTE
#define BYTE unsigned char
#endif

#ifndef UINT16
#define UINT16 unsigned short
#endif

#ifndef UINT32
#define UINT32 unsigned
#endif

#define BILLION  1000000000L;

static const char *myIP = "192.168.43.251";
static const char *destIP = "192.168.43.247";

/**
 * Deal with the thread which has been ended
 */
static void sigchld_handler(int signo)
{
	pid_t PID;
	int status;

	do {
		PID = waitpid(-1,&status, WNOHANG);
	} while(PID != -1);

	signal(SIGCHLD,sigchld_handler);
}

/**
 * 
 */
static void failhandler(const char * on_what)
{
	if (errno != 0) {
		fputs(strerror(errno),stderr);
		fputs(":",stderr);
	}
	fputs(on_what,stderr);
	fputc('\n',stderr);
	exit(1);
}

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
//		printf("connection error!\n ");
		return -1;
	} 

	return sockfd;
}

int receiveMessage(int socketfd, char* strSourceIP, int* dwCommTYPE, int * dwTransLength, char * * prgbBuffer)
{
	char * str_rcv_buf;
	int dw_rec_length, dwdata_length, type;

	//malloc some memory to receive the data
	str_rcv_buf = (char *)malloc(65536);

	//initializtion the receive buffer: str_rcv_buf
	memset(str_rcv_buf, 0, 65536);

	if(str_rcv_buf == NULL) {
		printf("malloc memory error!\n");
		return -1;
	}

	//receive the data from sourceIP
	if((dw_rec_length = recv(socketfd, str_rcv_buf, 65536, 0)) == -1)  {
		printf("Receive error!\n");
		return -2;
	}
	
	//copy the sourceIP & translength & data from the buf
	memcpy(strSourceIP, str_rcv_buf, 16);
	memcpy(&type, str_rcv_buf+32, 4);
	memcpy(&dwdata_length, str_rcv_buf+36, 4);
	
	if(dwdata_length != dw_rec_length) {
		printf("Recieved Data length error!\n");
		return -3;		
	}

	(*dwCommTYPE) = type;
	(*dwTransLength) = dwdata_length-40;
	if((*dwTransLength) > 0) {
		(*prgbBuffer) = str_rcv_buf+40;
	}
	else {
		(*prgbBuffer) = NULL;
	}
	
	return 0;	
}

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
		return -2;
//		exit(1);
	}

	//send the message succesfully
	if(dwSendbytes == dwData_length) {
		return 0;
	}
	else {
		return -1;
	}
}

static int counter = 0;

int confirmQuote(char * quoteRSP, char * aik, char * challenge)
{
	
	FILE		*f_in;
	BYTE		*quote;
	UINT32		quoteLen;
	RSA			*aikRsa;
	UINT32		selectLen;
	BYTE		*select;
	UINT32		pcrLen;
	BYTE		*pcrs;
	UINT32		sigLen;
	BYTE		*sig;
	BYTE		chalmd[20];
	BYTE		md[20];
	BYTE		qinfo[8+20+20];
	int			pcr;
	int			pcri = 0;
	int			i;

    unsigned char bytearray[strlen(quoteRSP) / 2];
    int str_len = strlen(quoteRSP);
    
    for (i = 0; i < (str_len / 2); i++) {
        sscanf(quoteRSP + 2*i, "%02X", &bytearray[i]);
    }
	
	quote = bytearray;
	quoteLen = str_len / 2;
	
	/* Hash challenge */
	SHA1 (challenge, strlen(challenge), chalmd);
	
	/* Read AIK from OpenSSL file */
	if ((f_in = fopen ("aikTEMP", "rb")) == NULL) {
		printf("Unable to open file aikrsa\n");
		exit(1);
	}
	if ((aikRsa = PEM_read_RSA_PUBKEY(f_in, NULL, NULL, NULL)) == NULL) {
		printf("Unable to read RSA file aikrsa\n");
		exit(1);
	}
	fclose (f_in);
	f_in = NULL;
	
	if (quoteLen < 2)
		return 1;
	selectLen = ntohs (*(UINT16*)quote);
	if (2 + selectLen + 4 > quoteLen) {
		return 1;
	}
	select = quote + 2;
	pcrLen = ntohl (*(UINT32*)(quote+2+selectLen));
	if (2 + selectLen + 4 + pcrLen + 20 > quoteLen) {
		return 1;
	}
	pcrs = select + selectLen + 4;
	sig = pcrs + pcrLen;
	sigLen = quote + quoteLen - sig;

	/**
	 * 	typedef struct tdTPM_QUOTE_INFO{
	 * 		TPM_STRUCT_VER version;
	 *		BYTE fixed[4];
	 *		TPM_COMPOSITE_HASH digestValue;
	 *		TPM_NONCE externalData;
	 *	} TPM_QUOTE_INFO;
	 */
	
	/* Create TPM_QUOTE_INFO struct */
	qinfo[0] = 1; qinfo[1] = 1; qinfo[2] = 0; qinfo[3] = 0;
	qinfo[4] = 'Q'; qinfo[5] = 'U'; qinfo[6] = 'O'; qinfo[7] = 'T';
	
	SHA1 (quote, 2+selectLen+4+pcrLen, qinfo+8);
	memcpy (qinfo+8+20, chalmd, 20);

	/* Verify RSA signature */
	SHA1 (qinfo, sizeof(qinfo), md);
	if (1 != RSA_verify(NID_sha1, md, sizeof(md), sig, sigLen, aikRsa)) {
		fprintf (stderr, "Error, bad RSA signature in quote\n");
		return 2;
	}

	/* Print out PCR values */
	for (pcr=0; pcr < 8*selectLen; pcr++) {
		if (select[pcr/8] & (1 << (pcr%8))) {
			printf ("%2d ", pcr);
			for (i=0; i<20; i++) {
				printf ("%02x", pcrs[20*pcri+i]);
			}
			printf ("\n");
			pcri++;
		}
	}
	fflush (stdout);
	
	free(aikRsa);
	
	return 0;
}

int autoChallenge(void)
{
	
	int			clientfd;
	int			dwStatus = 0;
	char		srcIP[16] = {0};
	char		rcIP[16] = {0};
	int			serverport = 3333;
	FILE *tempTest;
	char * buf_p;
	int readsize = 0;

	FILE *counterFile;
	char challenge[20];
	
	strcpy(srcIP, myIP);
	strcpy(rcIP, destIP);
	
	// Init the port, send the connection request message, and receive the returned message.
	printf("\n===== Auto Communication with Radio microphone =====\n");
	if (0 > (clientfd = initConnect(srcIP, rcIP, serverport))) {
		
		printf("\033[01;33m====== Radio microphone is OFF ======\033[01;37m\n");
	} else {
		
		if((counterFile = fopen("/tmp/counterText", "rb")) == NULL) {
			printf("fail\n");
			counter = 0;
		}
					
		fread(&counter, sizeof(int), 1, counterFile);
		fclose(counterFile);
		sprintf(challenge, "%02Xkoivu", counter);
		
		if(counter++ >= 250) counter = 0;
		sprintf(challenge, "%02Xkoivu", counter);
		
		if((counterFile = fopen("/tmp/counterText", "wb")) == NULL)
			printf("fail\n");

		fwrite(&counter, sizeof(int), 1, counterFile);
		fclose(counterFile);
		printf("%s \n", challenge);
		if (0 != sendMessage(clientfd, srcIP,rcIP, COMM_REQ_CHALLENGE, strlen(challenge), challenge)) {
			printf("\033[01;33m====== Radio microphone is OFF ======\033[01;37m\n");
			
		} else {
			printf("\033[01;33m====== Send Message: Random challenge ======\033[01;37m\n");
		}
	}
	
	close(clientfd);
	
	return 0;
	
}

int main(void) 
{
	printf("Starting...\n");
	
	int sock;
	int sockfd;
	int client_fd;
	struct sockaddr_in sin;
	struct ifreq ifr;
	struct sockaddr_in my_addr;					// local ip imformation //
	struct sockaddr_in remote_addr;				// client ip imformation // 
	pid_t PID;
	int type;
	int readsize = 0;
	char strRemoteIP[16];
	char * buf_p;
	char strMyIP[16] = {0};
	int kkk = 0;
	char challenge[20];
	FILE *tempTest;
	int i;

	FILE *counterFile;
	
	strcpy(strMyIP, myIP);
	
	//catch the SIGCHLD
	signal(SIGCHLD, sigchld_handler);
	
	printf("Starting to listen something from a network\n");
	
	//Create the socket
	my_addr.sin_family = AF_INET;
	my_addr.sin_port = htons(RASERVERPORT);
	my_addr.sin_addr.s_addr = INADDR_ANY;
	bzero(&(my_addr.sin_zero), sizeof(my_addr.sin_zero));
	if((sockfd = socket(AF_INET, SOCK_STREAM,0)) < 0) {
		failhandler("====== Server Create Socket error! ======\n");
	}
	
	//If the port is already used, then these two lines will make the port useable.
	struct linger sopt = {1, 0};
	setsockopt(sockfd, SOL_SOCKET, SO_LINGER, (void *)&sopt, sizeof(sopt));
	
	//Bind
	if(bind(sockfd,(struct sockaddr *)&my_addr,sizeof(my_addr))==-1) {
		failhandler("====== Server Bind error! ======\n");
	} 
	
	//Listen
	if(listen(sockfd, BACKLOG) == -1) {
		failhandler("====== Server Listen error! ======\n");
	}
	
//	clock_t startClock = clock();
	struct timespec aika, loppu;
	clock_gettime(CLOCK_REALTIME, &aika);
//	printf("%ld", (startClock / CLOCKS_PER_SEC));
	
	//Loop operation
	while(1) {
		
		//Accept return a new socket which communicate with client
		socklen_t length = sizeof(remote_addr);
		if ((client_fd = accept(sockfd, (struct sockaddr *)&remote_addr, &length)) < 0) {
			failhandler("====== Server Accept error! ======\n");
		}
		
		printf("\n--> --> Received a connection from: %s\n", inet_ntoa(remote_addr.sin_addr)); // TODO
		
		//create a new tenor request
		if((PID = fork()) == -1) {

			//child process create error
			printf("====== Fork a child proess fail! ======\n");
			close(client_fd);
			continue;
		} else if (PID > 0) {
			//father tenor deal
			close(client_fd);
			continue;
		}
		
		/*
		 *		Successfully generate a child process for a connection.
		 */
		else {
			
			//	son tenor to deal with request
			if(receiveMessage(client_fd, strRemoteIP, &type, &readsize, &buf_p) > 4) {
				printf("====== Receive error! ======\n");
				if (0 != sendMessage(client_fd, strMyIP,strRemoteIP, RA_RSP_ERROR_RECEIVEDATA, 0, NULL)) {
					printf("====== Send Response messeage to RAClient Failed! ======\n");
					close(client_fd);
					continue;
				}
				close(client_fd);
				exit(0);	
			}
			
			if(readsize < 0) {
				printf("====== The type of the connection is: %d. =====\n", type);
				printf("====== Read error! ======\n");
				printf("====== Readsize < 0, readsize is :%d ======\n",readsize);

				if (buf_p != NULL) {
					free(buf_p);
				}
				if (0 != sendMessage(client_fd, strMyIP, strRemoteIP, RA_RSP_ERROR_READDATA, 0,NULL)) {
					printf("====== Send Response messeage to RAClient Failed! ======\n");
					close(client_fd);
					exit(0);
					continue;
				}
				close(client_fd);
				exit(0);
				continue;
			}
			
			switch (type) {
			
				case COMM_WHILE:
					
					autoChallenge();
					
					break;
				
				case COMM_REQ_CONNECT:
					printf("\n--> --> Received a connection from: Radio microphone\n"); // TODO
					if (0 != sendMessage(client_fd, strMyIP,strRemoteIP, COMM_RSP_ALLOW, 0, NULL)) {
						printf("====== Send Response messeage to RAClient Failed! ======\n");
						close(client_fd);
						exit(0);
						continue;
					} else {
						printf("\033[01;34m====== Send Message: Connection is OK! ======\033[01;37m\n"); // TODO
					}
					break;
				
				case COMM_PUB_AIK_ENROLLMENT:
					printf("\n--> --> Received a connection from: Radio microphone\n"); // TODO
					
					tempTest = fopen("aikTEMP", "wb");
					fwrite(buf_p, 1, readsize, tempTest);
					fclose(tempTest);

					if(counter++ >= 250) counter = 0;
					sprintf(challenge, "%02Xkoivu", counter);
					
					if((counterFile = fopen("/tmp/counterText", "wb")) == NULL)
						printf("fail\n");

					fwrite(&counter, sizeof(int), 1, counterFile);
					
					if (0 != sendMessage(client_fd, strMyIP, strRemoteIP, COMM_REQ_CHALLENGE, strlen(challenge), challenge)) {
						printf("====== Send Response messeage to RAClient Failed! ======\n");
						close(client_fd);
						exit(0);
						continue;
					} else {
						printf("\033[22;32m====== Send Message: AIK enrollment is OK! ======\033[01;37m\n"); // TODO
						printf("\033[01;33m====== Send Message: Challenge text ======\033[01;37m\n");
					}
					
					break;
			
				case COMM_RSP_CHALLENGE:
					printf("\n--> --> Received a connection from: Radio microphone\n"); // TODO
					printf("\033[01;33m====== Received Message: Quote result ======\033[01;37m\n"); // TODO
		
					if((counterFile = fopen("/tmp/counterText", "rb")) == NULL)
						printf("fail\n");

					fread(&counter, sizeof(int), 1, counterFile);
					fclose(counterFile);
					sprintf(challenge, "%02Xkoivu", counter);
					if(0 != confirmQuote(buf_p, "ff", challenge)) {
						printf("Quote confirm failed\n");
						
						if (0 != sendMessage(client_fd, strMyIP,strRemoteIP, COMM_QUOTE_FAILED, 0, NULL)) {
							printf("====== Send Response messeage to RAClient Failed! ======\n");
							close(client_fd);
							exit(0);
							continue;
						}
					} else {
						printf("\033[22;32m====== Quote confirm success ======\033[01;37m\n"); // TODO 
						
						if (0 != sendMessage(client_fd, strMyIP,strRemoteIP, COMM_QUOTE_SUCCESS, 0, NULL)) {
							printf("====== Send Response messeage to RAClient Failed! ======\n");
							close(client_fd);
							exit(0);
							continue;
						} else {
							printf("\033[22;32m====== Send Message: Quote is OK! ======\033[01;37m\n"); // TODO
						}
						
						
					}
					
					printf("\n===========================================================================\n");
					
					break;
					
				case COMM_TURNED_ON:
					printf("\n--> --> Received a connection from: Radio microphone\n"); // TODO
						
						if(counter++ >= 250) counter = 0;
						sprintf(challenge, "%02Xkoivu", counter);
		
						if((counterFile = fopen("/tmp/counterText", "wb")) == NULL)
							printf("fail\n");

						fwrite(&counter, sizeof(int), 1, counterFile);
						fclose(counterFile);
						if (0 != sendMessage(client_fd, strMyIP,strRemoteIP, COMM_REQ_CHALLENGE, strlen(challenge), challenge)) {
							printf("====== Send Response messeage to RAClient Failed! ======\n");
							close(client_fd);
							exit(0);
							continue;
						} else {
							printf("\033[01;35m====== Receive Message: Turned on ======\033[01;37m\n");
							printf("\033[01;33m====== Send Message: Challenge text ======\033[01;37m\n");
						}
						
					break;
					
			} // Switch
			printf("\n");
			
			close(client_fd);
			exit(0);
		} // else 
		
	} // While
	
	return 0;
	
}
