/*
 * TPM_client.c
 *
 *  Created on: Nov 12, 2012
 *  Author: Turku TUAS
 */

// Compile gcc -m64 -o TPM_client TPM_client.c -ltspi -lssl -lpthread

#include <stdio.h>
#include <string.h>
#include <errno.h>

#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/ui.h>

#include <netinet/in.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/wait.h> 
#include <arpa/inet.h>
#include <signal.h>

#include <sys/ioctl.h>
#include <linux/if.h>

#include <trousers/tss.h>
#include <trousers/trousers.h>

// TPM supports 2048 length RSA keys
#define AIK_KEY_SIZE (2048/8)

// Communication Type
#define COMM_REQ_CONNECT			0x00000001 // Init connection
#define COMM_RSP_ALLOW				0x00000002 // Connection is allowed
#define COMM_PUB_AIK_ENROLLMENT		0x00000003 // Enroll public AIK to server
#define COMM_RSP_PUB_AIK_ENROLLMENT 0x00000004 // Public AIK received
#define COMM_REQ_CHALLENGE			0x00000005 // Server request challenging
#define COMM_RSP_CHALLENGE			0x00000006 // Sends Quote result to server
#define COMM_QUOTE_SUCCESS			0x00000007 // Quote is valid
#define COMM_QUOTE_FAILED			0x00000008 // Quote is invalid
#define COMM_TURNED_ON				0x00000009 // TPM Client is turned on

#define ERROR_RECEIVEDATA	0x0000001C
#define ERROR_READDATA		0x0000001D

#define CKERR	if (result != TSS_SUCCESS) goto error

#define SERVERPORT	3333	// Server port
#define BACKLOG		10		// max num of connection

// Sets IP addresses for communication. Setting this way IP addresses is not ideal, but works well.
// Setting IP addresses can do via main function arguments and that will be next thing to do.
static const char *myIP = "10.10.64.77";	// TPM client IP address
static const char *destIP = "10.10.64.78";	// Auth server IP address

/**
 * Initialise connection to the server and return socked ID.
 */
int initConnect(char * strSourceIP, char * strDestIP, int serverport)
{
	int sockfd;
	struct sockaddr_in source_addr,dest_addr;

	// Get the source ip
	source_addr.sin_addr.s_addr = inet_addr(strSourceIP);
	if(source_addr.sin_addr.s_addr == INADDR_NONE) {
		printf("source name is unavailable!\n");
		return -1;
	}

	// Get the destination ip
	dest_addr.sin_addr.s_addr = inet_addr(strDestIP);
	if(dest_addr.sin_addr.s_addr == INADDR_NONE) {
		printf("dest name is unavailable!\n");
		return -1;
	}

	// Create a socket
	if((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) { 
		printf("socket create error!\n");
		return -1;
	}
	
	// Set the address of destination
	dest_addr.sin_family = AF_INET;
	dest_addr.sin_port = htons(serverport);
	bzero(&(dest_addr.sin_zero),8); 

	// Connect the source ip and destination ip
	if(connect(sockfd, (struct sockaddr *)&dest_addr,sizeof(struct sockaddr)) != 0) {
		printf("connection error!\n ");
		return -1;
	} 

	return sockfd;
}

/**
 * Send data to server
 */
int sendMessage(int socketfd, char* strSourceIP, char* strDestIP, int dwCommTYPE, int dwTransLength, char * rgbBuffer)
{
	int dwSendbytes, dwData_type, dwData_length;
	char str_send_buf[65536]; // Max data length
	
	// Compute the whole length of the data and the head
	dwData_length = dwTransLength + 40;
	
	// Write the head to the data (sets max sending data buffer length) 
	memset(str_send_buf,0,65536);
	
	// Build all information to the data buffer
	memcpy(str_send_buf,strSourceIP,16);
	memcpy(str_send_buf+16,strDestIP,16);
	memcpy(str_send_buf+32,&dwCommTYPE,4);
	memcpy(str_send_buf+36,&dwData_length,4);
	
	// Checks is data buff valid for sending
	if((dwTransLength != 0) && (rgbBuffer != NULL)) {
		memcpy(str_send_buf+40, rgbBuffer, dwTransLength);
	}
	
	// Send the data
	if((dwSendbytes = send(socketfd, str_send_buf, dwData_length, 0)) == -1)  {
		printf("Send error!\n");
		return -2;
	}

	// Checks did data sent successfully
	if(dwSendbytes == dwData_length) {
		return 0;
	} else {
		return -1;
	}
}

/**
 * Handler received data from server.
 */
int receiveMessage(int socketfd, char* strSourceIP, int* dwCommTYPE, int * dwTransLength, char * * prgbBuffer)
{
	char *	str_rcv_buf;
	char *	ipg;
	int		dw_rec_length, dwdata_length;
	int		type;

	// Malloc some memory to receive the data
	str_rcv_buf = (char *)malloc(65536);

	// Initialisation the receive buffer: str_rcv_buf
	memset(str_rcv_buf, 0, 65536);

	if(str_rcv_buf == NULL) {
		printf("Malloc memory error!\n");
		return -1;
	}

	// Receive the data from sourceIP
	if((dw_rec_length = recv(socketfd, str_rcv_buf, 65536, 0)) == -1)  {
		printf("Receive error!\n");
		return -2;
	}
	
	// Copy the source IP
	memcpy(strSourceIP, str_rcv_buf, 16);
	// Copy connection type
	memcpy(&type, str_rcv_buf+32, 4);
	// Copy data
	memcpy(&dwdata_length, str_rcv_buf+36, 4);
	
	// Check does received data length same what server said it to be
	if(dwdata_length != dw_rec_length) {
		printf("Received Data length error!\n");
		return -3;		
	}
	
	// Return info and data via pointers
	(*dwCommTYPE) = type;
	(*dwTransLength) = dwdata_length - 40;
	if((*dwTransLength) > 0) {
		(*prgbBuffer) = str_rcv_buf + 40;
	}
	else {
		(*prgbBuffer) = NULL;
	}
	
	return 0;	
}

/**
 * This function generates attestation identity key.
 * Private and public AIK are returned via parameter pointers.
 */
int getAIK(int * pAIKLen, unsigned char * * publicAIK) {
	
	TSS_HCONTEXT	hContext;	// Context object handle
	TSS_HTPM		hTPM;		// TPM object handle
	TSS_HKEY		hSRK;		// Key object handle
	TSS_HKEY		hIdentKey;	// RSA key object handle
	TSS_HKEY		hPCAKey;	// RSA key object handle
	TSS_HPOLICY		hSrkPolicy;	// Policy object handle
	TSS_HPOLICY		hTPMPolicy;	// Policy object handle
	TSS_UUID		SRK_UUID = TSS_UUID_SRK;	// TPM address id/location in TPM
	int				result = 0;	// TPM function return code
	UINT32			initFlags = TSS_KEY_TYPE_IDENTITY | TSS_KEY_SIZE_2048  | TSS_KEY_VOLATILE | TSS_KEY_NOT_MIGRATABLE;
	BYTE			n[AIK_KEY_SIZE];	// TPM supports 2048 length RSA keys
	BYTE			*labelString;		// Secret label
	UINT32			labelLen;			// Length of the labelString
	BYTE			*rgbIdentityLabelData;		// This contains password in byte format. (This will be kinda empty because we assume no secret has set)
	UINT32			ulTCPAIdentityReqLength;	// Length of the identity label data
	BYTE			*rgbTCPAIdentityReq;		// 
	BYTE			*blob;						// Binary object, TPM handle only binary data
	UINT32			blobLen;					// Length of the blob
	FILE			*f_privateAIK;	// Private AIK file handler 
	FILE			*f_publicAIK;	// Public AIK file handler
	RSA				*rsa = NULL;	// RSA struct for getting public AIK in PEM format
	
	// First hContext is created.
	result = Tspi_Context_Create(&hContext);
	if (result != TSS_SUCCESS) {
		printf ("Error 0x%x on Tspi_Context_Create\n", result);
	} else {
		// printf("Tspi_Context_Create (hContext) success\n");
	}
	
	// Connect to TPM chip. If connection fails most likely TPM module is not turned on in BIOS.
	result = Tspi_Context_Connect(hContext, NULL);
	if (result != TSS_SUCCESS) {
		printf ("Error 0x%x on Tspi_Context_Connect\n", result);
	} else {
		// printf("Tspi_Context_Connect (hContext) success\n");
	}
	
	// Get TPM object from TPM.
	result = Tspi_Context_GetTpmObject (hContext, &hTPM);
	if (result != TSS_SUCCESS) {
		printf ("Error 0x%x on Tspi_Context_GetTpmObject\n", result);
	} else {
		// printf("Tspi_Context_GetTpmObject success (hTPM) success\n");
	}
	
	// Load SRK key to TPM based on UUID. Key is already in TPM, but this loads key to volatile memory.
	// This function also returns hSRK key object from TPM.
	result = Tspi_Context_LoadKeyByUUID(hContext, TSS_PS_TYPE_SYSTEM, SRK_UUID, &hSRK);
	if (result != TSS_SUCCESS) {
		printf ("Error 0x%x on Tspi_Context_LoadKeyByUUID for SRK\n", result);
	} else {
		// printf("Tspi_Context_LoadKeyByUUID (hSRK) success\n");
	}
    
	// Get a SRK keys policy object from SRK key.
	result = Tspi_GetPolicyObject(hSRK, TSS_POLICY_USAGE, &hSrkPolicy);
	if (result != TSS_SUCCESS) {
		printf ("Error 0x%x on Tspi_GetPolicyObject for SRK\n", result);
	} else {
		// printf("Tspi_GetPolicyObject (hSRK) success\n");
	}
	
	// Set to the SRK policy object a secret password. 
	// We can assume here that the SRK key does not have the password or any kind of secrets to set.
	// There for we set a null value.
	result = Tspi_Policy_SetSecret(hSrkPolicy, TSS_SECRET_MODE_PLAIN, 0, NULL);	
	if (result != TSS_SUCCESS) {
		printf ("Error 0x%x on Tspi_Policy_SetSecret for SRK\n", result);
	} else {
		// printf("Tspi_Policy_SetSecret (hSRK) success\n");
	}
	
	// This creates TPM policy object.
	result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_POLICY, TSS_POLICY_USAGE, &hTPMPolicy);
	if (result != TSS_SUCCESS) {
		printf ("Error 0x%x on Tspi_CreateObject for TPM policy\n", result);
	} else {
		// printf("Tspi_Context_CreateObject (hTPM) success\n");
	}
	
	// This assigns the TPM policy object to the TPM object.
	result = Tspi_Policy_AssignToObject(hTPMPolicy, hTPM);
	if (result != TSS_SUCCESS) {
		printf ("Error 0x%x on Tspi_Policy_AssignToObject for TPM\n", result);
	} else {
		// printf("Tspi_Policy_AssignToObject (hTPM) success\n");
	}
	
	// Set to TPM policy object secret. We assume there is no secret so there for a null value is set.
	result = Tspi_Policy_SetSecret(hTPMPolicy, TSS_SECRET_MODE_PLAIN, 0, NULL);
	if (result != TSS_SUCCESS) {
		printf ("Error 0x%x on Tspi_Policy_SetSecret for TPM\n", result);
	} else {
		// printf("Tspi_Policy_SetSecret (hTPM) success\n");
	}
	
	// This creates an Identity key object.
	// Note this is just a structure of the identity object.
	// This does not yet contain AIK.
	result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_RSAKEY, initFlags, &hIdentKey);
	if (result != TSS_SUCCESS) {
		printf ("Error 0x%x on Tspi_Context_CreateObject for key\n", result);
	} else {
		// printf("Tspi_Context_CreateObject (hIdentKey) success\n");
	}
	
	// Creates PCA key context object
	result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_RSAKEY, TSS_KEY_TYPE_LEGACY|TSS_KEY_SIZE_2048, &hPCAKey);
	if (result != TSS_SUCCESS) {
		printf ("Error 0x%x on Tspi_Context_CreateObject for PCA\n", result);
	} else {
		// printf("Tspi_Context_CreateObject (hPCAKey) success\n");
	}
	
	// Remember AIK key size
	memset (n, 0xff, sizeof(n));
	// Sets/defines size of the key and its modulus.
	result = Tspi_SetAttribData (hPCAKey, TSS_TSPATTRIB_RSAKEY_INFO, TSS_TSPATTRIB_KEYINFO_RSA_MODULUS, sizeof(n), n);
	if(result != TSS_SUCCESS) {
		printf("Tspi_SetAttribData (hPCAKey) fail\n");
	} else {
		// printf("Tspi_SetAttribData (hPCAKey) success\n");
	}
	
	// Sets/defines type of the key (RSA PKCS V15)
	result = Tspi_SetAttribUint32(hPCAKey, TSS_TSPATTRIB_KEY_INFO, TSS_TSPATTRIB_KEYINFO_ENCSCHEME, TSS_ES_RSAESPKCSV15);
	if (result != TSS_SUCCESS) {
		printf ("Error 0x%x on Tspi_SetAttribUint32 for PCA \n", result);
	} else {
		// printf("Tspi_SetAttribUint32 (hPCAKey) success\n");
	}
	
	// Sets secret label to key
	rgbIdentityLabelData = (BYTE *)Trspi_Native_To_UNICODE(labelString, &labelLen);
	if (rgbIdentityLabelData == NULL) {
		printf("Trspi_Native_To_UNICODE failed\n");
		result = 1;
	} else {
		// printf("Trspi_Native_To_UNICODE (IdentityLabel) success\n");
	}

	// Finally generate the AIK RSA pair
	printf ("===== Generating uniq identity key... =====\n");
	result = Tspi_TPM_CollateIdentityRequest(hTPM, hSRK, hPCAKey, labelLen,
						 rgbIdentityLabelData,
						 hIdentKey, TSS_ALG_AES,
						 &ulTCPAIdentityReqLength,
						 &rgbTCPAIdentityReq);
	if (result != TSS_SUCCESS){
		printf ("Error 0x%x on Tspi_TPM_CollateIdentityRequest\n", result);
	} else {
		// printf("Tspi_TPM_CollateIdentityRequest (TCPAIdentity) success\n");
	}
	
	// Free TPM memory
	Tspi_Context_FreeMemory (hContext, rgbTCPAIdentityReq);
	
	// Get the private key as wrapped key format
	result = Tspi_GetAttribData (hIdentKey, TSS_TSPATTRIB_KEY_BLOB, TSS_TSPATTRIB_KEYBLOB_BLOB, &blobLen, &blob);
	if (result != TSS_SUCCESS) {
		printf ("Error 0x%x on Tspi_GetAttribData for private aik blob\n", result);
	} else {
		// printf("Tspi_GetAttribData private AIK (hIdentKey) success\n");
	}
	
	// Save private AIK to file
	if((f_privateAIK = fopen("privateAIK", "wb")) == NULL) {
		printf("Open privateAIK file failed");
	}
	fwrite (blob, 1, blobLen, f_privateAIK);
	fclose(f_privateAIK); 
	
	// Now the private key can be saved to a file or to a secret place what you see is proper palace from security aspect.
	// Remember to free memory. Blob variable will be used for another function.
	Tspi_Context_FreeMemory (hContext, blob);
	
	// Get the public key with no certificate in PEM format
	result = Tspi_GetAttribData (hIdentKey, TSS_TSPATTRIB_KEY_BLOB, TSS_TSPATTRIB_KEYBLOB_PUBLIC_KEY, &blobLen, &blob);
	if (result != TSS_SUCCESS) {
		printf ("Error 0x%x on Tspi_GetAttribData for private aik blob\n", result);
	} else {
		// printf("Tspi_GetAttribData public AIK (hIdentKey) success\n");
	}
	
	// Open public AIK file for saving
	if((f_publicAIK = fopen("publicAIK", "wb")) == NULL) {
		printf("Open publicAIK file failed");
	}
	
	// Extract the RSA bits from the public key  
	rsa = RSA_new();
	rsa->n = BN_bin2bn (blob+blobLen-256, 256, NULL);
	rsa->e = BN_new();
	BN_set_word (rsa->e, 0x10001);
	
	// Save public AIK to file
	if (PEM_write_RSA_PUBKEY(f_publicAIK, rsa) < 0) {
		fprintf (stderr, "Unable to write to public key file ");
		RSA_free (rsa);
		result = 1;
	}
	fclose(f_publicAIK);
	RSA_free(rsa);
	
	// "returns" public AIK via pointer
	*pAIKLen = blobLen;
	(*publicAIK) = blob;
	
	// Remember to free TPM memory.
	Tspi_Context_FreeMemory (hContext, blob);
	
	return 0;
}

/**
 * This is function is for hashing a challenge and getting digest value from the hash.
 * Digest value is 20 bit length.
 * C-language does not have a standard library for hashing so we can use TPM for hashing.
 */
static void sha1(TSS_HCONTEXT hContext, void *buf, UINT32 bufLen, BYTE *digest)
{
	TSS_HHASH	hHash;
	BYTE		*tmpbuf;
	UINT32		tmpbufLen;

	Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_HASH, TSS_HASH_DEFAULT, &hHash);
	Tspi_Hash_UpdateHashValue(hHash, bufLen, (BYTE *)buf);
	Tspi_Hash_GetHashValue(hHash, &tmpbufLen, &tmpbuf);
	memcpy (digest, tmpbuf, tmpbufLen);
	Tspi_Context_FreeMemory(hContext, tmpbuf);
	Tspi_Context_CloseObject(hContext, hHash);
}

/**
 * Make quote
 */
int quote(int chalLen, unsigned char * challenge, int * quoteLen, unsigned char * * quoteBuf) 
{
	
	TSS_HCONTEXT	hContext;	// Context object handle
	TSS_HTPM		hTPM;		// TPM object handle
	TSS_HKEY		hSRK;		// SRK key object handle
	TSS_HKEY		hAIK;		// AIK key object handle
	TSS_HPOLICY		hSrkPolicy;	// Policy object handle
	TSS_HPOLICY		hAIKPolicy;	// Policy object handle
	TSS_HPCRS		hPCRs;		// PCR object handle
	TSS_UUID		SRK_UUID = TSS_UUID_SRK;	// TPM address id/location in TPM
	TSS_VALIDATION	valid;		// Quote-function insert quote-result to this object 
	TPM_QUOTE_INFO	*quoteInfo;	// Quote info object, this includes information to be quoted
	BYTE			srkSecret[] = TSS_WELL_KNOWN_SECRET; // We assume that TPM has no secrets set
	FILE			*f_in;		// Read from file
	FILE			*f_out;		// Write to file
	UINT32			tpmProp;	// TPM Capability properties request value code
	UINT32			npcrMax;	// Count how many PCR register slots TPM have
	UINT32			npcrBytes;	// TPM PCR values
	BYTE			*buf;		// Data buffer variable
	UINT32			bufLen;		// Data buffer length
	BYTE			*bp;		// List of PCR register values
	BYTE			*tmpbuf;	// TPM data buffer 
	UINT32			tmpbufLen;	// TPM data length
	BYTE			chalmd[20];	// Digest of the challenge hash
	BYTE			pcrmd[20];	// PCR digest value
	int				i;			// This is just for for-loops
	int				result;		// TPM function return code
	long 			pcr;		// PCR slot to be hashed 
	
	// First hContext is created.
	result = Tspi_Context_Create(&hContext); CKERR;
	
	// Connect to TPM chip. If connection fails most likely TPM module is not turned on in BIOS.
	result = Tspi_Context_Connect(hContext, NULL); CKERR;
	
	// Load SRK key to TPM based on UUID.
	// Key is already in TPM, but this loads key to volatile memory.
	// This function also returns hSRK key object from TPM.
	result = Tspi_Context_LoadKeyByUUID(hContext, TSS_PS_TYPE_SYSTEM, SRK_UUID, &hSRK); CKERR;
	
	// Get a SRK keys policy object from SRK key.
	result = Tspi_GetPolicyObject (hSRK, TSS_POLICY_USAGE, &hSrkPolicy); CKERR;
	
	// Set to the SRK policy object a secret password.
	// We can assume here that the SRK key does not have a password or any kind of secrets to set.
	// There for we set a null value.
	result = Tspi_Policy_SetSecret(hSrkPolicy, TSS_SECRET_MODE_PLAIN, 0, NULL); CKERR;
	
	// Get a TPM object from the TPM.
	result = Tspi_Context_GetTpmObject (hContext, &hTPM); CKERR;

	// Read AIK blob from the file
	if ((f_in = fopen("privateAIK", "rb")) == NULL) {
		fprintf (stderr, "Unable to open file privateAIK\n");
		exit (1);
	}
	fseek (f_in, 0, SEEK_END);
	bufLen = ftell (f_in);
	fseek (f_in, 0, SEEK_SET);
	buf = malloc (bufLen);
	if (fread(buf, 1, bufLen, f_in) != bufLen) {
		fprintf (stderr, "Unable to readn file privateAIK\n");
		exit (1);
	}
	fclose (f_in);
	
	// Load buffered private AIK variable to the TPM.
	// LoadKeyByBlob function returns a AIK handler struct object for later use.
	result = Tspi_Context_LoadKeyByBlob (hContext, hSRK, bufLen, buf, &hAIK); CKERR;
	free (buf);

	// Create PCR list to be quoted
	tpmProp = TSS_TPMCAP_PROP_PCR;
	result = Tspi_TPM_GetCapability(hTPM, TSS_TPMCAP_PROPERTY, sizeof(tpmProp), (BYTE *)&tpmProp, &tmpbufLen, &tmpbuf); CKERR;
	
	// Converts tpmbuf to count of register what the TPM has.
	npcrMax = *(UINT32 *)tmpbuf;
	Tspi_Context_FreeMemory(hContext, tmpbuf);
	
	// Next line converts the pcrMax variable to a BYTE format.
	npcrBytes = (npcrMax + 7) / 8;
	
	// Create PCRs struct object.
	result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_PCRS, TSS_PCRS_STRUCT_INFO, &hPCRs); CKERR;
	
	// Initialise the buffer variable array length for later use.
	// This will be used for quote validation.
	buf = malloc (2 + npcrBytes + 4 + 20 * npcrMax);
	*(UINT16 *)buf = htons(npcrBytes);
	for (i=0; i<npcrBytes; i++) {
		buf[2+i] = 0;
	}
	
	// The PCR register position to be hashed.
	// PCRs 1 - 5 SHOULD not be selected because those are reserved for other TPM functionalities.
	// PCRs 6 - 16 CAN be selected.
	pcr = 6;
	result = Tspi_PcrComposite_SelectPcrIndex(hPCRs, pcr); CKERR;
	buf[2+(pcr/8)] |= 1 << (pcr%8);
	
	// Creates a hash digest from the clear challenge text.
	sha1 (hContext, challenge, (UINT32) chalLen, chalmd);
	
	// Create a TSS_VALIDATION struct for quote. 
	// The challenge hash digest length and the data are set to a valid struct.
	// This will contain the result of the quote.
	valid.ulExternalDataLength = sizeof(chalmd);
	valid.rgbExternalData = chalmd;
	
	// Execute the Quote command.
	// Quoting need the TPM object, private AIK, PCRs handler object and struct object 
	// where to save the quote result and that is TSS_VALIDATION struct.
	result = Tspi_TPM_Quote(hTPM, hAIK, hPCRs, &valid); CKERR;
	
	/**
	 * 	typedef struct tdTPM_QUOTE_INFO{
	 * 		TPM_STRUCT_VER version;
	 *		BYTE fixed[4];
	 *		TPM_COMPOSITE_HASH digestValue;
	 *		TPM_NONCE externalData;
	 *	} TPM_QUOTE_INFO;
	 */
	// Converts quote result from valid struct to TPM QUOTE INFO type.
	quoteInfo = (TPM_QUOTE_INFO *)valid.rgbData;

	// Get all PCR values from the TPM.
	bp = buf + 2 + npcrBytes;
	*(UINT32 *)bp = htonl (20);
	bp += sizeof(UINT32);
	for (i=0; i<npcrMax; i++) {
		if (buf[2+(i/8)] & (1 << (i%8))) {
			result = Tspi_PcrComposite_GetPcrValue(hPCRs, i, &tmpbufLen, &tmpbuf); CKERR;
			memcpy (bp, tmpbuf, tmpbufLen);
			bp += tmpbufLen;
			Tspi_Context_FreeMemory(hContext, tmpbuf);
		}
	}
	bufLen = bp - buf;
	
	// Free TPM capability buffer
	Tspi_Context_FreeMemory(hContext, tmpbuf);

	// The Client should validate quote result before sending result to the Server.
	sha1 (hContext, buf, bufLen, pcrmd);
	if (memcmp (pcrmd, quoteInfo->compositeHash.digest, sizeof(pcrmd)) != 0) {
		// Try with smaller digest length
		*(UINT16 *)buf = htons(npcrBytes-1);
		memmove (buf+2+npcrBytes-1, buf+2+npcrBytes, bufLen-2-npcrBytes);
		bufLen -= 1;
		sha1 (hContext, buf, bufLen, pcrmd);
		if (memcmp (pcrmd, quoteInfo->compositeHash.digest, sizeof(pcrmd)) != 0) {
			fprintf (stderr, "Inconsistent PCR hash in output of quote\n");
			exit (1);
		}
	}
	
	// Create output file
	if ((f_out = fopen ("quote_file.quote", "wb")) == NULL) {
		fprintf (stderr, "Unable to create filequote_file\n");
		exit (1);
	}
	// PCR values
	if (fwrite (buf, 1, bufLen, f_out) != bufLen) {
		fprintf (stderr, "Unable to write to file quote_file\n");
		exit (1);
	}
	// Quote validation data, quote signature
	if (fwrite (valid.rgbValidationData, 1, valid.ulValidationDataLength, f_out) != valid.ulValidationDataLength) {
		fprintf (stderr, "Unable to write to file quote_file\n");
		exit (1);
	}
	fclose (f_out);
	
	
	// Close TPM session
	Tspi_Context_Close(hContext);

	return 0;
	
	error:
		fprintf (stderr, "Failure, error code: 0x%x\n", result);
		return 1;
}

/**
 * Deal with the thread which has been ended
 */
static void sigchld_handler(int signo)
{
	pid_t PID;
	int status;

	do {
		PID = waitpid(-1,&status, WNOHANG);
	} while(PID!=-1);

	signal(SIGCHLD,sigchld_handler);
}

/**
 * This function is executed when the server challenging TPM Client.
 * This function opens new connection to the server.
 */
int newChallengeConnect(int chalLen, unsigned char * challenge) 
{
	int		clientfd;				// Connection session id with server
	char	tpmClientIP[16] = {0};	// TPM Client ip address
	char	serverIP[16] = {0};		// Server IP address
	int		serverport = SERVERPORT;		// Network port
	int		i;						// Floor loop iteration count
	
	int				quoteLen;	// Length of the quote data
	unsigned char * quoteBuf;	// Quote data, but this data is broken atm
	FILE			*testFile;	// Quote file handler
	int				bufLen;		// Quote data length
	unsigned char	*buf;		// Quote data
	
	char	*buf_str;	// This will contain quote data in hex-format.
	char	*buf_ptr;	// Used for printing quote.
	int		size;				
	
	strcpy(tpmClientIP, myIP);
	strcpy(serverIP, destIP);
	
	
	printf("===== Received message from HEAD UNIT: Challenge requested =====\n");
	printf("\033[01;34m ===== Challenge string: %s ======\033[01;37m\n", challenge);	
	// quoteBuff is not atm used because quote data will broke if it is copied to new location.
	// There for quote is saved to the file in quote-function and read from there in this function.
	if(0 == quote(chalLen, challenge, &quoteLen, &quoteBuf)) {
		if((testFile = fopen("quote_file.quote", "rb")) == NULL) {
			printf("Quote open failed");
		}
		fseek (testFile, 0, SEEK_END);
		bufLen = ftell (testFile);
		fseek (testFile, 0, SEEK_SET);
		buf = malloc (bufLen);
		if (fread(buf, 1, bufLen, testFile) != bufLen) {
			fprintf (stderr, "Unable to read file: quote\n");
			exit (1);
		}
		fclose (testFile);
		
		// Print quote data in hex-format
		size = sizeof(buf) / sizeof(char);
		size = bufLen;
		buf_str = (char*) malloc(2 * size + 1), buf_ptr = buf_str;
		if (buf_str) {
			for (i = 0; i < size; i++) {
				buf_ptr += sprintf(buf_ptr, "%02X", buf[i]);
				printf("%02X", buf[i]);
				if(i%15 == 1 && i != 1) {
					printf("%02X ", buf[i]);
        	                        printf("\n");
	                        } else {
					printf("%02X ", buf[i]);
				}
				
				
			}
			printf("\n");
		}
	} else {
		printf("Quote failed");
		return 1;
	}
	
	// Init the port, send the connection request message, and receive the returned message.
	if (0 > (clientfd = initConnect(tpmClientIP, serverIP, serverport))) {
		
	} else {
		// Send the quote data to the server.
		if (0 != sendMessage(clientfd, tpmClientIP,serverIP, COMM_RSP_CHALLENGE, strlen(buf_str), buf_str)) {
			printf("\033[01;33m====== Send Message to HEAD UNIT: failed ======\033[01;37m\n");
		} else {
			printf("\033[01;33m====== Send Message to HEAD UNIT: Quote result ======\033[01;37m\n");
		}
	}
	
	// Close connection session to the server.
	close(clientfd);
	
	return 0;
}

/**
 * Loop mode is for server communication. TPM Client will wait request from server.
 * Server will challenge the TPM Client to assure the TPM Client is on.
 */
int loopMode() 
{
	int		sockfd;
	int		client_fd;					// Connection session id with server
	struct	sockaddr_in my_addr;		// TPM Client IP information
	struct	sockaddr_in remote_addr;	// Server IP information
	pid_t	PID;						// Process id
	int		type;						// Received connection type
	int		readsize = 0;				// Length of the received data
	char	strRemoteIP[16];
	char *	buf_p;
	char	strMyIP[16] = {0};			// TPM Client IP address
	FILE	*tempTest;
	int		i;							// For loop iteration count
	
	strcpy(strMyIP, myIP);
	
	// Catch the SIGCHLD
	signal(SIGCHLD, sigchld_handler);
	
	printf("Starting to listen something from a network\n\n");
	
	// Create the socket
	my_addr.sin_family = AF_INET;
	my_addr.sin_port = htons(SERVERPORT);
	my_addr.sin_addr.s_addr = INADDR_ANY;
	bzero(&(my_addr.sin_zero), sizeof(my_addr.sin_zero));
	if((sockfd = socket(AF_INET, SOCK_STREAM,0)) < 0) {
		printf("====== Server Create Socket error! ======\n");
	}
	
	// If the port is already used, then these two lines will make the port usable.
	struct linger sopt = {1, 0};
	setsockopt(sockfd, SOL_SOCKET, SO_LINGER, (void *)&sopt, sizeof(sopt));
	
	// Bind
	if(bind(sockfd,(struct sockaddr *)&my_addr,sizeof(my_addr))==-1) {
		printf("====== Server Bind error! ======\n");
	} 
	
	// Listen
	if(listen(sockfd, BACKLOG) == -1) {
		printf("====== Server Listen error! ======\n");
	}
	
	// Loop operation for different connection types
	while(1) {
		
		// Accept return a new socket which communicate with client
		socklen_t length = sizeof(remote_addr);
		if ((client_fd = accept(sockfd, (struct sockaddr *)&remote_addr, &length)) < 0) {
			printf("====== Server Accept error! ======\n");
		} else {
			
		}
		
		// Create a new tenor request
		if((PID = fork()) == -1) {
			printf("====== Create child process fail! ======\n");
			// Close connection session to the server before it actually started.
			close(client_fd);
			continue;
		} else if (PID > 0) {
			// Parent tenor deal, close connection session to the server before it actually started.
			close(client_fd);
			continue;
		}
		
		// Successfully generated a child process for a connection.
		else {
			
			//	Child tenor to deal with request
			if(receiveMessage(client_fd, strRemoteIP, &type, &readsize, &buf_p) > 4) {
				printf("====== Receive error! ======\n");
				
				// Send data receive error message to the server.
				if (0 != sendMessage(client_fd, strMyIP,strRemoteIP, ERROR_RECEIVEDATA, 0, NULL)) {
					printf("====== Send Response message to Server Failed! ======\n");
					close(client_fd);
					continue;
				}
				close(client_fd);
				exit(0);	
			} else {
				
			}
			
			if(readsize < 0) {
				printf("====== The type of the connection is: %d. =====\n", type);
				printf("====== Read error! ======\n");
				
				if (buf_p != NULL) {
					free(buf_p);
				}
				// Send data receive error message to the server.
				if (0 != sendMessage(client_fd, strMyIP,strRemoteIP, ERROR_READDATA, 0,NULL)) {
					printf("====== Send Response message to Server Failed! ======\n");
					close(client_fd);
					exit(0);
					continue;
				}
				
				// Closes connection session to the server.
				close(client_fd);
				exit(0);
				continue;
			} else {
				// printf("", strRemoteIP);
			}
			
			// Process based on requested connection type from server.
			switch (type) {
				
				// Inform to the server that connection is allowed and open
				case COMM_REQ_CONNECT:
					printf("\n--> --> Received a connection from: Head Unit\n"); // 
					if (0 != sendMessage(client_fd, strMyIP,strRemoteIP, COMM_RSP_ALLOW, 0, NULL)) {
						printf("====== Send Response message to Server Failed! ======\n");
						close(client_fd);
						exit(0);
						continue;
					} else {
						printf("\033[01;34m====== Send Message: Connection is OK! ======\033[01;37m\n"); // 
					}
					break;
				
				// Server challenged the TPM Client
				case COMM_REQ_CHALLENGE:
					
					// Process requested challenge and opens new connection to the server.
					newChallengeConnect(readsize, buf_p);
					
					break;
				
				// Quote confirmation success on server side.
				case COMM_QUOTE_SUCCESS:
					printf("===== Received message from HEAD UNIT: Quote Success! =====\n");
					
					break;
				
				// Quote confirmation failed on server side.
				case COMM_QUOTE_FAILED:
					printf("=====  Server said that Quote failed =====\n");
					
					break;
					
			} // Switch
			printf("\n");
			
			// Close the connection session to the server.
			close(client_fd);
			exit(0);
		} // Else 
		
	} // While
	
	return 0;
}

/**
 * No arguments yet needed.
 */
int main(void) {
	
	int				clientfd;				// Connection session id with server
	char			serverIP[16] = {0};		// Server IP address
	char			tpmClientIP[16] = {0};	// TPM Client IP address
	int				serverport = SERVERPORT;		
	int				dwStatus = 0;		
	int				dwTransLength = 0;	
	char			*buffer = NULL;		// Received data from the server
	int				type;				// Connection type code
	int				result;				// Result code of the function
	unsigned char	*aik;				// AIK blob
	int				aikLen;				// AIK length
	FILE			*testFile;
	int				quoteLen;			// Quote length
	unsigned char * quoteBuf;			// Quote data
	int				i;					// For loop iteration count
	int				bufLen;				//
	unsigned char	*buf;				
	
	// IPs to copy. This need to be done every time when new connection is made to the server.
	// Some reason these will be cleared when connection session is closed.
	strcpy(tpmClientIP, myIP);
	strcpy(serverIP, destIP);
	
	// Init the port, send the connection request message, and receive the returned message.
	printf("\n===== Start to Communicate with HEAD UNIT =====\n");
	if (0 > (clientfd = initConnect(tpmClientIP, serverIP, serverport))) {
		printf("===== Connect to HEAD UNIT Failed =====\n");
	} else {
		printf("===== Connect to HEAD UNIT Success =====\n");
	}
	
	// Send I'm here message to the server
	if (0 != (dwStatus = sendMessage(clientfd, tpmClientIP, serverIP, COMM_REQ_CONNECT, 0, NULL))) {
		printf("===== Send message to HEAD UNIT Failed! =====\n");
	}
	
	// Receive message from the server
	if (0 != (dwStatus = receiveMessage(clientfd, serverIP, &type, &dwTransLength, &buffer))) {
		printf("===== Received message from HEAD UNIT Failed! =====\n");
	}
	
	if(type == COMM_RSP_ALLOW) {
		close(clientfd);
		printf("===== Received Message from HEAD UNIT: Connection allowed =====\n");
	} else {
		printf("===== Connection failed =====\n");
	}
	
	// Close connection session to the server.
	close(clientfd);
	
	strcpy(tpmClientIP, myIP);
	strcpy(serverIP, destIP);
	
	// Start new connection session to server.
	if (0 > (clientfd = initConnect(tpmClientIP, serverIP, serverport))) {
		printf("===== Connect to HEAD UNIT Failed =====\n");
	}
	
	// Checks has the TPM Client done Enrolment before. 
	FILE *enrolled;
	if((enrolled = fopen("ennrolledAIKdone", "rb")) != NULL) {
		fseek (enrolled, 0, SEEK_END);
		bufLen = ftell (enrolled);
		fseek (enrolled, 0, SEEK_SET);
		buf = malloc (bufLen);
		if (fread(buf, 1, bufLen, enrolled) != bufLen) {
			exit (1);
		}
		fclose (enrolled);
	} else {
		buf = "0";
		bufLen = 1;
	}
	
	if(strncmp(buf, "1", bufLen) != 0) {
		printf("\n");
		
		// If TPM Client starts first time, it needs to make AIK.
		result = getAIK(&aikLen, &aik);
		
		// Enroll AIK to the server. This need to be done once if the TPM Client don't make new AIK.
		if(result == 0) {
			testFile = fopen("publicAIK", "rb");
			fseek (testFile, 0, SEEK_END);
			bufLen = ftell (testFile);
			fseek (testFile, 0, SEEK_SET);
			buf = malloc (bufLen);
			if (fread(buf, 1, bufLen, testFile) != bufLen) {
				exit (1);
			}
			fclose (testFile);
			
			enrolled = fopen("ennrolledAIKdone", "wb");
			fwrite("1", 1, 1, enrolled);
			fclose(enrolled);
			
			// Send public AIK to HEAD UNIT
			if (0 != (dwStatus = sendMessage(clientfd, tpmClientIP, serverIP, COMM_PUB_AIK_ENROLLMENT, bufLen, buf))) {
				printf("===== Send AIK message to HEAD UNIT Failed! =====\n");
			} else {
				printf("===== Send Message to HEAD UNIT: Enroll Public AIK =====\n");
			}
			
		} else {
			
		}
	} else {
		
		testFile = fopen("publicAIK", "rb");
		fseek (testFile, 0, SEEK_END);
		bufLen = ftell (testFile);
		fseek (testFile, 0, SEEK_SET);
		buf = malloc (bufLen);
		if (fread(buf, 1, bufLen, testFile) != bufLen) {
			exit (1);
		}
		fclose (testFile);
		
		// Send turn on message
		if (0 != (dwStatus = sendMessage(clientfd, tpmClientIP, serverIP, COMM_TURNED_ON, 0, NULL))) {
			printf("===== Send AIK message to HEAD UNIT Failed! =====\n");
		} else {
			printf("\n===== Send Message to HEAD UNIT: Turned on =====\n");
		}
	}
	
	// Receive message from the server
	if (0 != (dwStatus = receiveMessage(clientfd, serverIP, &type, &dwTransLength, &buffer))) {
		printf("===== Received message from HEAD UNIT Failed! =====\n");
	}
	
	if(type == COMM_REQ_CHALLENGE) {
		close(clientfd);
		
		strcpy(tpmClientIP, myIP);
		strcpy(serverIP, destIP);
		
		printf("===== Received message from HEAD UNIT: Challenge requested =====\n");
		
		// Produce TPM quote
		// quoteBuff is not atm used because quote data will broke if it is copied to new location.
		// There for quote is saved to the file in quote-function and read from there in this function.
		if(0 == quote(dwTransLength, buffer, &quoteLen, &quoteBuf)) {
			
			if (0 > (clientfd = initConnect(tpmClientIP, serverIP, serverport))) {
				printf("===== Connect to HEAD UNIT Failed =====\n");
			}
			
			testFile = fopen("quote_file.quote", "rb");
			fseek (testFile, 0, SEEK_END);
			bufLen = ftell (testFile);
			fseek (testFile, 0, SEEK_SET);
			buf = malloc (bufLen);
			if (fread(buf, 1, bufLen, testFile) != bufLen) {
				fprintf (stderr, "Unable to read file: quote\n");
				exit (1);
			}
			fclose (testFile);
			
			int i, size = sizeof(buf) / sizeof(char);
			size = bufLen;
			char *buf_str = (char*) malloc(2 * size + 1), *buf_ptr = buf_str;
			if (buf_str) {
			  for (i = 0; i < size; i++)
			    buf_ptr += sprintf(buf_ptr, "%02X", buf[i]);
			  
			}
			
			// Send quote to the server
			if (0 != (dwStatus = sendMessage(clientfd, tpmClientIP, serverIP, COMM_RSP_CHALLENGE, strlen(buf_str), buf_str))) {
				printf("===== Send Quote message to HEAD UNIT Failed! =====\n");
			} else {
				printf("\n===== Send Message to HEAD UNIT: Quote result =====\n");
			}
			free(buf_str);
			
			// Receive message from the server
			if (0 != (dwStatus = receiveMessage(clientfd, serverIP, &type, &dwTransLength, &buffer))) {
				printf("===== Received message from HEAD UNIT Failed! =====\n");
			}
			
			// Checks did quote confirmation success on server side.
			if(type == COMM_QUOTE_SUCCESS) {
				printf("===== Received message from HEAD UNIT: Quote Success! =====\n");
			} else if (type == COMM_QUOTE_FAILED) {
				printf("Server said that Quote failed\n");
			} else {
				printf("Quote confirmation failed on server side\n");
			}
			
		} else {
			printf("Quote failed");
			return 1;
		}
		close(clientfd);
		
	} else {
		printf("Message received from Head Unit failed\n");
	}
	
	close(clientfd);
	
	printf("\n");
	
	// After TPM Client has done all starting procedures it will go to loop mode
	loopMode();
	
	return 0;
}
