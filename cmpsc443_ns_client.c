////////////////////////////////////////////////////////////////////////////////
//
//  File          : cmpsc443_ns_client.c
//  Description   : This is the client side of the Needham Schroeder 
//                  protocol, and associated main processing loop.
//
//   Author        : Alina Aftab
//   Last Modified : FILL IN
//

// Includes
#include <unistd.h>
#include <cmpsc311_log.h>
#include <arpa/inet.h>



// Project Include Files
#include <cmpsc443_ns_proto.h>
#include <cmpsc311_network.h>
#include <cmpsc311_util.h>
#include <cmpsc443_ns_util.h>

// Defines
#define NS_ARGUMENTS "h"
#define USAGE \
	"USAGE: cmpsc443_ns_client [-h]\n" \
	"\n" \
	"where:\n" \
	"    -h - help mode (display this message)\n" \
	"\n" \

//Global Variables
int sockID;

// Functional Prototypes
int ns_client( void );

//
// Functions

//this function encrypts or decrptes (depending on flag) with the given inititialization
//vector, key, and cipher size.

int encrypt_decrypt_cipher(ns_iv_t init_vector, ns_key_t key, void *encrypted, void *decrypted, int cipher_size, int flag){

	gcry_cipher_hd_t handle;
	gcry_error_t err = 0;

	err = gcry_cipher_open (&handle, GCRY_CIPHER_AES, 
							GCRY_CIPHER_MODE_CBC, 0);
	if (err)
	{
		logMessage(LOG_ERROR_LEVEL, "Cipher_Open Failed: %s/%s\n",
		gcry_strsource (err),
		gcry_strerror (err));
		return -1;
	}

	err = gcry_cipher_setkey(handle, key, 16);

	if (err)
	{
		logMessage(LOG_ERROR_LEVEL, "Cipher SetKey Failed: %s/%s\n",
		gcry_strsource (err),
		gcry_strerror (err));
		return -1;
	}


	err = gcry_cipher_setiv(handle, init_vector, 16);

	
	if (err)
	{
		logMessage(LOG_ERROR_LEVEL, "Cipher SetIV Failed: %s/%s\n", 
		gcry_strsource (err), 
		gcry_strerror (err));
		return -1;
	}

	if (flag == 1){
		
		err = gcry_cipher_encrypt(handle, encrypted, NS_MAX_XMIT_SIZE, decrypted, cipher_size);
		if (err)
		{
			logMessage(LOG_ERROR_LEVEL, "Cipher Encryption Failed: %s/%s\n", 
			gcry_strsource (err), 
			gcry_strerror (err));
			return -1;
		}

	}
	else{
		err = gcry_cipher_decrypt(handle, decrypted, NS_MAX_XMIT_SIZE, encrypted, cipher_size);
		if (err)
		{
			logMessage(LOG_ERROR_LEVEL, "Cipher Decryption Failed: %s/%s\n", 
			gcry_strsource (err), 
			gcry_strerror (err));
			return -1;
		}

	}

	
	return 0;

}

void pad_to_multiple_of_16(uint16_t *cipher_size){

	if ((*cipher_size%16) != 0)
		*cipher_size = ((*cipher_size/16)+1)*16;

}

int send_payloadSize_msgType(uint16_t payload_size, uint16_t msg_type){

	char msg[4];
	uint16_t header;

	header = htons(payload_size);
	memmove(msg, &header, 2);

	header = htons(msg_type);
	memmove(msg+2, &header, 2);

	logMessage(LOG_INFO_LEVEL, "SEND HEADER: msg_type %d\n", msg_type);
	logMessage(LOG_INFO_LEVEL, "SEND HEADER: payload_size %d\n", payload_size);

	if(cmpsc311_send_bytes(sockID, 4, msg) ==-1)
		return -1;

	return 0;

}

int recieve_payloadSize_msgType(uint16_t *payload_size, uint16_t *msg_type){

	char header[4];

	if(cmpsc311_read_bytes(sockID, 4, header) ==-1)
		return -1;

	memmove(payload_size, header, 2);
	memmove(msg_type, header+2, 2);

	*payload_size = htons(*payload_size);
	*msg_type = ntohs(*msg_type);

	logMessage(LOG_INFO_LEVEL, "RECIEVE HEADER: Payload_size: %d", *payload_size);
	logMessage(LOG_INFO_LEVEL, "RECIEVE HEADER: Msg_type: %d", *msg_type);

	
	return 0;

}


void get_encrypted_data(uint16_t *cipher_size, void *encrypted){

	cmpsc311_read_bytes(sockID, *cipher_size, encrypted);

}

void get_cipherSize_and_initVector(void *response, uint16_t *cipher_size, ns_iv_t *init_vector){

	cmpsc311_read_bytes(sockID, 18, response);
	
	memmove(init_vector, response, 16);
	memmove(cipher_size, response+16, 2);

	*cipher_size = ntohs(*cipher_size);

	logBufferMessage(LOG_INFO_LEVEL, "IV: ", (char*)init_vector, 16); 
	logMessage(LOG_INFO_LEVEL, "Init vector success");
	logMessage(LOG_INFO_LEVEL, "Cipher_size success:  %d bytes", *cipher_size);

	


}






////////////////////////////////////////////////////////////////////////////////
//
// Function     : main
// Description  : The main function for the Needam Schroeder protocol client
//
// Inputs       : argc - the number of command line parameters
//                argv - the parameters
// Outputs      : 0 if successful, -1 if failure

int main( int argc, char *argv[] )
{
	// Local variables
	int ch;

	// Process the command line parameters
	while ((ch = getopt(argc, argv, NS_ARGUMENTS)) != -1) {

		switch (ch) {
		case 'h': // Help, print usage
			fprintf( stderr, USAGE );
			return( -1 );

		default:  // Default (unknown)
			fprintf( stderr, "Unknown command line option (%c), aborting.\n", ch );
			return( -1 );
		}
	}

	// Create the log, run the client
    initializeLogWithFilehandle(STDERR_FILENO);
    enableLogLevels(LOG_INFO_LEVEL);
	ns_client();

	// Return successfully
	return( 0 );
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : ns_client
// Description  : The client function for the Needam Schroeder protocol server
//
// Inputs       : none
// Outputs      : 0 if successful, -1 if failure

int ns_client( void ) {

	///////////////////////////////////////////////////////////
	//////////////////////////////////////////////////////////
	//				VARIABLE DECLARATIONS

	uint16_t payload_size;
	uint16_t msg_type;
	uint16_t cipher_size;
	ns_iv_t init_vector;
	ns_key_t AliceKey;
	tkt_req_t ticket_request;
	tkt_res_t ticket_response;
	char encrypted_msg[NS_MAX_XMIT_SIZE];
	char decrypted_msg[NS_MAX_XMIT_SIZE];

	memset(encrypted_msg, 0, NS_MAX_XMIT_SIZE);
	memset(decrypted_msg, 0, NS_MAX_XMIT_SIZE);
	memset(init_vector, 0, 16);

	///////////////////////////////////////////////////////////
	//////////////////////////////////////////////////////////
	// 				CREATING CLIENT CONNECTION

	sockID = cmpsc311_client_connect("127.0.0.1", NS_SERVER_PROTOCOL_PORT);
	
	if(sockID==-1) return -1;

	///////////////////////////////////////////////////////////
	//////////////////////////////////////////////////////////
	//				TICKET REQUEST

	logMessage(LOG_INFO_LEVEL, "::::::::TICKET REQUEST::::::::");
	
	if(send_payloadSize_msgType(40, 1)==-1) return -1;

	createNonce(&ticket_request.N1);

	logMessage(LOG_INFO_LEVEL, "NONCE CREATED: %llx\n", ticket_request.N1);
	logBufferMessage(LOG_INFO_LEVEL, "Nonce Created: ",(char*) &ticket_request.N1, 8); 
	
	memmove(&ticket_request.A, NS_ALICE_IDENTITY, 6);
	memmove(&ticket_request.B, NS_BOB_IDENTITY, 4);

	memmove(decrypted_msg, &ticket_request, 40);

	if(cmpsc311_send_bytes(sockID, 40, decrypted_msg)== -1)
		return -1;
		
	////////////////////////////////////////////////////////////////////
	////////////////////////////////////////////////////////////////////
	//				TICKET RESPONSE

	logMessage(LOG_INFO_LEVEL, "::::::::TICKET RESPONSE::::::::");

	if(recieve_payloadSize_msgType(&payload_size, &msg_type)== -1)
		return -1;

	if (makeKeyFromPassword(NS_ALICE_PASSWORD, AliceKey) == -1){
		logMessage(LOG_ERROR_LEVEL, "Make Alice Password Failed");
		return -1;
	}
	
	get_cipherSize_and_initVector(encrypted_msg, &cipher_size, &init_vector);

	pad_to_multiple_of_16(&cipher_size);
	
	get_encrypted_data(&cipher_size, encrypted_msg);
	
	logMessage(LOG_INFO_LEVEL, "Message Recieve Success");

	encrypt_decrypt_cipher(init_vector, AliceKey, encrypted_msg, decrypted_msg, cipher_size, 0);
	
	memcpy(&ticket_response, decrypted_msg, 8);
	memcpy(&ticket_response.B, decrypted_msg+8, 16);
	memcpy(&ticket_response.Kab, decrypted_msg+24, 16);

	memcpy(&cipher_size, decrypted_msg+58, 2);
	cipher_size = ntohs(cipher_size);

	memcpy(&ticket_response.ticket, decrypted_msg+40, cipher_size+20);

	logMessage(LOG_INFO_LEVEL, "cipher 2 size: %d", cipher_size);
	logBufferMessage(LOG_INFO_LEVEL, "cipher 2 size", (char*)&cipher_size, 2);
	
	logBufferMessage(LOG_INFO_LEVEL, "Nonce in tkt req", (char*)&ticket_response, 8);
	
	logMessage(LOG_INFO_LEVEL, "Bob in tkt req %s\n", &ticket_response.B);
	
	logBufferMessage(LOG_INFO_LEVEL, "Bob in tkt req", (char*)&ticket_response.B, 16);
	
	logBufferMessage(LOG_INFO_LEVEL, "Shared Key ", (char*)&ticket_response.Kab , 16);

	logBufferMessage(LOG_INFO_LEVEL, "ticket ", (char*)&ticket_response.ticket , 52);

	////////////////////////////////////////////////////////////////////
	///////////////////////////////////////////////////////////////////

	logMessage(LOG_INFO_LEVEL, "::::::::SERVER REQUEST::::::::");

	ns_nonce_t nonce2;
	createNonce(&nonce2);
	getRandomData(init_vector, 16);

	logBufferMessage(LOG_INFO_LEVEL, "NONCE 2 Created", (char*)&nonce2, 8);

	
	if(send_payloadSize_msgType(118, 3)==-1) return -1;


	memset(encrypted_msg, 0, NS_MAX_XMIT_SIZE);

	memmove(encrypted_msg, NS_ALICE_IDENTITY, 6);
	memmove(encrypted_msg+16, NS_BOB_IDENTITY, 4);
	memmove(encrypted_msg+32, &ticket_response.ticket, 52);

	memmove(encrypted_msg+ 84, init_vector, 16);

	cipher_size = htons(8);

	memmove(encrypted_msg+100, &cipher_size, 2);

	encrypt_decrypt_cipher(init_vector,ticket_response.Kab,decrypted_msg, &nonce2, 16, 1);

	memmove(encrypted_msg+ 102, decrypted_msg, 16);

	if(cmpsc311_send_bytes(sockID, 118, encrypted_msg) == -1) return -1;

	
	////////////////////////////////////////////////////////////////////////
	////////////////////////////////////////////////////////////////////////

	logMessage(LOG_INFO_LEVEL, "::::::::SERVICE RESPONSE::::::::\n");

	memset(encrypted_msg, 0 , NS_MAX_XMIT_SIZE);
	memset(decrypted_msg, 0, NS_MAX_XMIT_SIZE);

	logBufferMessage(LOG_INFO_LEVEL, "encryped %d", encrypted_msg, 16);

	if(recieve_payloadSize_msgType( &payload_size, &msg_type) == -1) return -1;

	get_cipherSize_and_initVector(encrypted_msg, &cipher_size, &init_vector);

	pad_to_multiple_of_16(&cipher_size);

	get_encrypted_data(&cipher_size, encrypted_msg);

	logMessage(LOG_INFO_LEVEL, "Cipher length in Server res %d", cipher_size);

	encrypt_decrypt_cipher(init_vector, ticket_response.Kab, encrypted_msg, decrypted_msg,cipher_size, 0);

	ns_nonce_t nonce3;
	memmove(&nonce3, decrypted_msg, 8);
	logBufferMessage(LOG_INFO_LEVEL, "NONCE 2 In serv response: ", (char*)&nonce3, 8);

	nonce3 = nonce3 + htonll64(1);

	logBufferMessage(LOG_INFO_LEVEL, "NONCE 2 + 1 ", (char*)&nonce3, 8);
	logMessage(LOG_INFO_LEVEL, "NONCE 2 in serv Respose: %llu", nonce3);

	memmove(&nonce3, decrypted_msg+8, 8);

	logMessage(LOG_INFO_LEVEL, "NONCE 3 in serv Respose: %llu", nonce3);

	logBufferMessage(LOG_INFO_LEVEL, "NONCE 3 In serv response: ", (char*)&nonce3, 8);

	/////////////////////////////////////////////////////////////////////////////////
	////////////////////////////////////////////////////////////////////
	logMessage(LOG_INFO_LEVEL, "::::::::SERVICE ACKNOWLEDGEMENT::::::::");

	memset(decrypted_msg, 0, NS_MAX_XMIT_SIZE);
	logBufferMessage(LOG_INFO_LEVEL, "Nonce 3", (char*)&nonce3, 8);

	nonce3  = nonce3 - htonll64(1);

	logBufferMessage(LOG_INFO_LEVEL, "Nonce 3", (char*)&nonce3, 8);
	memmove(decrypted_msg, &nonce3, 8);
	getRandomData(init_vector, 16);
	encrypt_decrypt_cipher(init_vector, ticket_response.Kab, encrypted_msg, decrypted_msg,  cipher_size, 1);
	memset(decrypted_msg, 0 , NS_MAX_XMIT_SIZE);
	memmove(decrypted_msg, &init_vector, 16);
	cipher_size = htons(8);
	memmove(decrypted_msg+16, &cipher_size, 2);
	memmove(decrypted_msg+18, encrypted_msg, 16 );

	if(send_payloadSize_msgType(34, 5)==-1) return -1;

	if(cmpsc311_send_bytes(sockID, 34, decrypted_msg)==-1) return -1;

	/////////////////////////////////////////////////////////////////////////////////////////////////////
	/////////////////////////////////////////////////////////////////////////////////////////////////////

	logMessage(LOG_INFO_LEVEL, "::::::::DATA REQUEST::::::::");
	if(recieve_payloadSize_msgType(&payload_size, &msg_type)==-1) return -1;

	get_cipherSize_and_initVector(encrypted_msg, &cipher_size, &init_vector);

	pad_to_multiple_of_16(&cipher_size);

	get_encrypted_data(&cipher_size, encrypted_msg);

	logMessage(LOG_INFO_LEVEL, "Cipher_size: %d", cipher_size);
	memset(decrypted_msg, 0, NS_MAX_XMIT_SIZE);

	encrypt_decrypt_cipher(init_vector, ticket_response.Kab, encrypted_msg, decrypted_msg, cipher_size, 0);

	////////////////////////////////////////////////////////////////////////////////////
	////////////////////////////////////////////////////////////////////////////////////

	logMessage(LOG_INFO_LEVEL, "::::::::DATA RESPONSE::::::::");

	memset(encrypted_msg, 0, NS_MAX_XMIT_SIZE);

	for(int i = 0; i< cipher_size; i++){
		decrypted_msg[i] = decrypted_msg[i] ^ (uint8_t)182 ;

	}

	getRandomData(init_vector, 16);

	logMessage(LOG_INFO_LEVEL, "Cipher_ Size: %d", cipher_size);

	encrypt_decrypt_cipher(init_vector, ticket_response.Kab, encrypted_msg, decrypted_msg, cipher_size, 1);

	if(send_payloadSize_msgType(cipher_size+18, 7)==-1) return -1;

	memmove(decrypted_msg, init_vector, 16);
	cipher_size = htons(cipher_size);


	memmove(decrypted_msg+16, &cipher_size, 2);
	cipher_size = ntohs(cipher_size);
	memmove(decrypted_msg+18, encrypted_msg, cipher_size);

	

	//logMessage(LOG_INFO_LEVEL, "Cipher_ Size: %d", cipher_size);
	if(cmpsc311_send_bytes(sockID, 146, decrypted_msg)==-1) return -1;

	/////////////////////////////////////////////////////////////////////////////////////////
	/////////////////////////////////////////////////////////////////////////////////////////
	
	logMessage(LOG_INFO_LEVEL, "::::::::SERVER FINISH::::::::");
	if(recieve_payloadSize_msgType(&payload_size, &msg_type)==-1) return -1;


	if(cmpsc311_close(sockID)==-1) return -1;










	return 0;
}