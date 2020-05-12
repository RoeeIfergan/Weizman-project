#ifndef ROEE_GCM_TEST_HEADER
#define ROEE_GCM_TEST_HEADER
/* WRITE CODE DSCPTN
*/
#include "roee_gcm_test.h"
#include <stdint.h>
#include "../../crypto/include/mbedtls/cipher.h"
#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdio.h>
#define mbedtls_printf     printf
#endif

#if defined(MBEDTLS_GCM_C)
#include "mbedtls/gcm.h"
#endif

#if defined(MBEDTLS_ENTROPY_C)
#include "mbedtls/entropy.h"
#endif

#if defined(MBEDTLS_SHA256_C)
#include "mbedtls/sha256.h"
#endif

#if defined(MBEDTLS_CTR_DRBG_C)
#include "mbedtls/ctr_drbg.h"
#endif
#include <string.h>

#include "mbedtls/error.h"

#if defined(MBEDTLS_MEMORY_BUFFER_ALLOC_C)
#include "mbedtls/memory_buffer_alloc.h"
#endif

#if defined(MBEDTLS_SHA256_C)
#include "mbedtls/sha256.h"
#endif
#include "mbedtls/pkcs5.h"

/*
 * This file will Encrypt using the "gcm.h" file
*/

#define BUFSIZE         2048
#define keySize		128
/*
	Functions
*/

//Function for Encrypting
void Encrypt(unsigned char * bufOutput, unsigned char bufInput[], int bufSize, const unsigned char key[], unsigned int key_Length, const unsigned char iv[], int iv_Length, unsigned char tag[], int tag_Length) {

	//char bufOutput[bufSize];
	printf("\n");
	printf("ENCRYPTION\n");
	printf("-=-=-=--=-=-=-=-=-=-=-=-=-=-=-\n");

        //declaring the context struct
        mbedtls_gcm_context gcmContext;
	printf("gcmContext Done\n");

        //initializing the gcmContext
        mbedtls_gcm_init(& gcmContext);
	printf("gcm init Done\n");

        //associates the gcmContext with a cipher algorithm(AES) and a key
        if(mbedtls_gcm_setkey(&gcmContext,  MBEDTLS_CIPHER_ID_AES, key, key_Length) != 0) {
                printf( "setkey failed :(\n");
        }


	//Encrypting bufInput with tag
        if(mbedtls_gcm_crypt_and_tag(&gcmContext, MBEDTLS_GCM_ENCRYPT, bufSize, iv, iv_Length, NULL, 0, bufInput, bufOutput, tag_Length, tag)!= 0) {
                printf("Encrypting failed :(\n");
        }

        //clearing the gcmContext
        mbedtls_gcm_free(&gcmContext);
	printf("\n");
}

//Function for Decrypting
void Decrypt(unsigned char * bufOutput, const unsigned char bufInput[], int bufSize, const unsigned char key[], unsigned int key_Length, const unsigned char iv[], int iv_Length, const unsigned char tag[], int tag_Length) {

	printf("\n");
	printf("DECRYPTING\n");
	printf("-=-=-=--=-=-=-=-=-=-=-=-=-=-=-");

	//declaring the context struct
	mbedtls_gcm_context gcmContext;


        //initializing the gcmContext
        mbedtls_gcm_init(& gcmContext);


        //associates the gcmContext with a cipher algorithm(AES) and a key
        if(mbedtls_gcm_setkey(&gcmContext,  MBEDTLS_CIPHER_ID_AES, key , key_Length) != 0) {
                printf( "setkey failed :(\n");
        }

	//Decrypting the encrypted text and verifying the tags match
        if(mbedtls_gcm_auth_decrypt(&gcmContext, bufSize, iv, iv_Length, NULL, 0,tag, tag_Length, bufInput, bufOutput)!= 0) {
                printf("Decryption failed :(\n");
        }

        //clearing the gcmContext
        mbedtls_gcm_free(&gcmContext);
	printf("\n");
}

//turning a password into a key
//returns -1 if not succesful
//returns 0 if successful
int getKey(unsigned char * keyP, const unsigned char * pass) {
	printf("Start\n");

	//initializing the context struct
	mbedtls_md_context_t sha256_ctx;
	printf("sha256 context created\n");

	const mbedtls_md_info_t *info_sha256;

	//initzializing the mbedtls_md_init
	mbedtls_md_init( &sha256_ctx );
	printf("sha1 init created\n");

	//valHashPass validates the password hashing
	int valHashPass;

	//salt - to prevent rainbow attacks
	//doesn't need to be protected, store with password without encryption
	const unsigned char * salt = "saltSaltsaltSaltsaltSaltsaltSaltsaltSalt";	//40 bit salt
	//salt length
	int saltLen = 40;

	//number of iterations that mbedtls_pkcs5_pbkdf2_hmac does
	unsigned int iterations = 200000;	//should be between 5000-100,000

	//key length
	uint32_t keyLen = 256;

	//password to hash for key
//	const unsigned char* pass = "pass123";
	//password length
	int passLen = strlen(pass);

	//Message Digests wrappers verification - hashing data from any length to fixed size
	info_sha256 = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);


	//if info_sha256 is NULL, it is created in second if, and checked
	if( info_sha256 == NULL )
	{
		//valHashPass = 1 when info_sha256 isn't initialized
		//this is for second if to initialize it
		valHashPass = 1;
		printf("ERROR: info_sha256 = NULL!\n");
		return -1;
	}

	//if info_sha1 is NULL, it is created and checked
	if( ( valHashPass = mbedtls_md_setup( &sha256_ctx, info_sha256, 1 ) ) != 0 )
	{
		printf("ERROR: Initializing info_sha1 failed!\n");
		return -1;
	}


	//hashing password into key
	valHashPass = mbedtls_pkcs5_pbkdf2_hmac(&sha256_ctx, pass, passLen, salt, saltLen, iterations, keyLen, keyP);

	//if hashing failed quit
	if(valHashPass != 0) {
		printf("ERROR: Failed hashing password!\n");
		return -1;
	}
	else {
		printf("Password digested and hashed successfully\n");
	}

	//free up sha256_ctx memory
	mbedtls_md_free( &sha256_ctx );

	//return 0 on success
	return 0;
}

#endif
