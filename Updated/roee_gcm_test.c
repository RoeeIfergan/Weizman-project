/* WRITE CODE DSCPTN
*/


//#if !defined(ROEE_GCM_TEST_HEADER)
//#include "roee_gcm_test.h"
//#endif

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
/*
 * This file will Encrypt using the "gcm.h" file
*/

#if defined(MBEDTLS_PKCS5_C)

#include "mbedtls/pkcs5.h"
#include "mbedtls/error.h"
#endif

//#include  "roee_gcm_test.h"
#define BUFSIZE         2048
#define keySize		128


/*
	Functions
*/


//turning a password into a key
int getKey(unsigned char * keyP, const unsigned char* pass) {
	printf("Start\n");

	//initializing the context struct
	mbedtls_md_context_t sha256_ctx;
	printf("sha1 context created\n");

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

	//key - must be 128 bits long
	//unsigned char key[128];
	//pointer to key
	//unsigned char * keyP = key;

	//key length
	uint32_t keyLen = 256;

	//password to hash for key
	//const unsigned char* pass = "pass123";
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

	//printing password
	//for(int i = 0; i < 128;i++)
	//	printf("%c", key[i]);
	//printf("\n");
	//free up sha256_ctx memory
	mbedtls_md_free( &sha256_ctx );


	//return 0 on success
	return 0;
}

//Function for Encrypting
void Encrypt(unsigned char * bufOutput, char bufInput[], int bufSize, unsigned char key[], int key_Length, unsigned char iv[], int iv_Length, char tag[], int tag_Length) {

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
void Decrypt(unsigned char * bufOutput, char bufInput[], int bufSize, unsigned char key[], int key_Length, unsigned char iv[], int iv_Length, char tag[], int tag_Length) {

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




/*TEST FUNCTION
 * */


int main() {

	//key - must be 128 bits long
	unsigned char key[512];
	bzero(key, 512);
	//pointer to key
	unsigned char * keyP = key;

	getKey(keyP, "000");

	unsigned char key2[128];
	//sprintf(key2, "%02x", key2);
	//printing password
	int cnt = 0;
	int check = 0;
	int cnt2 = 1;
	unsigned char temp;
	unsigned char * tempP = &temp;
	//sprintf(temp, "%x", key[i];
	for(int i = 0; i < 512;i++) {
		printf("%x", key[i]);
		sprintf(tempP, "%x", key[i]);
		if(temp != '0')
			cnt++;
		if(temp == '0') {
			if(check == 0)
				cnt2 = 0;
			cnt2++;
			if(cnt == 10)
				break;
		}
	}
	printf("\n");
	printf("cnt: %d\n", cnt);

	/*
	printf("Start\n");

	//initializing the context struct
	mbedtls_md_context_t sha256_ctx;
	printf("sha1 context created\n");

	const mbedtls_md_info_t *info_sha256;
	int ret;
	//unsigned char key[64];



	mbedtls_md_init( &sha256_ctx );
	printf("sha1 init created\n");

	int valHashPass;
	const unsigned char * salt = "saltSaltsaltSaltsaltSaltsaltSaltsaltSalt";	//40 bit salt
	int saltLen = 40;
	unsigned int iterations = 200000;	//should be between 5000-100,000
	unsigned char key[128];
	unsigned char * keyP = key;
	uint32_t keyLen = 128;
	const unsigned char* pass = "pass123";
	int passLen = strlen(pass);

//	valHashPass = mbedtls_pkcs5_pbkdf2_hmac(&sha1_ctx, pass, passLen, salt, saltLen, iterations, keyLen, keyP);


//	printf("Key: %s", key);


	//Message Digests wrappers verification - hashing data from any length to fixed size
	info_sha256 = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
	printf("works so far!\n");


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


	valHashPass = mbedtls_pkcs5_pbkdf2_hmac(&sha256_ctx, pass, passLen, salt, saltLen, iterations, keyLen, keyP);

	if(valHashPass != 0) {
		printf("ERROR: Failed hashing password!\n");
		return -1;
	}
	else {
		printf("Password digested and hashed successfully\n");
	}
i = 0; i < 128;i++)
	printf("%c", key[i]);
//        printf("Key: %s\n", key);
	int key_len = strlen(key);
	printf("key Length: %d\n", key_len);

	mbedtls_md_free( &sha256_ctx );

*/
	//for( i = 0; i < MAX_TESTS; i++ )
	//{
	//if( verbose != 0 )
	//	mbedtls_printf( "  PBKDF2 (SHA1) #%d: ", i );

	//ret = mbedtls_pkcs5_pbkdf2_hmac( &sha1_ctx, password_test_data[i],
	//plen_test_data[i], salt_test_data[i],
	//slen_test_data[i], it_cnt_test_data[i],
	//key_len_test_data[i], key );

/*
	if( ret != 0 || memcmp( result_key_test_data[i], key, key_len_test_data[i] ) != 0 ) {
		if( verbose != 0 )
			mbedtls_printf( "failed\n" );

		ret = 1;
		goto exit;
	}

	if( verbose != 0 )
		mbedtls_printf( "passed\n" );
	}

	if( verbose != 0 )
		mbedtls_printf( "\n" );

	exit:
	mbedtls_md_free( &sha1_ctx );

	//return( ret );


*/


/*

==================================================================

*/
/*
	#if defined(MBEDTLS_GCM_C)
	int bufSize = 2048;
	char bufInput[BUFSIZE] = "Hello World - 1 2 3 ";
	printf("works!");
	char bufOutput[BUFSIZE];
	char * bOP = bufOutput;
	char tag[] = "12341234";
	unsigned char key[128] = "ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWX";

	unsigned char iv[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWd";
	int ivLength = strlen(iv);


	char currTag[] = "123123";
	//Encrypt(bOP, bufInput, 2048, "ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWX", 128, "ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWd", 128, currTag, strlen(currTag));
	Encrypt(bOP, bufInput, 2048, key, 128, iv, 128, currTag, strlen(currTag));


	//Encrypt(bOP, bufInput, BUFSIZE, key, 128,iv, ivLength, tag, strlen(tag));

	printf("%s\n", bufOutput);
	printf("done Encrypting\n");
	printf("Start Decrypting\n");
	char Fdecrypt[BUFSIZE];
	bOP = Fdecrypt;
	Decrypt(bOP, bufOutput, 2048, key, 128,iv, 128, currTag, strlen(currTag));
	//Decrypt(bOP, bufOutput, BUFSIZE, key, 128,iv, ivLength, currTag, strlen(currTag));
	printf("D: %s\n", Fdecrypt);
#endif

#if defined(MBEDTLS_MEMORY_BUFFER_ALLOC_C)
    mbedtls_memory_buffer_alloc_free();
#endif
*/
    return( 0 );

}














/*
 * unsigned char tmp[200];
 *
 * ---------------------------------------------------
if( todo.aes_gcm )
    {
        int keysize;
        mbedtls_gcm_context gcm;

        mbedtls_gcm_init( &gcm );
        for( keysize = 128; keysize <= 256; keysize += 64 )
        {
            mbedtls_snprintf( title, sizeof( title ), "AES-GCM-%d", keysize );

            memset( buf, 0, sizeof( buf ) );
            memset( tmp, 0, sizeof( tmp ) );
            mbedtls_gcm_setkey( &gcm, MBEDTLS_CIPHER_ID_AES, tmp, keysize );

            TIME_AND_TSC( title,
                    mbedtls_gcm_crypt_and_tag( &gcm, MBEDTLS_GCM_ENCRYPT, BUFSIZE, tmp,
                        12, NULL, 0, buf, buf, 16, tmp ) );

            mbedtls_gcm_free( &gcm );
        }
    }
*/

/*
	printf("HELLO PRINTING\n");
	printf("bufOutput:%sNothing\n", bufOutput);
	//declaring the context struct
	mbedtls_gcm_context gcmContext;


	//initializing the gcmContext
	mbedtls_gcm_init(& gcmContext);


	//associates the gcmContext with a cipher algorithm(AES) and a key
	if(mbedtls_gcm_setkey(&gcmContext,  MBEDTLS_CIPHER_ID_AES, key, keySize) != 0) {
		printf( "setkey failed :(\n");
	}

	if(mbedtls_gcm_crypt_and_tag(&gcmContext, MBEDTLS_GCM_ENCRYPT, BUFSIZE, iv, ivLength, NULL, 0, bufInput, bufOutput, strlen(tag), tag)!= 0) {
		printf("Encrypting failed :(\n");
	}

	//clearing the gcmContext
	mbedtls_gcm_free(&gcmContext);

	//printing into a file
	//printing Original text
	printf("Print Original: %s\n", bufInput);

	printf("\n");
	//printing encrypted text
	//printf("\t\tPrint Encrypted: %s\n", bufOutput);
	printf("print Encrypted:\n");
	printf("123");
	//printf(bufOutput);

	FILE * fp;
        fp = fopen("/root/mbedtls/programs/test/output.txt", "w");
        fprintf(fp, bufOutput, 0);
        fclose(fp);
	printf("123");



	printf("\n----------------------------------");
	//printf("\n\n\n\n\n");









	//decrypting


	char fDecrypted[BUFSIZE];


	printf("DECRYPTING");
        //printf("bufOutput:%s121\n", bufOutput);
        //declaring the context struct
        //mbedtls_gcm_context gcmContext;


        //initializing the gcmContext
        mbedtls_gcm_init(& gcmContext);


        //associates the gcmContext with a cipher algorithm(AES) and a key
        if(mbedtls_gcm_setkey(&gcmContext,  MBEDTLS_CIPHER_ID_AES, key , keySize) != 0) {
                printf( "setkey failed :(\n");
        }


        if(mbedtls_gcm_auth_decrypt(&gcmContext, BUFSIZE, iv, ivLength, NULL, 0,tag, strlen(tag), bufOutput, fDecrypted)!= 0) {
                printf("Decryption failed :(\n");
        }

        //clearing the gcmContext
        mbedtls_gcm_free(&gcmContext);

        //printing Original text
        printf("\t\tPrint Original: '%s'\n", bufOutput);

        printf("\n");
        //printing Decrypted text
        //printf("\t\tPrint Decrypted: %s\n", bufOutput);
        printf("print Decrypted:\n'");
        printf(fDecrypted);
	printf("'");

	printf("\n");
*/

