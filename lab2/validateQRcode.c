#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <time.h>
#include <stdlib.h>
#include <math.h>
#include "lib/sha1.h"

#define T_X 30
#define TEXT_LENGTH 8

static int
validateTOTP(char * secret_hex, char * TOTP_string)
{
	// convert the secret_hex to 10 bytes hex key
	uint8_t secret_in_hex[10];
	char two_hex[3];
	for (int i = 0; i < 20; i++)
	{
		two_hex[0] = *(secret_hex + i);
		two_hex[1] = *(secret_hex + i + 1);
		two_hex[2] = 0;

		if(i%2 == 0)
		{
			secret_in_hex[i/2] = (uint8_t)strtol(two_hex, NULL, 16);
		}
		i++;
	}

	// https://datatracker.ietf.org/doc/pdf/rfc2104 pg13
	/* HMAC definition
	We define two fixed and different strings ipad and opad as follows
 	(the 'i' and 'o' are mnemonics for inner and outer):
 	ipad = the byte 0x36 repeated B times
 	opad = the byte 0x5C repeated B times.
 	To compute HMAC over the data `text' we perform
 	H(K XOR opad, H(K XOR ipad, text))
	*/

	unsigned char k_ipad[SHA1_BLOCKSIZE]; 
	unsigned char k_opad[SHA1_BLOCKSIZE];
	/* start out by storing key in pads */
	memset(k_ipad, 0, sizeof(k_ipad));
    memset(k_opad, 0, sizeof(k_opad));
    memcpy(k_ipad, secret_in_hex, 10);
    memcpy(k_opad, secret_in_hex, 10);
	/* XOR key with ipad and opad values */
	for(int i = 0; i < SHA1_BLOCKSIZE; i++)
	{
		k_ipad[i] ^= 0x36;	// K XOR ipad
		k_opad[i] ^= 0x5c;	// K XOR opad
	}

	// c_t is count of the number of durations t_x between t_0 and t(now)
	// t_0 is the Unix time, defualt to 0
	// T_X is one time duration, defualt to 30s
	// c_t = floor(t - t_0 / t_x)

	/*construct text as time*/
	uint8_t text[TEXT_LENGTH];
	long curr_time = time(NULL);
	long c_t = curr_time/T_X;
	int count = TEXT_LENGTH;
	while(count)
	{
		count--;
		// convert long to 8 bytes array to be used in sha1_update
		text[count] = c_t;
		c_t = c_t >> 8;
	}

	/*HMAC_SHA-1*/
	SHA1_INFO i_ctx, o_ctx;
	uint8_t i_sha[SHA1_DIGEST_LENGTH];
	uint8_t o_sha[SHA1_DIGEST_LENGTH];

	sha1_init(&i_ctx);
	sha1_update(&i_ctx, k_ipad, SHA1_BLOCKSIZE);
	sha1_update(&i_ctx, text, 8);
	sha1_final(&i_ctx,i_sha);

	sha1_init(&o_ctx);
	sha1_update(&o_ctx, k_opad, SHA1_BLOCKSIZE);
	sha1_update(&o_ctx, i_sha, SHA1_DIGEST_LENGTH);
	sha1_final(&o_ctx,o_sha);


	/*truncate HMAC to integer*/
	/*
	Dynamic Truncation: The truncate function takes the least 4 bits of the hash value's last 
	byte to determine an offset. This offset is used to select a 4-byte (32-bit) dynamic binary 
	code from the hash result. The offset ensures that the selection is somewhat unpredictable, 
	adding to the security of the generated password.
	*/
	int offset = o_sha[SHA1_DIGEST_LENGTH - 1] & 0xf;

	/*
	Extracting a 31-bit String: From the selected 4-byte segment, the top bit is cleared to make 
	sure the result is a positive 31-bit integer. This step is necessary because the final HOTP 
	value needs to be easily representable and manageable, especially for systems that may not 
	handle large integers efficiently.
	*/
    int bin_code = ((o_sha[offset] & 0x7f) << 24) |
                 ((o_sha[offset + 1] & 0xff) << 16) |
                 ((o_sha[offset + 2] & 0xff) << 8) |
                 (o_sha[offset + 3] & 0xff);
    
	/*
	Modulo Operation: The 31-bit integer is then reduced using a modulo operation to ensure it 
	fits within a desired range, typically 10^6 to 10^8, to produce a 6 to 8 digit OTP. The most 
	common practice is to use 10^6, resulting in a 6-digit OTP.
	*/
	int result = bin_code % (int)pow(10, 6);
	return result == atoi(TOTP_string);;
}


int
main(int argc, char * argv[])
{
	if ( argc != 3 ) {
		printf("Usage: %s [secretHex] [TOTP]\n", argv[0]);
		return(-1);
	}

	char *	secret_hex = argv[1];
	char *	TOTP_value = argv[2];

	assert (strlen(secret_hex) <= 20);
	assert (strlen(TOTP_value) == 6);

	printf("\nSecret (Hex): %s\nTOTP Value: %s (%s)\n\n",
		secret_hex,
		TOTP_value,
		validateTOTP(secret_hex, TOTP_value) ? "valid" : "invalid");

	return(0);
}
