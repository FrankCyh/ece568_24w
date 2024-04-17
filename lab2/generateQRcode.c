#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "lib/encoding.h"

int
main(int argc, char * argv[])
{
	if ( argc != 4 ) {
		printf("Usage: %s [issuer] [accountName] [secretHex]\n", argv[0]);
		return(-1);
	}

	char *	issuer = argv[1];
	char *	accountName = argv[2];
	char *	secret_hex = argv[3];

	assert (strlen(secret_hex) <= 20);

	printf("\nIssuer: %s\nAccount Name: %s\nSecret (Hex): %s\n\n",
		issuer, accountName, secret_hex);

	// Create an otpauth:// URI and display a QR code that's compatible
	// with Google Authenticator

	// ECE568 Begin
	
	//convert the secret_hex to 10 bytes hex
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

	// ecode the secret_in_hex to base32
	uint8_t secret_encode[20];
	base32_encode(secret_in_hex, 10, secret_encode, 20); 

	// construct the otpauth_uri
	char otpauth_uri[100];
	sprintf(otpauth_uri, "otpauth://totp/%s?issuer=%s&secret=%s&period=30", urlEncode(accountName), urlEncode(issuer), secret_encode);
	
	displayQRcode(otpauth_uri);
	// ECE568 End
	// displayQRcode("otpauth://testing");

	return (0);
}
