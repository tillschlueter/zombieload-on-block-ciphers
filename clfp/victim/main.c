// Based on https://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption

// pread() requires this:
#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 500
#endif

#include <string.h>
#include <stdbool.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>

void handleErrors(void);
int ossl_encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
			unsigned char *ciphertext);
int ossl_decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
			unsigned char *plaintext);

void printptr(unsigned char* ptr) {
	for (int i = sizeof(unsigned char*) * 8 - 1; i >= 0; i--) {
		if (((size_t)ptr >> i) & 1UL) {
			printf("1");
		} else {
			printf("0");
		}
		if (i == 6 || i == 12) {
			printf(" ");
		}
	}
	puts("");
}

int main (int argc, char* argv[]) {
	// Parse command line argument: number of repetitions
	// (either positive number or "inf")
	long long NUM;
	bool infinte = false;
	if (argc > 1) {
		if (strcmp(argv[1], "inf") == 0) {
			NUM = 0;
			infinte = true;
			puts("Will do [inf] repetitions");
		} else {
			NUM = abs(atoll(argv[1]));
			printf("Will do %lld repetitions\n", NUM);
		}
	} else {
		puts("Please supply the number of repetitions as command line argument (positive integer or \"inf\").");
		return 2;
	}

	// 128 bit key (taken from FIPS197)
	unsigned char __attribute__((aligned(64))) key[] = {
		0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
		0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
	};

	printf("Key logical address: %p\n", key);
	printptr(key);

	// 128 bit plaintext (taken from FIPS197)
	unsigned char plaintext[] = {
		0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d,
		0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34
	};

	// determine length of plaintext (should be 16)
	size_t plaintext_len = sizeof(plaintext);

	for (long long i = 0; (infinte || i < NUM); i++) {
		// clflush(&(key[0]));
		// Buffers to keep ciphertext and decrypted text
		unsigned char ciphertext[plaintext_len];

		int ciphertext_len;

		// Encrypt plaintext
		ciphertext_len = ossl_encrypt(plaintext, plaintext_len, key, ciphertext);

		// Print ciphertext 
		// printf("Ciphertext is:\n");
		// BIO_dump_fp(stdout, (const char *)ciphertext, ciphertext_len);

		// Use ciphertext_len
		(void)ciphertext_len;
	}

	return 0;
}

void handleErrors(void) {
	ERR_print_errors_fp(stderr);
	abort();
}

int ossl_encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
			unsigned char *ciphertext) {
	// Context
	EVP_CIPHER_CTX *ctx;

	// Create and initialise the context 
	if(!(ctx = EVP_CIPHER_CTX_new()))
		handleErrors();

	// Initialise encryption operation using 128 bit key and no IV (because of ECB)
	if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL))
		handleErrors();

	// Disable Padding
	if(1 != EVP_CIPHER_CTX_set_padding(ctx, 0))
		handleErrors();

	// Encrypt plaintext_len plaintext bytes into ciphertext; Write ciphertext length into len.
	int len;
	if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
		handleErrors();

	// Keep track of ciphertext length
	int ciphertext_len = len;
	
	// Finalise the encryption. Since Padding is disabled, no more ciphertext bytes are written at
	// this stage. Be sure that the last 128 bit block is full before finalisation.
	if(1 != EVP_EncryptFinal_ex(ctx, NULL, &len))
		handleErrors();

	// Keep track of ciphertext length (len should be 0 here)
	ciphertext_len += len;

	// Clean up
	EVP_CIPHER_CTX_free(ctx);

	// return ciphertext length
	return ciphertext_len;
}


int ossl_decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
			unsigned char *plaintext) {
	// Context
	EVP_CIPHER_CTX *ctx;

	// Create and initialise the context 
	if(!(ctx = EVP_CIPHER_CTX_new()))
		handleErrors();

	// Initialise decryption operation using 128 bit key and no IV (because of ECB)
	if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL))
		handleErrors();

	// Disable Padding
	if(1 != EVP_CIPHER_CTX_set_padding(ctx, 0))
		handleErrors();

	// Decrypt ciphertext_len ciphertext bytes into plaintext; Write plaintext length into len.
	int len;
	if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
		handleErrors();
	
	// Keep track of plaintext length
	int plaintext_len = len;

	// Finalise the encryption. Since Padding is disabled, no more plaintext bytes are
	// written at this stage.
	if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
		handleErrors();

	// Keep track of plaintext length (len should be 0 here)
	plaintext_len += len;

	// Clean up
	EVP_CIPHER_CTX_free(ctx);

	// return plaintext length
	return plaintext_len;
}
