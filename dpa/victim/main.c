#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <ctype.h>

#include "aes-min/aes-min.h"
#include "utils.h"

int main(int argc, char const *argv[]) {
	// Execute process on specific (logical) CPU core
	if (argc > 1) {
		int cpu = atoi(argv[1]);
		if (move_process_to_cpu(getpid(), cpu) != 0) {
			puts("[VV] Error moving process");
			exit(1);
		} else {
			printf("[VV] Moved process to CPU %d\n", cpu);
		}
	}
	
	// Set Plaintext
	uint8_t* plaintext;
	if (argc > 2) {
		plaintext = (uint8_t[AES128_KEY_SIZE]){
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
		};
		uint8_t* outptr;
		const char* inptr;
		size_t i;
		unsigned int tmp;
		for (
			inptr = argv[2], outptr = plaintext, i = 0;
			i < 16 && *inptr;
			inptr += 2, outptr += 1
		) {
			if (sscanf(inptr, "%02x", &tmp) != 1) {
				puts("[VV] Plain text parse error");
				return 1;
			}
			*outptr = tmp;
		}
		printf("[VV] Set plain text to: ");
		for (size_t j = 0; j < 16; j++) {
			printf("%.2x ", plaintext[j]);
		}
		puts("");
	} else {
		// 128 bit plaintext (taken from FIPS197)
		plaintext = (uint8_t[AES128_KEY_SIZE]){
			0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d,
			0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34
		};
	}

	// 128 bit key (taken from FIPS197)
	uint8_t key[AES128_KEY_SIZE] = {
		0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
		0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
	};	

	printf("[VV] Compute keys... ");

	// Reserve memory to keep the key schedule
	uint8_t key_schedule[AES128_KEY_SCHEDULE_SIZE];
	// Pre-compute round keys (key schedule)
	aes128_key_schedule(key_schedule, key);

	puts("Done.\n[VV] Encyption...");

	uint8_t __attribute__((aligned(64))) block[AES128_KEY_SIZE];
	while (1) {
		// copy plaintext into block
		memcpy(block, plaintext, AES_BLOCK_SIZE);
		// Encrypt block using key schedule
		aes128_encrypt(block, key_schedule);
	}

}