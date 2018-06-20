#ifndef AES_H
#define AES_H

/* Because array size can't be a const in C, the following two are macros.
   Both sizes are in bytes. */
#define AES_MAXNR 14
#define AES_BLOCK_SIZE 16

/* This should be a hidden type, but EVP requires that the size be known */
typedef struct aes_key_st {
#ifdef AES_LONG
    unsigned long rd_key[4 *(AES_MAXNR + 1)];
#else
    unsigned int rd_key[4 *(AES_MAXNR + 1)];
#endif
    int rounds;
} AES_KEY;


typedef void (*block128_f)(const unsigned char in[16],
			unsigned char out[16],
			const void *key);

typedef void (*cbc128_f)(const unsigned char *in, unsigned char *out,
			size_t len, const void *key,
			unsigned char ivec[16], int enc);

typedef void (*ctr128_f)(const unsigned char *in, unsigned char *out,
			size_t blocks, const void *key,
			const unsigned char ivec[16]);

void AES_encrypt(const unsigned char *in, unsigned char *out,
		 const AES_KEY *key);
void AES_decrypt(const unsigned char *in, unsigned char *out,
		 const AES_KEY *key);
int AES_set_encrypt_key(const unsigned char *userKey, const int bits,
			AES_KEY *key);
int AES_set_decrypt_key(const unsigned char *userKey, const int bits,
			 AES_KEY *key);

void CRYPTO_ctr128_encrypt(const unsigned char *in, unsigned char *out,
			size_t len, const void *key,
			unsigned char ivec[16], unsigned char ecount_buf[16],
			unsigned int *num, block128_f block);
void CRYPTO_ctr128_encrypt_ctr32(const unsigned char *in, unsigned char *out,
			size_t len, const void *key,
			unsigned char ivec[16], unsigned char ecount_buf[16],
			unsigned int *num, ctr128_f func);

#endif
