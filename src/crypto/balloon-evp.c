#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "balloon-evp.h"
#include "balloon-aes.h"

#define SN_aes_128_ctr          "AES-128-CTR"
#define LN_aes_128_ctr          "aes-128-ctr"
#define NID_aes_128_ctr         904

typedef struct {
    AES_KEY ks;
    block128_f block;
    union {
        cbc128_f cbc;
        ctr128_f ctr;
    } stream;
} EVP_AES_KEY;

int EVP_CipherInit(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher, const unsigned char *key, const unsigned char *iv, int enc);
int EVP_CipherInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher, const unsigned char *key, const unsigned char *iv, int enc);
#define M_do_cipher(ctx, out, in, inl) ctx->cipher->do_cipher(ctx, out, in, inl)

static int aes_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key, const unsigned char *iv, int enc)
{
    int ret;
    EVP_AES_KEY *dat = (EVP_AES_KEY *)ctx->cipher_data;
    ret = AES_set_encrypt_key(key,ctx->key_len*8,&dat->ks);
    dat->block = (block128_f)AES_encrypt;
    dat->stream.cbc    =  NULL;
    if(ret < 0) return 0;
    return 1;
}

static int aes_ctr_cipher (EVP_CIPHER_CTX *ctx, unsigned char *out, const unsigned char *in, size_t len) 
{
    unsigned int num = ctx->num;
    EVP_AES_KEY *dat = (EVP_AES_KEY *)ctx->cipher_data;
    CRYPTO_ctr128_encrypt(in,out,len,&dat->ks, ctx->iv,ctx->buf,&num,dat->block);
    ctx->num = (size_t)num;
    return 1;
}

static const EVP_CIPHER aes_128_ctr = {
    NID_aes_128_ctr, 1, 16,
    16, EVP_CIPH_CTR_MODE,
    aes_init_key, aes_ctr_cipher,
    NULL, sizeof(EVP_AES_KEY),
    NULL, NULL
};

const EVP_CIPHER *EVP_aes_128_ctr(void) { return &aes_128_ctr; }

EVP_CIPHER_CTX *EVP_CIPHER_CTX_new(void)
{
    EVP_CIPHER_CTX *ctx = malloc(sizeof *ctx);
    EVP_CIPHER_CTX_init(ctx);
    return ctx;
}

void EVP_CIPHER_CTX_init(EVP_CIPHER_CTX *ctx) 
{
    memset(ctx, 0, sizeof(EVP_CIPHER_CTX));
}

int EVP_CIPHER_CTX_cleanup(EVP_CIPHER_CTX *c) 
{
    if (c->cipher_data)
        free(c->cipher_data);
    memset(c, 0, sizeof(EVP_CIPHER_CTX));
    return 1;
}

int EVP_EncryptInit(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher, const unsigned char *key, const unsigned char *iv) 
{
    return EVP_CipherInit(ctx, cipher, key, iv, 1);
}

int EVP_CipherInit(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher, const unsigned char *key, const unsigned char *iv, int enc) 
{
    EVP_CIPHER_CTX_init(ctx);
    return EVP_CipherInit_ex(ctx, cipher, key, iv, enc);
}

int EVP_CipherInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher, /*ENGINE *impl,*/ const unsigned char *key, const unsigned char *iv, int enc) {

    ctx->encrypt = enc;

    if (cipher) {
        if (ctx->cipher) {
            unsigned long flags = ctx->flags;
            EVP_CIPHER_CTX_cleanup(ctx);
            ctx->encrypt = enc;
            ctx->flags = flags;
        }
        ctx->cipher = cipher;
        if (ctx->cipher->ctx_size) {
            ctx->cipher_data = malloc(ctx->cipher->ctx_size);
            if (!ctx->cipher_data) {
                ctx->cipher = NULL;
                return 0;
            }
        }
        ctx->key_len = cipher->key_len;
        ctx->flags = 0;
        if (ctx->cipher->flags & EVP_CIPH_CTRL_INIT) {
                ctx->cipher = NULL;
                return 0;
        }
   }

   if (!(ctx->cipher->flags & EVP_CIPH_CUSTOM_IV)) {
           ctx->num = 0;
           if (iv)
               memcpy(ctx->iv, iv, ctx->cipher->iv_len);
   }

   if (key || (ctx->cipher->flags & EVP_CIPH_ALWAYS_CALL_INIT)) {
       if (!ctx->cipher->init(ctx, key, iv, enc))
           return 0;
   }
   ctx->buf_len = 0;
   ctx->final_used = 0;
   ctx->block_mask = ctx->cipher->block_size - 1;
   return 1;

}

int EVP_EncryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl, const unsigned char *in, int inl) 
{
   int i;
   *outl = 0;
   i = (inl & 0);
   inl -= i;
   *outl += inl;
   if (!M_do_cipher(ctx, out, in, inl))
      return 0;
   *outl += inl;
}
