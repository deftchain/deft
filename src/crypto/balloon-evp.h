#ifndef EVP_H
#define EVP_H

#define EVP_MAX_IV_LENGTH               16
#define EVP_MAX_BLOCK_LENGTH            32
#define EVP_CIPH_CTR_MODE               0x5
#define EVP_F_EVP_ENCRYPTFINAL_EX       127
#define EVP_CIPH_NO_PADDING             0x100
#define EVP_CIPH_FLAG_CUSTOM_CIPHER                      0x100000
#define EVP_R_DATA_NOT_MULTIPLE_OF_BLOCK_LENGTH          138

/* Values for cipher flags */

/* Modes for ciphers */

#define		EVP_CIPH_STREAM_CIPHER		0x0
#define		EVP_CIPH_ECB_MODE		0x1
#define		EVP_CIPH_CBC_MODE		0x2
#define		EVP_CIPH_CFB_MODE		0x3
#define		EVP_CIPH_OFB_MODE		0x4
#define		EVP_CIPH_CTR_MODE		0x5
#define		EVP_CIPH_GCM_MODE		0x6
#define		EVP_CIPH_CCM_MODE		0x7
#define		EVP_CIPH_XTS_MODE		0x10001
#define 	EVP_CIPH_MODE			0xF0007
/* Set if variable length cipher */
#define 	EVP_CIPH_VARIABLE_LENGTH	0x8
/* Set if the iv handling should be done by the cipher itself */
#define 	EVP_CIPH_CUSTOM_IV		0x10
/* Set if the cipher's init() function should be called if key is NULL */
#define 	EVP_CIPH_ALWAYS_CALL_INIT	0x20
/* Call ctrl() to init cipher parameters */
#define 	EVP_CIPH_CTRL_INIT		0x40
/* Don't use standard key length function */
#define 	EVP_CIPH_CUSTOM_KEY_LENGTH	0x80
/* Don't use standard block padding */
#define 	EVP_CIPH_NO_PADDING		0x100
/* cipher handles random key generation */
#define 	EVP_CIPH_RAND_KEY		0x200
/* cipher has its own additional copying logic */
#define 	EVP_CIPH_CUSTOM_COPY		0x400
/* Allow use default ASN1 get/set iv */
#define		EVP_CIPH_FLAG_DEFAULT_ASN1	0x1000
/* Buffer length in bits not bytes: CFB1 mode only */
#define		EVP_CIPH_FLAG_LENGTH_BITS	0x2000
/* Note if suitable for use in FIPS mode */
#define		EVP_CIPH_FLAG_FIPS		0x4000
/* Allow non FIPS cipher in FIPS mode */
#define		EVP_CIPH_FLAG_NON_FIPS_ALLOW	0x8000
/* Cipher handles any and all padding logic as well
 * as finalisation.
 */
#define 	EVP_CIPH_FLAG_CUSTOM_CIPHER	0x100000
#define		EVP_CIPH_FLAG_AEAD_CIPHER	0x200000

/* ctrl() values */

#define		EVP_CTRL_INIT			0x0
#define 	EVP_CTRL_SET_KEY_LENGTH		0x1
#define 	EVP_CTRL_GET_RC2_KEY_BITS	0x2
#define 	EVP_CTRL_SET_RC2_KEY_BITS	0x3
#define 	EVP_CTRL_GET_RC5_ROUNDS		0x4
#define 	EVP_CTRL_SET_RC5_ROUNDS		0x5
#define 	EVP_CTRL_RAND_KEY		0x6
#define 	EVP_CTRL_PBE_PRF_NID		0x7
#define 	EVP_CTRL_COPY			0x8
#define 	EVP_CTRL_GCM_SET_IVLEN		0x9
#define 	EVP_CTRL_GCM_GET_TAG		0x10
#define 	EVP_CTRL_GCM_SET_TAG		0x11
#define		EVP_CTRL_GCM_SET_IV_FIXED	0x12
#define		EVP_CTRL_GCM_IV_GEN		0x13
#define		EVP_CTRL_CCM_SET_IVLEN		EVP_CTRL_GCM_SET_IVLEN
#define		EVP_CTRL_CCM_GET_TAG		EVP_CTRL_GCM_GET_TAG
#define		EVP_CTRL_CCM_SET_TAG		EVP_CTRL_GCM_SET_TAG
#define		EVP_CTRL_CCM_SET_L		0x14
#define		EVP_CTRL_CCM_SET_MSGLEN		0x15
/* AEAD cipher deduces payload length and returns number of bytes
 * required to store MAC and eventual padding. Subsequent call to
 * EVP_Cipher even appends/verifies MAC.
 */
#define		EVP_CTRL_AEAD_TLS1_AAD		0x16
/* Used by composite AEAD ciphers, no-op in GCM, CCM... */
#define		EVP_CTRL_AEAD_SET_MAC_KEY	0x17
/* Set the GCM invocation field, decrypt only */
#define		EVP_CTRL_GCM_SET_IV_INV		0x18

struct evp_cipher_st;
struct evp_cipher_ctx_st;
typedef struct evp_cipher_st EVP_CIPHER;
typedef struct evp_cipher_ctx_st EVP_CIPHER_CTX;


struct evp_cipher_st {
    int nid;
    int block_size;
    int key_len;        /* Default value for variable length ciphers */
    int iv_len;
    unsigned long flags;    /* Various flags */
    int (*init)(EVP_CIPHER_CTX *ctx, const unsigned char *key,
            const unsigned char *iv, int enc);    /* init key */
    int (*do_cipher)(EVP_CIPHER_CTX *ctx, unsigned char *out,
             const unsigned char *in, size_t inl);/* encrypt/decrypt data */
    int (*cleanup)(EVP_CIPHER_CTX *); /* cleanup ctx */
    int ctx_size;        /* how big ctx->cipher_data needs to be */
    //int (*set_asn1_parameters)(EVP_CIPHER_CTX *, ASN1_TYPE *); /* Populate a ASN1_TYPE with parameters */
    //int (*get_asn1_parameters)(EVP_CIPHER_CTX *, ASN1_TYPE *); /* Get parameters from a ASN1_TYPE */
    int (*ctrl)(EVP_CIPHER_CTX *, int type, int arg, void *ptr); /* Miscellaneous operations */
    void *app_data;        /* Application data */
} /* EVP_CIPHER */;

struct evp_cipher_ctx_st {
    const EVP_CIPHER *cipher;
    // ENGINE *engine;    /* functional reference if 'cipher' is ENGINE-provided */
    int encrypt;        /* encrypt or decrypt */
    int buf_len;        /* number we have left */

    unsigned char  oiv[EVP_MAX_IV_LENGTH];    /* original iv */
    unsigned char  iv[EVP_MAX_IV_LENGTH];    /* working iv */
    unsigned char buf[EVP_MAX_BLOCK_LENGTH];/* saved partial block */
    int num;                /* used by cfb/ofb/ctr mode */

    void *app_data;        /* application stuff */
    int key_len;        /* May change for variable length cipher */
    unsigned long flags;    /* Various flags */
    void *cipher_data; /* per EVP data */
    int final_used;
    int block_mask;
    unsigned char final[EVP_MAX_BLOCK_LENGTH];/* possible final block */
} /* EVP_CIPHER_CTX */;

#define EVP_CIPHER_CTX_mode(e)		(e->cipher->flags & EVP_CIPH_MODE)


void EVP_CIPHER_CTX_init(EVP_CIPHER_CTX *ctx);
int EVP_CIPHER_CTX_set_padding(EVP_CIPHER_CTX *ctx, int pad);
int EVP_CIPHER_CTX_cleanup(EVP_CIPHER_CTX *c);

int EVP_EncryptInit(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher, const unsigned char *key, const unsigned char *iv);
int EVP_EncryptFinal(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl);
int EVP_EncryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl, const unsigned char *in, int inl);

const EVP_CIPHER *EVP_aes_128_ctr(void);

#endif
