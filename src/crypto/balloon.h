#include <stdbool.h>
#include <stdint.h>
#include <openssl/sha.h>
#include "balloon-aes.h"
#include "balloon-evp.h"

#ifdef __cplusplus
extern "C" {
#endif

#define BITSTREAM_BUF_SIZE ((32) * (AES_BLOCK_SIZE))
#define N_NEIGHBORS (3)
#define SALT_LEN (32)
#define INLEN_MAX (1ull<<20)
#define TCOST_MIN 1ull
#define SCOST_MIN (1)
#define SCOST_MAX (UINT32_MAX)
#define BLOCKS_MIN (1ull)
#define THREADS_MAX 4096
#define BLOCK_SIZE (32)
#define UNUSED __attribute__ ((unused))

struct bitstream {
  bool initialized;
  uint8_t *zeros;
  SHA256_CTX c;
  EVP_CIPHER_CTX ctx;
};

struct hash_state;

struct hash_state {
  uint64_t counter;
  uint64_t n_blocks;
  bool has_mixed;
  uint8_t *buffer;
  struct bitstream bstream;
  const struct balloon_options *opts;
};

void balloon_hash (const void* input, void* output);
void hash_state_init (struct hash_state *s, const struct balloon_options *opts, const uint8_t salt[SALT_LEN]);
void hash_state_free (struct hash_state *s);
void hash_state_fill (struct hash_state *s, const uint8_t *in, size_t inlen);
void hash_state_mix (struct hash_state *s);
void hash_state_extract (const struct hash_state *s, uint8_t out[BLOCK_SIZE]);

#ifdef __cplusplus
}
#endif
