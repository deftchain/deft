#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>
#include "balloon-aes.h"
#include "balloon-evp.h"
#include "balloon.h"

#ifdef __cplusplus
extern "C"{
#endif

struct balloon_options {
  int64_t s_cost;
  int32_t t_cost;
};

void balloon_hash (const void* input, void* output) {
  struct balloon_options opts;
  struct hash_state s;
  opts.s_cost = 128;
  opts.t_cost = 4;
  hash_state_init (&s, &opts, input);
  hash_state_fill (&s, input, 80);
  hash_state_mix (&s);
  uint8_t *b = s.buffer + 131040;
  memcpy ((char *)output, (const char *)b, 32);
  hash_state_free (&s);
}

void bitstream_init (struct bitstream *b) {
  SHA256_Init(&b->c);
  EVP_CIPHER_CTX_init (&b->ctx);
  b->zeros = malloc (512);
  memset (b->zeros, 0, 512);
}

static inline void bitstream_free (struct bitstream *b) {
  uint8_t out[16];
  int outl;
  EVP_EncryptFinal (&b->ctx, out, &outl);
  EVP_CIPHER_CTX_cleanup (&b->ctx);
  free (b->zeros);
}

void bitstream_seed_add (struct bitstream *b, const void *seed, size_t seedlen) {
  SHA256_Update(&b->c, seed, seedlen);
}

static inline void bitstream_seed_finalize (struct bitstream *b) {
  uint8_t key_bytes[32];
  SHA256_Final (key_bytes, &b->c);
  uint8_t iv[16];
  memset (iv, 0, 16);
  EVP_EncryptInit (&b->ctx, EVP_aes_128_ctr(), key_bytes, iv);
}

void bitstream_fill_buffer (struct bitstream *b, void *out, size_t outlen) {
  int encl;
  EVP_EncryptUpdate (&b->ctx, out, &encl, b->zeros, 8);
}

static void expand (uint64_t *counter, uint8_t *buf) {
  const uint8_t *blocks[1] = { buf };
  uint8_t *cur = buf + 32;
  uint8_t hashmash[40];
  int i;
  SHA256_CTX ctx;
  for (i = 1; i < 4096; i++) {
    SHA256_Init (&ctx);
    memcpy(&hashmash[0], counter, 8);
    memcpy(&hashmash[8], blocks[0], 32);
    SHA256_Update (&ctx, hashmash, 40);
    SHA256_Final (cur, &ctx);
    *counter += 1;
    blocks[0] += 32;
    cur += 32;
  }
}

void hash_state_init (struct hash_state *s, const struct balloon_options *opts, const uint8_t salt[32]) {
  s->counter = 0;
  s->buffer = malloc(131072);
  s->opts = opts;
  bitstream_init (&s->bstream);
  bitstream_seed_add (&s->bstream, salt, 32);
  bitstream_seed_add (&s->bstream, &opts->s_cost, 8);
  bitstream_seed_add (&s->bstream, &opts->t_cost, 4);
  bitstream_seed_finalize (&s->bstream);
}

void hash_state_free (struct hash_state *s) {
  bitstream_free (&s->bstream);
  free (s->buffer);
}

void hash_state_fill (struct hash_state *s, const uint8_t *in, size_t inlen) {
  uint8_t hashmash[132];
  SHA256_CTX c;
  SHA256_Init (&c);
  memcpy(&hashmash[0],&s->counter,8);
  memcpy(&hashmash[8],in,32);
  memcpy(&hashmash[40],in,80);
  memcpy(&hashmash[120],&s->opts->s_cost, 8);
  memcpy(&hashmash[128],&s->opts->t_cost, 4);
  SHA256_Update (&c, hashmash, 132);
  SHA256_Final (s->buffer, &c);
  s->counter++;
  expand (&s->counter, s->buffer);
}

void hash_state_mix (struct hash_state *s) {
  SHA256_CTX ctx;
  uint8_t buf[8];
  uint8_t hashmash[168];
  int i, k;

  for (k=0; k<4; k++) {
    uint64_t neighbor;
    for (i = 0; i < 4096; i++) {
      uint8_t *cur_block = s->buffer + (32 * i);
      const uint8_t *blocks[5];
      const uint8_t *prev_block = i ? cur_block - 32 : s->buffer + 131040;
      blocks[0] = prev_block;
      blocks[1] = cur_block;
      bitstream_fill_buffer (&s->bstream, buf, 8);
      neighbor = (buf[2]<<16)|(buf[1]<<8)|buf[0];
      blocks[2] = s->buffer + (32 * (neighbor % 4096));
      bitstream_fill_buffer (&s->bstream, buf, 8);
      neighbor = (buf[2]<<16)|(buf[1]<<8)|buf[0];
      blocks[3] = s->buffer + (32 * (neighbor % 4096));
      bitstream_fill_buffer (&s->bstream, buf, 8);
      neighbor = (buf[2]<<16)|(buf[1]<<8)|buf[0];
      blocks[4] = s->buffer + (32 * (neighbor % 4096));
      SHA256_Init (&ctx);
      memcpy(&hashmash[0],&s->counter, 8);
      memcpy(&hashmash[8], blocks[0], 32);
      memcpy(&hashmash[40], blocks[1], 32);
      memcpy(&hashmash[72], blocks[2], 32);
      memcpy(&hashmash[104], blocks[3], 32);
      memcpy(&hashmash[136], blocks[4], 32);
      SHA256_Update (&ctx, hashmash, 168);
      SHA256_Final (cur_block, &ctx);
      s->counter += 1;
    }
  }  
}

#ifdef __cplusplus
}
#endif
