#ifndef _crypto_h
#define _crypto_h

#include "chacha.h"
#include "sha256.h"
#include "ed.h"

// cryptographic hash
void crypto_sha256(char *data, const size_t size, char *hash);
void crypto_sha256_hmac(char *data, const size_t size, char *key, char *hash);

// secure random generator
void crypto_rand(char *buf, size_t len);

// stream cipher
void crypto_stream_init(chacha_ctx *ctx, const char *key, const char *iv);
void crypto_stream_compute(chacha_ctx *ctx, char *in, char *out, size_t size);

// curve cryptography
void crypto_curve_generate_secret(char *sec);
void crypto_curve_compute_public(char *pub, const char *sec);
void crypto_curve_compute_shared(char *shared, const char *sec, const char *pub);
// from: https://github.com/rafalsk/ref10_extract
// from: https://moderncrypto.org/mail-archive/curves/2014/000205.html
// signature are 64 bytes, maximum message length is 256 bytes
// this is a non-deterministic function that has build in random from crypto_rand
// return 1 on success, 0 on failure
int crypto_curve_sign(char *signature, char *msg, size_t size, char *sec);
int crypto_curve_verify(char *signature, char *msg, size_t size, char *pub);

// key deviation
void crypto_key_derive(const char *passphrase, char *buf, int iexp, const char *salt);

// low-level interface
void hmac_init(SHA256_CTX *ctx, const uint8_t *key);
void hmac_final(SHA256_CTX *ctx, const uint8_t *key, uint8_t *hash);
// from sha256.h
void sha256_init(SHA256_CTX *ctx);
void sha256_update(SHA256_CTX *ctx, const uint8_t data[], size_t len);
void sha256_final(SHA256_CTX *ctx, uint8_t hash[]);

#endif