#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// crypto utilities
#include "sha256.h"
#include "chacha.h"
#include "ed.h"

int curve25519_donna(uint8_t *p, const uint8_t *s, const uint8_t *b);

/**
 * Get secure entropy suitable for key generation from OS.
 * Abort the program if the entropy could not be retrieved.
 */
static void secure_entropy(void *buf, size_t len);

#if defined(__unix__) || defined(__APPLE__)
static void
secure_entropy(void *buf, size_t len)
{
    FILE *r = fopen("/dev/urandom", "rb");
    if (!r) {
		printf("failed to open %s", "/dev/urandom");
        abort();
	}
    if (!fread(buf, len, 1, r)) {
        printf("failed to gather entropy");
		abort();
	}
    fclose(r);
}

#elif defined(_WIN32)
#include <windows.h>

static void
secure_entropy(void *buf, size_t len)
{
    HCRYPTPROV h = 0;
    DWORD type = PROV_RSA_FULL;
    DWORD flags = CRYPT_VERIFYCONTEXT | CRYPT_SILENT;
    if (!CryptAcquireContext(&h, 0, 0, type, flags) ||
        !CryptGenRandom(h, len, buf)) {
        printf("failed to gather entropy");
		abort();
	}
    CryptReleaseContext(h, 0);
}
#endif

/**
 * Initialize a SHA-256 context for HMAC-SHA256.
 * All message data will go into the resulting context.
 */
void hmac_init(SHA256_CTX *ctx, const uint8_t *key)
{
    int i;
    uint8_t pad[SHA256_BLOCK_SIZE];
    sha256_init(ctx);
    for (i = 0; i < SHA256_BLOCK_SIZE; i++)
        pad[i] = key[i] ^ 0x36U;
    sha256_update(ctx, pad, sizeof(pad));
}

/**
 * Compute the final HMAC-SHA256 MAC.
 * The key must be the same as used for initialization.
 */
void hmac_final(SHA256_CTX *ctx, const uint8_t *key, uint8_t *hash)
{
    int i;
    uint8_t pad[SHA256_BLOCK_SIZE];
    sha256_final(ctx, hash);
    sha256_init(ctx);
    for (i = 0; i < SHA256_BLOCK_SIZE; i++)
        pad[i] = key[i] ^ 0x5cU;
    sha256_update(ctx, pad, sizeof(pad));
    sha256_update(ctx, hash, SHA256_BLOCK_SIZE);
    sha256_final(ctx, hash);
}

void crypto_sha256(char *data, const size_t size, char *hash)
{
	SHA256_CTX ctx[1];
	size_t data_cursor = 0, cur_block_size = SHA256_BLOCK_SIZE;
	
	sha256_init(ctx);
	
	while(data_cursor < size) {
		cur_block_size = (size - data_cursor > SHA256_BLOCK_SIZE) ? SHA256_BLOCK_SIZE : size - data_cursor;
		//printf("current block size: %lld\n", cur_block_size);
		sha256_update(ctx, (uint8_t *)(data+data_cursor), cur_block_size);
		data_cursor += cur_block_size;
	}
	
	sha256_final(ctx, (uint8_t *)hash);
}

void crypto_sha256_hmac(char *data, const size_t size, char *key, char *hash)
{
	SHA256_CTX ctx[1];
	size_t data_cursor = 0, cur_block_size = SHA256_BLOCK_SIZE;
	
	hmac_init(ctx, (uint8_t *)key);
	
	while(data_cursor < size) {
		cur_block_size = (size - data_cursor > SHA256_BLOCK_SIZE) ? SHA256_BLOCK_SIZE : size - data_cursor;
		//printf("current block size: %lld\n", cur_block_size);
		sha256_update(ctx, (uint8_t *)(data+data_cursor), cur_block_size);
		data_cursor += cur_block_size;
	}
	
	hmac_final(ctx, (uint8_t *)key, (uint8_t *)hash);
}

void crypto_rand(char *buf, size_t len)
{
	secure_entropy(buf, len);
}

void crypto_stream_init(chacha_ctx *ctx, const char *key, const char *iv)
{
	chacha_keysetup(ctx, (uint8_t *)key, 256);
    chacha_ivsetup(ctx, (uint8_t *)iv);
}

void crypto_stream_compute(chacha_ctx *ctx, char *in, char *out, size_t size)
{
	size_t data_cursor = 0, cur_block_size = CHACHA_BLOCKLENGTH;
	
	while(data_cursor < size) {
		cur_block_size = (size - data_cursor > CHACHA_BLOCKLENGTH) ? CHACHA_BLOCKLENGTH : size - data_cursor;
		//printf("current block size: %lld\n", cur_block_size);
		chacha_encrypt(ctx, (uint8_t *)in+data_cursor, (uint8_t *)out+data_cursor, cur_block_size);
		data_cursor += cur_block_size;
	}
}

/**
 * Generate a brand new Curve25519 secret key from system entropy.
 */
void crypto_curve_generate_secret(char *sec)
{
    secure_entropy(sec, 32);
    sec[0] &= 248;
    sec[31] &= 127;
    sec[31] |= 64;
}

/**
 * Generate a Curve25519 public key from a secret key.
 */
void crypto_curve_compute_public(char *pub, const char *sec)
{
    static const uint8_t b[32] = {9};
    curve25519_donna((uint8_t *)pub, (uint8_t *)sec, b);
}

/**
 * Compute a shared secret from our secret key and their public key.
 */
void crypto_curve_compute_shared(char *shared, const char *sec, const char *pub)
{
    curve25519_donna((uint8_t *)shared, (uint8_t *)sec, (uint8_t *)pub);
}

// signature are 64 bytes, maximum message length is 256 bytes
// this is a non-deterministic function that has build in random from crypto_rand
int crypto_curve_sign(char *signature, char *msg, size_t size, char *sec)
{
	unsigned char buf[64];
	crypto_rand((char *)buf, 64);
	if(curve25519_sign((unsigned char *)signature, (unsigned char *)sec, (unsigned char *)msg, (unsigned long long)size, buf) != 0) {
		printf("signing failed\n");
		return 0;
	}
	
	//printf("signing complete\n");
	return 1;
}

// return 1 on success, 0 on failure
int crypto_curve_verify(char *signature, char *msg, size_t size, char *pub)
{
	if(curve25519_verify((unsigned char *)signature, (unsigned char *)pub, (unsigned char *)msg, (unsigned long long)size) != 0) {
		//printf("sign verify failed\n");
		return 0;
	}

	//printf("sign verified\n");
	return 1;
}

/**
 * Derive a 32-byte key from null-terminated passphrase into buf.
 * Optionally provide an 8-byte salt.
 */
void crypto_key_derive(const char *passphrase, char *buf, int iexp, const char *salt)
{
    uint8_t salt32[SHA256_BLOCK_SIZE] = {0};
    SHA256_CTX ctx[1];
    unsigned long i;
    unsigned long memlen = 1UL << iexp;
    unsigned long mask = memlen - 1;
    unsigned long iterations = 1UL << (iexp - 5);
    uint8_t *memory, *memptr, *p;

    memory = malloc(memlen + SHA256_BLOCK_SIZE);
	// this part need further improvement
    if (!memory) {
        printf("not enough memory for key derivation");
		abort();
	}

    if (salt)
        memcpy(salt32, salt, 8);
    hmac_init(ctx, salt32);
    sha256_update(ctx, (uint8_t *)passphrase, strlen(passphrase));
    hmac_final(ctx, salt32, memory);

    for (p = memory + SHA256_BLOCK_SIZE;
         p < memory + memlen + SHA256_BLOCK_SIZE;
         p += SHA256_BLOCK_SIZE) {
        sha256_init(ctx);
        sha256_update(ctx, p - SHA256_BLOCK_SIZE, SHA256_BLOCK_SIZE);
        sha256_final(ctx, p);
    }

    memptr = memory + memlen - SHA256_BLOCK_SIZE;
    for (i = 0; i < iterations; i++) {
        unsigned long offset;
        sha256_init(ctx);
        sha256_update(ctx, memptr, SHA256_BLOCK_SIZE);
        sha256_final(ctx, memptr);
        offset = ((unsigned long)memptr[3] << 24 |
                  (unsigned long)memptr[2] << 16 |
                  (unsigned long)memptr[1] <<  8 |
                  (unsigned long)memptr[0] <<  0);
        memptr = memory + (offset & mask);
    }

    memcpy(buf, memptr, SHA256_BLOCK_SIZE);
    free(memory);
}

#if defined(CRYPTO_TEST)

void test1() 
{
	/// testing SHA256 functionality on strings
	char hash[32];
	char data[] = "testtesttestttttt";
	
	crypto_sha256(data, sizeof(data)-1, hash); // use -1 to omit the trailing '\0'
	
	printf("hash: ");
	int i;
	for(i = 0; i < 32; i++) {
		printf("%02x", (unsigned char)hash[i]);
	}
}

void test2() 
{
	/// testing SHA256 functionlity on files
	char hash[32];
	FILE *f = fopen("test.bin", "r");
	if(!f) {
		printf("fopen failed\n");
		abort();
	}
	char buf[200];
	int res = fread(buf, 1, 300, f);
	if(res <= 0) {
		printf("fread failed\n");
		abort();
	}
	
	crypto_sha256(buf, res, hash);
	
	printf("hash: ");
	int i;
	for(i = 0; i < 32; i++) {
		printf("%02x", (unsigned char)hash[i]);
	}
	fclose(f);
}

void test3()
{
	/// testing SHA-256 HMAC functionality
	char hmac[32];
	char data[] = "testtesttestttttt";
	char key[] = "abcdefghijklmnopqrstuvwxy512345";//simulate 32 bytes key
	
	crypto_sha256_hmac(data, sizeof(data)-1, key, hmac); // use -1 to omit the trailing '\0'
	
	printf("hmac: ");
	int i;
	for(i = 0; i < 32; i++) {
		printf("%02x", (unsigned char)hmac[i]);
	}
}

void test4()
{
	/// testing crypto_rand functionality
	/// (Note: the result from CryptoGenRandom (on Windows) does not output
	/// random numbers that has a mean value of 127.5, but instead have a mean 
	/// value close to 127, not yet sure why, but shouldn't be a big issue 
	size_t size = 1 << 20;
	
	FILE *tfile = fopen("random_file", "wb");
	char *buf = malloc(size);
	crypto_rand(buf, size);
	fwrite(buf, 1, size, tfile);
	fclose(tfile);
	free(buf);
}

void test5()
{
	/// testing chacha20 stream cipher (encryption and decryption)
	char key[] = "zyxabcdefghijklmnopqrstuvw09876";
	char iv[] = "k83nf872";
	char data[] = "testtesttest!!!";
	char buf[2][100] = {'\0'};
	chacha_ctx ctx;
	crypto_stream_init(&ctx, key, iv);
	crypto_stream_compute(&ctx, data, buf[0], sizeof(data));
	int i;
	for(i = 0; i < sizeof(data); i++) {
		printf("%02x", (unsigned char)buf[0][i]);
	}
	printf("\n");
	
	chacha_ctx ctx2;
	crypto_stream_init(&ctx2, key, iv);
	crypto_stream_compute(&ctx2, buf[0], buf[1], sizeof(data));
	for(i = 0; i < sizeof(data); i++) {
		printf("%02x", (unsigned char)buf[1][i]);
	}
	printf("\n");
	for(i = 0; i < sizeof(data); i++) {
		printf("%c", buf[1][i]);
	}
	printf("\n");
}

void test6()
{
	/// testing public key systems (elliptical curve cryptography)
	char sec[32], pub[32], esec[32], epub[32], shared1[32], shared2[32];
	crypto_curve_generate_secret(sec);
	crypto_curve_compute_public(pub, sec);
	
	crypto_curve_generate_secret(esec);
	crypto_curve_compute_public(epub, esec);
	
	// shared secret for encryption
	crypto_curve_compute_shared(shared1, esec, pub);
	// shared secret for decryption
	crypto_curve_compute_shared(shared2, sec, epub);
	
	int i;
	printf("pub: ");
	for(i = 0; i < 32; i++) {
		printf("%02x", (unsigned char)pub[i]);
	}
	printf("\nsec: ");
	for(i = 0; i < 32; i++) {
		printf("%02x", (unsigned char)sec[i]);
	}
	printf("\nepub: ");
	for(i = 0; i < 32; i++) {
		printf("%02x", (unsigned char)epub[i]);
	}
	printf("\nesec: ");
	for(i = 0; i < 32; i++) {
		printf("%02x", (unsigned char)esec[i]);
	}
	printf("\nencryption shared: ");
	for(i = 0; i < 32; i++) {
		printf("%02x", (unsigned char)shared1[i]);
	}
	printf("\ndecryption shared: ");
	for(i = 0; i < 32; i++) {
		printf("%02x", (unsigned char)shared2[i]);
	}
	printf("\n");
	
	// verify it
	if(memcmp(shared1, shared2, 32) != 0) {
		printf("shared key comparison failed\n");
	} else {
		printf("shared key comparison succeed\n");
	}
}

void test7()
{
	/// testing the signature
	char sec[32], pub[32], sig[64];
	crypto_curve_generate_secret(sec);
	crypto_curve_compute_public(pub, sec);
	
	char msg[32];
	crypto_sha256(pub, 32, msg);
	
	int i, j;
	for(i = 0; i < 100; i++) {
		crypto_curve_sign(sig, msg, sizeof(msg), sec);
		printf("sig: ");
		for(j = 0; j < 64; j++) {
			printf("%02x", (unsigned char)sig[j]);
		}
		if(crypto_curve_verify(sig, msg, sizeof(msg), pub)) {
			printf("   verified");
		}
		printf("\n");
	}
}

int main()
{
	//test1();// passed
	//printf("\n\n");
	//test2();// passed
	//printf("\n\n");
	//test3();// passed
	//printf("\n\n");
	//test4();// fixed
	// https://stackoverflow.com/questions/50959262/cryptgenrandom-returns-none-uniform-result/
	//printf("\n\n");
	//test5();// passed
	//printf("\n\n");
	//test6();// passed
	test7();
	return 0;
}

#endif
