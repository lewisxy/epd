int crypto_hash_sha512(unsigned char *out,const unsigned char *in,unsigned long long inlen);
void curve25519_keygen(unsigned char* curve25519_pubkey_out, /* 32 bytes */
                       const unsigned char* curve25519_privkey_in); /* 32 bytes */

/* returns 0 on success */
int curve25519_sign(unsigned char* signature_out, /* 64 bytes */
                     const unsigned char* curve25519_privkey, /* 32 bytes */
                     const unsigned char* msg, const unsigned long msg_len,
                     const unsigned char* random); /* 64 bytes */

/* returns 0 on success */
int curve25519_verify(const unsigned char* signature, /* 64 bytes */
                      const unsigned char* curve25519_pubkey, /* 32 bytes */
                      const unsigned char* msg, const unsigned long msg_len);