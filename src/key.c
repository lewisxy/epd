#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "db.h" // to access some defined constants. (Will change in the future)

#include "util.h"
#include "stream.h"
#include "crypto.h"
#include "key.h"

// get_passphrase from enchive
/**
 * Read a passphrase directly from the keyboard without echo.
 */
void get_passphrase(char *buf, size_t len, char *prompt);

/**
 * Read a passphrase without any fanfare (fallback).
 */
void
get_passphrase_dumb(char *buf, size_t len, char *prompt)
{
    size_t passlen;
    printf("warning: eading passphrase from stdin with echo");
    fputs(prompt, stderr);
    fflush(stderr);
    if (!fgets(buf, len, stdin)) {
        printf("could not read passphrase");
		exit(EXIT_FAILURE);
	}
    passlen = strlen(buf);
    if (buf[passlen - 1] < ' ')
        buf[passlen - 1] = 0;
}

#if defined(__unix__) || defined(__APPLE__)
#include <fcntl.h>
#include <unistd.h>
#include <termios.h>
#include <errno.h>

void
get_passphrase(char *buf, size_t len, char *prompt)
{
    int tty;

    tty = open("/dev/tty", O_RDWR);
    if (tty == -1) {
        get_passphrase_dumb(buf, len, prompt);
    } else {
        char newline = '\n';
        size_t i = 0;
        struct termios old, new;
        if (write(tty, prompt, strlen(prompt)) == -1) {
            printf("error asking for passphrase");
			exit(EXIT_FAILURE);
		}
        tcgetattr(tty, &old);
        new = old;
        new.c_lflag &= ~ECHO;
        tcsetattr(tty, TCSANOW, &new);
        errno = 0;
        while (i < len - 1 && read(tty, buf + i, 1) == 1) {
            if (buf[i] == '\n' || buf[i] == '\r')
                break;
            i++;
        }
        buf[i] = 0;
        tcsetattr(tty, TCSANOW, &old);
        if (write(tty, &newline, 1) == -1) {
            printf("error asking for passphrase");
			exit(EXIT_FAILURE);
		}
        close(tty);
        if (errno) {
            printf("could not read passphrase from /dev/tty");
			exit(EXIT_FAILURE);
		}
    }
}

#elif defined(_WIN32)
#include <windows.h>

void
get_passphrase(char *buf, size_t len, char *prompt)
{
    DWORD orig;
    HANDLE in = GetStdHandle(STD_INPUT_HANDLE);
    if (!GetConsoleMode(in, &orig)) {
        get_passphrase_dumb(buf, len, prompt);
    } else {
        size_t passlen;
        SetConsoleMode(in, orig & ~ENABLE_ECHO_INPUT);
        fputs(prompt, stderr);
        if (!fgets(buf, len, stdin)) {
            printf("could not read passphrase");
			exit(EXIT_FAILURE);
		}
        fputc('\n', stderr);
        passlen = strlen(buf);
        if (buf[passlen - 1] < ' ')
            buf[passlen - 1] = 0;
		// reset console to normal after entering password
		SetConsoleMode(in, orig);
	}
}

#else
void
get_passphrase(char *buf, size_t len, char *prompt)
{
    get_passphrase_dumb(buf, len, prompt);
}
#endif

/* Layout of key file 
public key 0-31 (32 bytes)
private key 32-95 (64 bytes)
signature of previous bytes 95-159 (64 bytes)
*/

/* Layout of secret key portion */
#define SECFILE_IV            0
#define SECFILE_ITERATIONS    8
#define SECFILE_PROTECT_HASH  9
#define SECFILE_SECKEY        32

int key_create(stream **st)
{
	int iexp = EP_KEY_DERIVE_ITERATIONS;
	
	char pub[EP_KEY_SIZE], sec[EP_KEY_SIZE];
	
	crypto_curve_generate_secret(sec);
	crypto_curve_compute_public(pub, sec);
	
	/* printf("pub: ");
	dump_bin(pub, 32);
	printf("\n");
	printf("sec: ");
	dump_bin(sec, 32);
	printf("\n"); */
	
	stream *st1 = stream_create(100, -1);
	//write public key
	if(!st1 || !stream_write(pub, EP_KEY_SIZE, 1, st1)) {
		printf("Failed to write public key to stream");
		return 0;
	}
	
    chacha_ctx cha[1];
	char protect[EP_KEY_SIZE];
		
    char buf[8 + 1 + 23 + 32] = {'\0'}; /* entire file contents */

    char *buf_iv           = buf + SECFILE_IV;
    char *buf_iterations   = buf + SECFILE_ITERATIONS;
    char *buf_protect_hash = buf + SECFILE_PROTECT_HASH;
    char *buf_seckey       = buf + SECFILE_SECKEY;

    if (iexp) {
        /* Prompt for a passphrase. */
        char pass[2][EP_KEY_PASS_MAX];
        get_passphrase(pass[0], sizeof(pass[0]),
                       "protection passphrase (empty for none): ");
        if (!pass[0][0]) {
            /* Nevermind. */
            iexp = 0;
        }  else {
            get_passphrase(pass[1], sizeof(pass[0]),
                           "protection passphrase (repeat): ");
            if (strcmp(pass[0], pass[1]) != 0) {
                printf("protection passphrases don't match");
				return 0;
			}

            /* Generate an IV to double as salt. */
            crypto_rand(buf_iv, 8);

            crypto_key_derive(pass[0], protect, iexp, buf_iv);
            buf_iterations[0] = iexp;

			crypto_sha256(protect, sizeof(protect), buf_protect_hash);
        }
    }

    if (iexp) {
        /* Encrypt using key derived from passphrase. */
		crypto_stream_init(cha, protect, buf_iv);
		crypto_stream_compute(cha, sec, buf_seckey, EP_KEY_SIZE);
    } else {
        /* Copy key to output buffer. */
        memcpy(buf_seckey, sec, EP_KEY_SIZE);
    }
	
	if(!stream_write(buf, sizeof(buf), 1, st1)) {
		printf("Failed to write private key to stream");
		return 0;
	}
	
	char sign[64];
	if(!crypto_curve_sign(sign, st1->buf, st1->cursor_pos, sec) || \
		!crypto_curve_verify(sign, st1->buf, st1->cursor_pos, pub)) {
		printf("Failed to create sign");
		return 0;
	}
	
	if(!stream_write(sign, sizeof(sign), 1, st1)) {
		printf("Failed to write signature to stream");
		return 0;
	}
	
	*st = st1;
	return 1;
}

//void key_write(char *filename, char *pub, char *sec);
int key_load_pub(stream *st, char *pub)
{
	// full bufffer of the key
	char buf[EP_KEY_SIZE * 5];
	
	stream_setpos(st, 0L);
	if(!stream_read(buf, sizeof(buf), 1, st)) {
		printf("Failed to read key from stream");
		return 0;
	}
	
	/* verify public key with signature */
	if(!crypto_curve_verify(buf + 32 + 64, buf, 32 + 64, buf)) {
		printf("Signature verification failed, keyfile is corrupted");
		return 0;
	}
	
	memcpy(pub, buf, EP_KEY_SIZE);
	
	return 1;
}

int key_load_sec(stream *st, char *sec)
{
	int iexp = EP_KEY_DERIVE_ITERATIONS;
	
	stream_setpos(st, 0L);
	/* verify public key with signature */
	if(!crypto_curve_verify(st->buf + 32 + 64, st->buf, 32 + 64, st->buf)) {
		printf("Signature verification failed, keyfile is corrupted");
		return 0;
	}
	
	stream_setpos(st, 32L);
	
    chacha_ctx cha[1];
	char protect[EP_KEY_SIZE];
	char protect_hash[EP_HASH_SIZE];
		
    char buf[8 + 1 + 23 + 32] = {'\0'}; /* entire file contents */

    char *buf_iv           = buf + SECFILE_IV;
    char *buf_iterations   = buf + SECFILE_ITERATIONS;
    char *buf_protect_hash = buf + SECFILE_PROTECT_HASH;
    char *buf_seckey       = buf + SECFILE_SECKEY;

    if(!stream_read(buf, sizeof(buf), 1, st)) {
		printf("Failed to read buffer");
		return 0;
	}
	
    iexp = buf_iterations[0];
    if (iexp) {
        /* Secret key is encrypted. */
        /* Ask user for passphrase. */
        char pass[EP_KEY_PASS_MAX];
        get_passphrase(pass, sizeof(pass), "passphrase: ");
        crypto_key_derive(pass, protect, iexp, buf_iv);

        /* Validate passphrase. */
		crypto_sha256(protect, sizeof(protect), protect_hash);
        if (memcmp(protect_hash, buf_protect_hash, 23) != 0) {
            printf("wrong passphrase");
			return 0;
		}
        /* Decrypt the key into the output. */
		crypto_stream_init(cha, protect, buf_iv);
		crypto_stream_compute(cha, buf_seckey, sec, EP_KEY_SIZE);
    } else {
        /* Key is unencrypted, copy into output. */
        memcpy(sec, buf_seckey, EP_KEY_SIZE);
    }
	return 1;
}

int key_change_pw(stream *st)
{
	int iexp = EP_KEY_DERIVE_ITERATIONS;
	
	char pub[EP_KEY_SIZE], sec[EP_KEY_SIZE], protect_hash[EP_HASH_SIZE];
	
	if(!key_load_pub(st, pub)) {
		printf("failed to load public key");
		return 0;
	}
	if(!key_load_sec(st, sec)) {
		printf("failed to load secret key");
		return 0;
	}
	
    chacha_ctx cha[1];
	char protect[EP_KEY_SIZE];
		
    char buf[8 + 1 + 23 + 32] = {'\0'}; /* entire file contents */

    char *buf_iv           = buf + SECFILE_IV;
    char *buf_iterations   = buf + SECFILE_ITERATIONS;
    char *buf_protect_hash = buf + SECFILE_PROTECT_HASH;
    char *buf_seckey       = buf + SECFILE_SECKEY;
	
	// set new password
	if (iexp) {
        /* Prompt for a passphrase. */
        char pass[2][EP_KEY_PASS_MAX];
        get_passphrase(pass[0], sizeof(pass[0]),
                       "new passphrase (empty for none): ");
        if (!pass[0][0]) {
            /* Nevermind. */
            iexp = 0;
        }  else {
            get_passphrase(pass[1], sizeof(pass[0]),
                           "new passphrase (repeat): ");
            if (strcmp(pass[0], pass[1]) != 0) {
                printf("protection passphrases don't match");
				return 0;
			}

            /* Generate an IV to double as salt. */
            crypto_rand(buf_iv, 8);

            crypto_key_derive(pass[0], protect, iexp, buf_iv);
            buf_iterations[0] = iexp;

			crypto_sha256(protect, sizeof(protect), buf_protect_hash);
        }
    }

    if (iexp) {
        /* Encrypt using key derived from passphrase. */
		crypto_stream_init(cha, protect, buf_iv);
		crypto_stream_compute(cha, sec, buf_seckey, EP_KEY_SIZE);
    } else {
        /* Copy key to output buffer. */
        memcpy(buf_seckey, sec, EP_KEY_SIZE);
    }
	
	stream_setpos(st, 32L);
	// write new buf
	if(!stream_write(buf, sizeof(buf), 1, st)) {
		printf("Failed to write private key to stream");
		return 0;
	}
	
	// generate new sign
	char sign[64];
	if(!crypto_curve_sign(sign, st->buf, st->cursor_pos, sec) || \
		!crypto_curve_verify(sign, st->buf, st->cursor_pos, pub)) {
		printf("Failed to create sign");
		return 0;
	}
	
	if(!stream_write(sign, sizeof(sign), 1, st)) {
		printf("Failed to write signature to stream");
		return 0;
	}
	
	return 1;
}
