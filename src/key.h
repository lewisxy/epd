#ifndef _key_h
#define _key_h

#include "stream.h"

#define EP_KEY_FILE_SIZE 160
#define EP_KEY_DERIVE_ITERATIONS 25
#define EP_KEY_PASS_MAX 1024

int key_create(stream **st);
int key_load_pub(stream *st, char *pub);
int key_load_sec(stream *st, char *sec);
int key_change_pw(stream *st);

// utility
void get_passphrase(char *buf, size_t len, char *prompt);

#endif