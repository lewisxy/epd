#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdint.h>

#include "crypto.h"
#include "util.h"

// copy at most n-1 characters and placed a '\0' in the end of dest
char *secure_strncpy(char *dest, const char *src, size_t n)
{
	size_t i;

	for (i = 0; i < n-1 && src[i] != '\0'; i++)
        dest[i] = src[i];
    for ( ; i < n; i++)
        dest[i] = '\0';

	return dest;
}

// in order to fix the paranoid bug of realloc ...
void *secure_realloc(void *old_ptr, size_t old_size, size_t new_size)
{
	// allocate and initialize new memory
	void *new_ptr = malloc(new_size);
	if(!new_ptr) return NULL;
	memset(new_ptr, 0, new_size);
	
	// copy the old to new
	if(new_size > old_size) {
		memcpy(new_ptr, old_ptr, old_size);
	} else {
		memcpy(new_ptr, old_ptr, new_size);
	}
	
	// set clean up the old memory
	memset(old_ptr, 0, old_size);
	free(old_ptr);
	
	return new_ptr;
}

/**
 * Return a copy of S, which may be NULL.
 * Abort the program if out of memory.
 */
char *dupstr(const char *s)
{
    char *copy = 0;
    if (s) {
        size_t len = strlen(s) + 1;
        copy = malloc(len);
        if (!copy) {
            printf("out of memory");
            exit(EXIT_FAILURE);
        }
        memcpy(copy, s, len);
    }
    return copy;
}

/**
 * Concatenate N strings as a new string.
 * Abort the program if out of memory.
 */
char *joinstr(int n, ...)
{
    int i;
    va_list ap;
    char *p, *str;
    size_t len = 1;

    va_start(ap, n);
    for (i = 0; i < n; i++) {
        char *s = va_arg(ap, char *);
        len += strlen(s);
    }
    va_end(ap);
	
    p = str = malloc(len);
    if (!str) {
        printf("%s", "out of memory");
		exit(EXIT_FAILURE);
	}
	
    va_start(ap, n);
    for (i = 0; i < n; i++) {
        char *s = va_arg(ap, char *);
        size_t slen = strlen(s);
        memcpy(p, s, slen);
        p += slen;
    }
    va_end(ap);

    *p = 0;
    return str;
}

void dump_bin(void *ptr, size_t size)
{
	size_t i;
	for(i = 0; i < size; i++) {
		printf("%02x", ((unsigned char *)ptr)[i]);
	}
}

/**
 * Write a NULL-terminated array of strings with a newline after each.
 */
void multiputs(const char **s, FILE *f)
{
    while (*s) {
        fputs(*s++, f);
        fputc('\n', f);
    }
}

/**
 * Return 1 if file exists, or 0 if it doesn't.
 */
int file_exists(char *filename)
{
    FILE *f = fopen(filename, "r");
    if (f) {
        fclose(f);
        return 1;
    }
    return 0;
}

long file_size(FILE *f)
{
	if(f) {
		fseek(f, 0, SEEK_END);
		long fsize = ftell(f);
		fseek(f, 0, SEEK_SET);
		return fsize;
	} else {
		return -1;
	}
}

/**
 * Print a nice fingerprint of a key.
 */
void print_fingerprint(const char *key)
{
    int i;
    uint8_t hash[32];
    SHA256_CTX sha[1];

    sha256_init(sha);
    sha256_update(sha, (uint8_t *)key, 32);
    sha256_final(sha, hash);
    for (i = 0; i < 16; i += 4) {
        unsigned long chunk =
            ((unsigned long)hash[i + 0] << 24) |
            ((unsigned long)hash[i + 1] << 16) |
            ((unsigned long)hash[i + 2] <<  8) |
            ((unsigned long)hash[i + 3] <<  0);
        printf("%s%08lx", i ? "-" : "", chunk);
    }
}

int hex_to_byte(char *hex_str, char **bytes)
{
	int len = strlen(hex_str);
	
	if(len % 2 == 1 || len < 2) {
		fprintf(stderr, "illegal input string\n");
		return 0;
	}
	
	int byte_len = len/2;
	char *buf = malloc(byte_len);
	if(!buf) return 0;
	
	int i, res = 0;
	char tmp[3] = {'\0'};
	for(i = 0; i < byte_len; i++) {
		memcpy(tmp, &hex_str[i*2], 2);
		res = sscanf(tmp, "%hhx", buf+i);
		if(res <= 0) {
			fprintf(stderr, "conversion failed\n");
			free(buf);
			buf = NULL;
			return 0;
		}
	}
	*bytes = buf;
	return byte_len;
}

int str_to_int(char *str, int *num)
{
	int res = atoi(str);
	// if input is a 0 ...
	if(!res) {
		if(sscanf(str, "%d", &res)) {
			*num = res;
			return 1;
		} else {
			return 0;
		}
	}
	*num = res;
	return 1;
}

// rtn is a pointer of a list of strings
// the number of strings on rtn is indicated by the return value
// currently support only single char delimiter
int split_str(char *str, char delim, char ***rtn)
{
	size_t prio = 0, len = strlen(str), count = 0;
	int i = 0;
	char **buf = NULL;
	char *copy = NULL;
	int *buf2 = NULL;
	
	// make a copy of the string and set the delimter as terminator
	copy = malloc(len+1);
	if(!copy) return 0;
	memcpy(copy, str, len);
	copy[len] = '\0';
	
	int newlen = 0;
	for(i = 0; i < len; i++) {
		if(copy[i] == delim) {
			copy[i] = '\0';
			newlen++;
		}
	}
	newlen = len - newlen;
	
	// buf2 record the start point of every substring
	buf2 = calloc(sizeof(int), len);
	if(!buf2) { free(copy); return 0; }
	// initialize buf2 to -1
	for(i = 0; i < len; i++) {
		buf2[i] = -1;
	}
	i = 0;
	
	// trim the delimeter before the string
	while(str[i] == delim && i < len) {
		i++;
	}
	prio = i;
	buf2[0] = i;
	count++;
	//printf("%d ", i);
	
	for(; i < len; i++) {
		if(str[i] != delim) {
			if(i > prio+1) {
				buf2[count] = i;
				count++;
				//printf("%d ", i);
			}
			prio = i;
		}
	}
	
	// copy the string to return buffer
	buf = calloc(sizeof(char *), count);
	if(!buf) { free(copy); free(buf2); return 0;}
	
	for(i = 0; i < count; i++) {
		buf[i] = NULL;
	}
	
	// include the termination byte
	newlen += count;
	
	// the buffer that will be inserted as value of buf
	char *buf3 = malloc(newlen);
	if(!buf3) { free(copy); free(buf2); free(buf); return 0;}
	memset(buf3, 0, newlen);
	//buf[0] = buf3;
	
	int count2 = 0;
	for(i = 0; i < count; i++) {
		if(buf2[i] >= 0) {
			buf[i] = buf3 + count2;
			strcpy(buf3+count2, copy+buf2[i]);
			count2 += (strlen(copy+buf2[i])+1);
		}
	}
	
	free(copy);
	free(buf2);
	
	*rtn = buf;
	return count;
}

int get_input(char *buf, size_t len, char *prompt)
{
    size_t slen;
    fputs(prompt, stderr);
    fflush(stderr);
    if (!fgets(buf, len, stdin))
        return 0;
    slen = strlen(buf);
    if (buf[slen - 1] < ' ')
        buf[slen - 1] = 0;
	return 1;
}

int get_confirm(char *prompt)
{
	char buf;
	fprintf(stderr, "%s (press \'y\' to confirm): ", prompt);
    fflush(stderr);
	buf = fgetc(stdin);
	if(buf == 'y' || buf == 'Y') {
		return 1;
	} else {
		return 0;
	}
}
