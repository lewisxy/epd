#ifndef _util_h
#define _util_h

// bit masking
#define bit_of(A, O) (*((uint8_t *)(A)) & (1 << (7-(O))))
#define bit_mask_1(A, O) (*((uint8_t *)(A)) |= (1 << (7-(O))))
#define bit_mask_0(A, O) (*((uint8_t *)(A)) &= ~(1 << (7-(O))))

// copy at most n-1 bytes and forcely fill the last bytes to '\0'
char *secure_strncpy(char *dest, const char *src, size_t n);

// in order to fix the paranoid bug of realloc ...
void *secure_realloc(void *old_ptr, size_t old_size, size_t new_size);

// return the a string that is the duplication of s
char *dupstr(const char *s);

// return a freeable string buffer that join the n strings given
char *joinstr(int n, ...);

// dump the buffer pointed by ptr with size in hex form printed in stdout
void dump_bin(void *ptr, size_t size);

// Write a NULL-terminated array of strings with a newline after each.
void multiputs(const char **s, FILE *f);

// check whether a file exist, return 1 when exist, 0 when not
int file_exists(char *filename);

// return the file size of a file, f is expected to be opened in "rb" mode
// but other modes should work as well
long file_size(FILE *f);

// convert a hex string to bytes
// return the number of byte converted
int hex_to_byte(char *hex_str, char **bytes);

// safely convert string to number, return 0 if failed
int str_to_int(char *str, int *num);

// rtn is a pointer of a list of strings
// the number of strings on rtn is indicated by the return value
// currently support only single char delimiter
// suppose you call like this: split_str(str, ' ', &rtn);
// you need to free rtn[0] and rtn during clean up
int split_str(char *str, char delim, char ***rtn);

// print the prompt and get the input from stdin and write to buf with max size of len
// return 1 on success, return 0 on failure
int get_input(char *buf, size_t len, char *prompt);

// ask for confirmation, return 1 when confirmed, return 0 when failed
int get_confirm(char *prompt);

#endif
