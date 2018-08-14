#ifndef _db_h
#define _db_h

#include <stdio.h>
#include <stdint.h>

#include "stream.h"

#include "config.h"

// db structure:
// [iv][epublic][header][table][tag table][HMAC for header table and tag table(32)][data][HMAC for data(32)]
// [header][table][tag table][data] is encrypted

#define EP_FP_SIZE 16

// each table entry has a size of 64 bytes
#define EP_TABLE_NAME_SIZE 16

typedef struct {
	char htag[EP_HTAG_SIZE]; // hash tag of the data entry
	char tag[EP_TAG_SIZE];
	char name[EP_TABLE_NAME_SIZE]; // first 16 bytes of the name of the content, could be used for searching
	char fp[EP_FP_SIZE]; // fingerprint of public key that encrypt value, leave blank to indicate no encryption on value
	char key[EP_KEY_SIZE]; // ephermeral public key, also used as encryption key to data entry
} table_entry;

//#define EP_TABLE_ENTRY_SIZE EP_HTAG_SIZE + EP_TAG_SIZE + EP_TABLE_NAME_SIZE + EP_KEY_SIZE
#define EP_TABLE_ENTRY_SIZE 80

// tag table (in memory) structure
// a list of pointers to strings that contains the tags
// if the tag of that entry does not exist, that pointer will be NULL

// the currently supported maximum tag number is 64
#define EP_TAG_MAX 64
// the maximum size of each tag is 64 bytes
#define EP_TAG_MAX_SIZE 64

#define EP_TAG_DEFAULT "default" // 8 bytes

// tag table (in file) structure
#define TAG_INDEX 0
#define TAG_DATA_SIZE 8 // the size of data portion only, not the whole size
#define TAG_DATA 12
// the rest of the length varies ... (current maximum size is 4096+16)

// EPD database file header layout, total 72 Bytes
#define EP_HEADER_SIZE 72

// header (in file) structure
// [PROG_NAME (3)][FORMAT_VERSION (1)][DATABASE_NAME (64)][HEADER_NENTRY(4)]
#define HEADER_PROG_NAME 0
#define HEADER_FORMAT_VERSION 3
#define HEADER_NAME 4
#define HEADER_NENTRY 68

#define EP_HEADER_NAME_SIZE 64
typedef struct {
	char name[64]; // name of db
	/* do not use size_t!!! 
	it will cause overflow on some x64 systems due to endianness problem */
	uint32_t nentry; // number of entries
	table_entry *table;
	char **tags;
} header;

// each data entry has a size of 520 bytes
#define EP_DATA_ENTRY_NAME_SIZE 128
#define EP_DATA_ENTRY_NOTE_SIZE 256
#define EP_DATA_ENTRY_VALUE_SIZE 128

typedef struct {
	char tag[EP_TAG_SIZE];
	char name[128]; // name of the entry
	char note[256]; // a brief hint of the value, could include usernames and other less sensitive data
	char value[128]; // sensitive value
} data_entry;

// value encryption key = shared(table_key, seckey)
// value encryption iv = first 8 bytes of hash of shared key

//#define EP_DATA_ENTRY_SIZE EP_TAG_SIZE + EP_DATA_ENTRY_NAME_SIZE + EP_DATA_ENTRY_NOTE_SIZE + EP_DATA_ENTRY_VALUE_SIZE
#define EP_DATA_ENTRY_SIZE 520

typedef struct {
	char htag[EP_HTAG_SIZE];
	data_entry data_entry;
} data;

// db structure: for simplicity
typedef struct {
	header *header;
	data *data;
} database;

database *db_load(stream *db_file, char *sec);
int db_write(database *db, stream *db_file, char* pub);
database *db_create(char *name);
int db_set_db_name(database *db, char *name);
void db_close(database *db);

// htag as return, leave new_data as NULL will create default entry
int db_add_entry(database *db, data_entry *new_data, char *key, char *new_htag);
// delete the entry with specific htag
int db_delete_entry(database *db, char *htag);

// new htag as return (could be NULL if you don't need)
int db_set_fullname(database *db, char *htag, char *fullname, char *new_htag);
int db_set_note(database *db, char *htag, char *note, char *new_htag);
int db_set_value(database *db, char *htag, char *value, char *new_htag);

int db_get_fullname(database *db, char *htag, char *fullname);
int db_get_note(database *db, char *htag, char *note);
int db_get_value(database *db, char *htag, char *value);

// return the index of new tag on success (0-EP_TAG_MAX-1), -1 on failure
int db_create_tag(database *db, char *new_tag);
// htag is used to locate entry, tag_idx is used to locate tag, 
// value 1 means set as 1, 0 means set as 0
// optional new_htag return
int db_set_tag(database *db, char *htag, int tag_idx, int value, char *new_htag);

// advanced features
//char* db_search(char *pat, char *htag);

// deprecated functions
// return the pointer of htag if succeed, return NULL if failed
//char *db_add_entry(db *db, data_entry *entry, size_t entry_size);
// return 1 if succeed, return 0 if failed
//int db_delete_entry(db *db, char *htag);
// return new htag if succeed, return NULL if failed
//char *db_update_entry(db *db, char *htag, data_entry *entry, size_t new_size);

// From db_util.c
void db_print_status(database *db);
void db_print_table(database *db, int htag_len);
void db_print_tags(char **tt, char *tags);
void db_print_all_data(database *db);
void db_print_table_entry(table_entry *tn, int htag_len);
void db_print_data_entry(char *name, char *note, char *value, char **tt, char *tags);
data_entry *db_make_data_entry(char *name, char *note, char *value, char *tag);

// Advanced functions (from db_util.c);
void db_search_table(database *db, char *keyword);
int db_find_htag(database *db, char *keyword, char **htag_list);
table_entry *db_find_table_entry_from_htag(database *db, char *htag);

#endif
