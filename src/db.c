#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "stream.h"
#include "util.h"
#include "crypto.h"
#include "db.h"
#include "config.h"

#include "dbg.h"

// Enpass database file header layout, total 72 Bytes
//#define HEADER_PROG_NAME 0
//#define HEADER_FORMAT_VERSION 3
//#define HEADER_NAME 4
//#define HEADER_NENTRY 68

database *db_load(stream *db_file, char *sec)
{
	check(db_file, "invalid file");
	char iv[EP_IV_SIZE], epub[EP_KEY_SIZE], shared[EP_KEY_SIZE], check_iv[EP_KEY_SIZE];
	char header_buf[EP_HEADER_SIZE];
	chacha_ctx ctx[1];
	
	char checksum[2][EP_HASH_SIZE];
	SHA256_CTX hmac[1];
	
	int i, count = 0;
	char tt_idx[12]; // index and data size
	uint32_t tt_data_size = 0;
	
	// prepare database and header memory
	database *db = malloc(sizeof(database));
	check_mem(db);
	db->header = NULL;
	db->data = NULL;
	
	db->header = malloc(sizeof(header));
	check_mem(db->header);
	db->header->nentry = 0;
	db->header->table = NULL;
	db->header->tags = NULL;
	
	// initialize the file stream
	stream_setpos(db_file, 0L);
	
	check(stream_read(iv, EP_IV_SIZE, 1, db_file), "Failed to read iv");
	check(stream_read(epub, EP_KEY_SIZE, 1, db_file), "Failed to read ephemeral public key");
	crypto_curve_compute_shared(shared, sec, epub);
	
	// setup hmac checks
	hmac_init(hmac, (uint8_t *)shared);
	
	// verify shared-key and with iv
	crypto_sha256(shared, EP_KEY_SIZE, check_iv);
	check(memcmp(iv, check_iv, EP_IV_SIZE) == 0, "Invalid secret key or file is corrupted");
	
	// read and decrypt database header
	check(stream_read(header_buf, EP_HEADER_SIZE, 1, db_file), "Failed to read header");
	crypto_stream_init(ctx, shared, iv);
	crypto_stream_compute(ctx, header_buf, header_buf, EP_HEADER_SIZE);// in-place chacha decryption
	
	// check critical information
	check(memcmp(header_buf+HEADER_PROG_NAME, EP_PROG_NAME, strlen(EP_PROG_NAME)) == 0, "Program name verification failed");
	check(*(header_buf+HEADER_FORMAT_VERSION) == EP_FORMAT_VERSION, "Incompatible format version");
	
	check(memcpy(db->header->name, header_buf+HEADER_NAME, EP_HEADER_NAME_SIZE), "Failed to copy database name");
	check(memcpy(&db->header->nentry, header_buf+HEADER_NENTRY, 4), "Failed to copy entry count");
	check(db->header->nentry > 0, "illegal entry count");
	// empty database is not allowed
	
	sha256_update(hmac, (uint8_t *)header_buf, EP_HEADER_SIZE);
	
	// read and decrypt index table
	table_entry *table = calloc(db->header->nentry, EP_TABLE_ENTRY_SIZE);
	check_mem(table);
	check(stream_read(table, EP_TABLE_ENTRY_SIZE, db->header->nentry, db_file), "Failed to read table");
	crypto_stream_compute(ctx, (char *)table, (char *)table, EP_TABLE_ENTRY_SIZE*db->header->nentry);
	
	db->header->table = table;
	table = NULL;
	
	sha256_update(hmac, (uint8_t *)db->header->table, db->header->nentry * EP_TABLE_ENTRY_SIZE);
	
	// read and decrypt tag table
	char **tt = malloc(sizeof(char *) * EP_TAG_MAX);
	check_mem(tt);
	
	check(stream_read(tt_idx, sizeof(tt_idx), 1, db_file), "Failed to read tag table index");
	crypto_stream_compute(ctx, tt_idx, tt_idx, sizeof(tt_idx));
	memcpy(&tt_data_size, tt_idx+TAG_DATA_SIZE, 4);
	check(tt_data_size <= 4096 && tt_data_size % EP_TAG_MAX_SIZE == 0, "Invalid tag table size");
	
	char *tt_data_buf = malloc(tt_data_size);
	check_mem(tt_data_buf);
	
	check(stream_read(tt_data_buf, tt_data_size, 1, db_file), "Failed to read tag table");
	crypto_stream_compute(ctx, tt_data_buf, tt_data_buf, tt_data_size);
	
	for(i = 0; i < EP_TAG_MAX; i++) {
		if(bit_of(tt_idx+(i/8), i%8)) {
			tt[i] = malloc(EP_TAG_MAX_SIZE);
			check_mem(tt[i]);
			memcpy(tt[i], tt_data_buf+count*EP_TAG_MAX_SIZE, EP_TAG_MAX_SIZE);
			count++;
		} else {
			tt[i] = NULL;
		}
	}
	db->header->tags = tt;
	
	sha256_update(hmac, (uint8_t *)tt_idx, 12);
	sha256_update(hmac, (uint8_t *)tt_data_buf, tt_data_size);
	
	free(tt_data_buf);
	tt_data_buf = NULL;
	
	// read checksum and verify the validity of header, table and tag table
	check(stream_read(checksum[0], EP_HASH_SIZE, 1, db_file), "Failed to read checksum");
	hmac_final(hmac, (uint8_t *)shared, (uint8_t *)checksum[1]);
	check(memcmp(checksum[0], checksum[1], EP_HASH_SIZE) == 0, "Checksum does not match. File is corrupted");
	
	// read and decrypt data
	data *data = calloc(db->header->nentry, EP_HTAG_SIZE + EP_DATA_ENTRY_SIZE);
	check_mem(data);

	check(stream_read(data, db->header->nentry*(EP_DATA_ENTRY_SIZE+EP_HTAG_SIZE), 1, db_file), "Failed to read data");
	crypto_stream_compute(ctx, (char *)data, (char *)data, db->header->nentry*(EP_DATA_ENTRY_SIZE+EP_HTAG_SIZE));
	
	db->data = data;
	data = NULL;
	
	// read the second checksum and verify the validity of data
	check(stream_read(checksum[0], EP_HASH_SIZE, 1, db_file), "Failed to read checksum");
	
	crypto_sha256_hmac((char *)db->data, db->header->nentry*(EP_DATA_ENTRY_SIZE+EP_HTAG_SIZE), shared, checksum[1]);
	
	check(memcmp(checksum[0], checksum[1], EP_HASH_SIZE) == 0, "Checksum does not match. File is corrupted");
	
	return db;
	
error:
	if(table) free(table);
	if(tt_data_buf) free(tt_data_buf);
	if(data) free(data);
	db_close(db);
	return NULL;
}

// Enpass database file header layout, total 72 Bytes
//#define HEADER_PROG_NAME 0
//#define HEADER_FORMAT_VERSION 3
//#define HEADER_NAME 4
//#define HEADER_NENTRY 68

/// TODO: This function may produce UNINITIALIZED MEMORY warnings in valgrind, need further inspections
int db_write(database *db, stream *db_file, char* pub)
{
	char esec[EP_KEY_SIZE], epub[EP_KEY_SIZE], shared[EP_KEY_SIZE], iv[EP_HASH_SIZE], checksum[EP_HASH_SIZE];
	chacha_ctx ctx[1];
	SHA256_CTX hmac[1];
	
	char header_buf[EP_HEADER_SIZE];
	
	int i, count = 0;
	char tt_idx[12] = {'\0'};
	uint32_t tt_data_size = 0;
	
	// initialize the file stream
	stream_setpos(db_file, 0L);
	
	// generate ephemeral public and private key pair
	crypto_curve_generate_secret(esec);
	crypto_curve_compute_public(epub, esec);
	
	// compute shared key for encryption
	crypto_curve_compute_shared(shared, esec, pub);
	
	// compute iv using shared key
	crypto_sha256(shared, EP_HASH_SIZE, iv);
	
	// write iv and epub to db file
	check(stream_write(iv, EP_IV_SIZE, 1, db_file), "Failed to write iv");
	check(stream_write(epub, EP_KEY_SIZE, 1, db_file), "Failed to write ephemeral public key");
	
	crypto_stream_init(ctx, shared, iv);
	
	// serialize and encrypt header (at the same time, preparing HMAC)
	hmac_init(hmac, (uint8_t *)shared);
	
	check(memcpy(header_buf+HEADER_PROG_NAME, EP_PROG_NAME, strlen(EP_PROG_NAME)), "Failed to write program name");
	*(header_buf+HEADER_FORMAT_VERSION) = EP_FORMAT_VERSION;
	check(memcpy(header_buf+HEADER_NAME, db->header->name, sizeof(EP_HEADER_NAME_SIZE)), "Failed to write database name");
	check(memcpy(header_buf+HEADER_NENTRY, &db->header->nentry, 4), "Failed to write entry count");
	
	sha256_update(hmac, (uint8_t *)header_buf, EP_HEADER_SIZE);
	crypto_stream_compute(ctx, header_buf, header_buf, EP_HEADER_SIZE);
	check(stream_write(header_buf, EP_HEADER_SIZE, 1, db_file), "Failed to write header");
	
	// encrypt table
	sha256_update(hmac, (uint8_t *)db->header->table, EP_TABLE_ENTRY_SIZE * db->header->nentry);
	char *enc_table = calloc(db->header->nentry, EP_TABLE_ENTRY_SIZE);
	check_mem(enc_table);
	crypto_stream_compute(ctx, (char *)db->header->table, enc_table, EP_TABLE_ENTRY_SIZE * db->header->nentry);
	check(stream_write(enc_table, EP_TABLE_ENTRY_SIZE * db->header->nentry, 1, db_file), "Failed to write table");
	free(enc_table);
	enc_table = NULL;
	
	// encrypt tag table	
	//dump_bin(db->header->tags, EP_TAG_MAX);
	for(i = 0; i < EP_TAG_MAX; i++) {
		if(db->header->tags[i]) {
			int a = i / 8;
			int o = i % 8;
			bit_mask_1(tt_idx+a, o);
			count++;
		}
	}
	tt_data_size = count*EP_TAG_MAX_SIZE;
	char *tt_data_buf = malloc(tt_data_size);
	check_mem(tt_data_buf);
	for(i = 0; i < EP_TAG_MAX; i++) {
		if(db->header->tags[i]) {
			memcpy(tt_data_buf+i*EP_TAG_MAX_SIZE, db->header->tags[i], EP_TAG_MAX_SIZE);
		}
	}
	memcpy(tt_idx+TAG_DATA_SIZE, &tt_data_size, 4);
	
	sha256_update(hmac, (uint8_t *)tt_idx, 12);
	crypto_stream_compute(ctx, tt_idx, tt_idx, 12);
	sha256_update(hmac, (uint8_t *)tt_data_buf, tt_data_size);
	crypto_stream_compute(ctx, tt_data_buf, tt_data_buf, tt_data_size);
	
	check(stream_write(tt_idx, 12, 1, db_file), "Failed to write tag index");
	check(stream_write(tt_data_buf, tt_data_size, 1, db_file), "Failed to write tag table");
	
	free(tt_data_buf);
	tt_data_buf = NULL;
	
	// compute and write the checksum of the header, table and tag table
	hmac_final(hmac, (uint8_t *)shared, (uint8_t *)checksum);
	check(stream_write(checksum, EP_HASH_SIZE, 1, db_file), "Failed to write checksum");
	
	// encrypt and write data
	char *enc_data = calloc(db->header->nentry, EP_HTAG_SIZE + EP_DATA_ENTRY_SIZE);
	check_mem(enc_data);
	
	crypto_stream_compute(ctx, (char *)db->data, enc_data, db->header->nentry*(EP_DATA_ENTRY_SIZE+EP_HTAG_SIZE));
	check(stream_write(enc_data, db->header->nentry*(EP_DATA_ENTRY_SIZE+EP_HTAG_SIZE), 1, db_file), "Failed to write data");
	
	free(enc_data);
	enc_data = NULL;
	
	// compute and write the checksum of the data
	crypto_sha256_hmac((char *)db->data, db->header->nentry*(EP_DATA_ENTRY_SIZE+EP_HTAG_SIZE), shared, checksum);
	
	check(stream_write(checksum, EP_HASH_SIZE, 1, db_file), "Failed to write checksum");
	return 1;
	
error:
	if(enc_table) free(enc_table);
	if(tt_data_buf) free(tt_data_buf);
	if(enc_data) free(enc_data);
	return 0;
}

database *db_create(char *name)
{
	database *db = malloc(sizeof(database));
	check_mem(db);
	db->header = NULL;
	db->data = NULL;
	
	db->header = malloc(sizeof(header));
	check_mem(db->header);
	db->header->nentry = 0;
	db->header->table = NULL;
	db->header->tags = NULL;
	
	char _name[64] = {'\0'};
	
	// copy name if there is one, or use the default name if none is provided
	if(!name) {
		check(memcpy(db->header->name, EP_DEFAULT_NAME, sizeof(EP_DEFAULT_NAME)), "Failed to copy name");
	} else {
		check(secure_strncpy(_name, name, EP_HEADER_NAME_SIZE), "Failed to copy name");
		check(memcpy(db->header->name, _name, sizeof(_name)), "Failed to copy name");
	}
	
	// make table
	db->header->nentry = 0;
	db->header->table = malloc(EP_TABLE_ENTRY_SIZE);
	check_mem(db->header->table);
	memset(db->header->table, 0, EP_TABLE_ENTRY_SIZE);
	
	// make tag tables
	db->header->tags = malloc(EP_TAG_MAX * sizeof(char *));
	check_mem(db->header->tags);
	memset(db->header->tags, 0, EP_TAG_MAX * sizeof(char *));
	
	// make default tag
	db->header->tags[0] = malloc(EP_TAG_MAX_SIZE);
	memcpy(db->header->tags[0], EP_TAG_DEFAULT, sizeof(EP_TAG_DEFAULT));
	
	// make data entry
	db->data = malloc(EP_DATA_ENTRY_SIZE + EP_HTAG_SIZE);
	check_mem(db->data);
	
	check(db_add_entry(db, NULL, NULL, NULL), "Failed to add the first entry");
	
	debug("db create complete, db: %p", db);
	
	//db_print_table(db, EP_HTAG_SIZE);
	
	return db;
	
error:

	debug("db create failed");
	db_close(db);
	return NULL;
}

int db_set_db_name(database *db, char *name)
{
	char _name[64] = {'\0'};
	if(!name) {
		return 0;
	} else {
		check(secure_strncpy(_name, name, 64), "Failed to copy name");
		check(memcpy(db->header->name, _name, sizeof(_name)), "Failed to set DB name");
	}
	return 1;
error:
	return 0;
}

void db_close(database *db)
{
	int i2;
	if(db) {
		if(db->header) {
			if(db->header->table) {
				// clear the memory for security reason
				memset(db->header->table, 0, db->header->nentry*EP_TABLE_ENTRY_SIZE);
				free(db->header->table);
				db->header->table = NULL;
			}
			if(db->header->tags) {
				for(i2 = 0; i2 < EP_TAG_MAX; i2++) {
					if(db->header->tags[i2]) {
						free(db->header->tags[i2]);
						db->header->tags[i2] = NULL;
					}
				}
				free(db->header->tags);
				db->header->tags = NULL;
			}
			free(db->header);
			db->header = NULL;
		}
		if(db->data) { free(db->data); db->data = NULL; }
		free(db);
		db = NULL;
	}
}

static void db_compute_htag(data_entry *entry, char *htag)
{
	char tmp[32];
	crypto_sha256((char *)entry, EP_DATA_ENTRY_SIZE, tmp);
	memcpy(htag, tmp, EP_HTAG_SIZE);
}

// htag as return, leave new_data as NULL will create default entry
/// TODO: This function may produce UNINITIALIZED MEMORY warnings in valgrind, need further inspections
int db_add_entry(database *db, data_entry *new_data, char *key, char *new_htag)
{
	char _key[EP_KEY_SIZE];
	char empty_buf[16] = {'\0'};
	
	char htag[EP_HTAG_SIZE];
	chacha_ctx ctx[1];
	char iv[EP_IV_SIZE];

	// allocate and initialize new memory
	void *tmp_ptr = NULL;
	tmp_ptr= secure_realloc(db->header->table, db->header->nentry*EP_TABLE_ENTRY_SIZE, (db->header->nentry+1)*EP_TABLE_ENTRY_SIZE);
	check_mem(tmp_ptr);
	db->header->table = tmp_ptr;
	memset(&db->header->table[db->header->nentry], 0, EP_TABLE_ENTRY_SIZE);
	
	tmp_ptr = secure_realloc(db->data, db->header->nentry*(EP_DATA_ENTRY_SIZE+EP_HTAG_SIZE), (db->header->nentry+1)*(EP_DATA_ENTRY_SIZE+EP_HTAG_SIZE));
	check_mem(tmp_ptr);
	db->data = tmp_ptr;
	memset(&db->data[db->header->nentry], 0, (EP_DATA_ENTRY_SIZE+EP_HTAG_SIZE));
	
	// prepare new keys
	if(!key) {
		crypto_rand(_key, EP_KEY_SIZE);
		key = _key;
	}
	check(memcpy(db->header->table[db->header->nentry].key, key, EP_KEY_SIZE), "Failed to copy key");
	
	if(!new_data) {
		// create new default entry
		// set default table values
		check(secure_strncpy(db->header->table[db->header->nentry].name, EP_DEFAULT_NAME, sizeof(EP_DEFAULT_NAME)), "Failed to copy name");
		check(memcpy(db->header->table[db->header->nentry].tag, empty_buf, EP_TAG_MAX / 8), "Failed to copy tags");
		// leave fp as it is (all zeros)
		
		// set default tag
		if(db->header->tags[0] && strlen(db->header->tags[0]) == strlen(EP_TAG_DEFAULT) && \
			memcmp(db->header->tags[0], EP_TAG_DEFAULT, sizeof(EP_TAG_DEFAULT)) == 0) {
			bit_mask_1(db->header->table[db->header->nentry].tag, 0);
		}
		
		// initialization
		memset(&db->data[db->header->nentry].data_entry, 0, EP_DATA_ENTRY_SIZE);
	
		// set default data
		check(memcpy(db->data[db->header->nentry].data_entry.tag, db->header->table[db->header->nentry].tag, EP_TAG_MAX / 8), "Failed to copy tag");
		check(secure_strncpy(db->data[db->header->nentry].data_entry.name, EP_DEFAULT_NAME, sizeof(EP_DEFAULT_NAME)), "Failed to copy name");
		check(secure_strncpy(db->data[db->header->nentry].data_entry.note, EP_DEFAULT_NAME, sizeof(EP_DEFAULT_NAME)), "Failed to copy note");
		check(memcpy(db->data[db->header->nentry].data_entry.value, EP_DEFAULT_NAME, sizeof(EP_DEFAULT_NAME)), "Failed to copy value");
	} else {
		// add existing data entry
		check(secure_strncpy(db->header->table[db->header->nentry].name, new_data->name, EP_TABLE_NAME_SIZE), "Failed to copy name");
		check(memcpy(db->header->table[db->header->nentry].tag, new_data->tag, EP_TAG_MAX / 8), "Failed to copy the tag");
		
		// assume the value data is already encrypted by external keys
		check(memcpy(&db->data[db->header->nentry].data_entry, new_data, EP_DATA_ENTRY_SIZE), "Failed to copy new data");
	}
	
	// compute and write htag
	db_compute_htag(&db->data[db->header->nentry].data_entry, htag);
	check(memcpy(db->header->table[db->header->nentry].htag, htag, EP_HTAG_SIZE), "Failed to copy htag");
	check(memcpy(db->data[db->header->nentry].htag, htag, EP_HTAG_SIZE), "Failed to copy htag");
	
	// encrypt newly created data entry
	memcpy(iv, htag, EP_IV_SIZE); // use first 8 bytes of htag as iv
	crypto_stream_init(ctx, key, iv);
	crypto_stream_compute(ctx, (char *)&db->data[db->header->nentry].data_entry, (char *)&db->data[db->header->nentry].data_entry, EP_DATA_ENTRY_SIZE);
	
	// update the entry count
	db->header->nentry += 1;
	
	if(new_htag) {
		check(memcpy(new_htag, htag, EP_HTAG_SIZE), "Failed to copy htag");
	}
	return 1;

error:
	// do nothing
	return 0;
}

static int db_find_entry(database *db, char *htag)
{
	// find the entry in table
	int i, id = -1;
	for(i = 0; i < db->header->nentry; i++) {
		if(memcmp(db->header->table[i].htag, htag, EP_HTAG_SIZE) == 0) {
			id = i;
			break;
		}
	}
	return id;
}

// delete the entry with specific htag
int db_delete_entry(database *db, char *htag)
{
	// find the entry in table
	int id = db_find_entry(db, htag);
	check(id != -1, "no such entry in the database");
	
	// do nothing if the entry to delete is the last one
	if(id == db->header->nentry-1) {
		db->header->nentry -= 1;
		return 1;
	}
	
	int i;
	for(i = id; i < db->header->nentry-1; i++) {
		check(memcpy(&db->header->table[i], &db->header->table[i+1], EP_TABLE_ENTRY_SIZE), "Failed to move table");
		check(memcpy(&db->data[i], &db->data[i+1], EP_DATA_ENTRY_SIZE + EP_HTAG_SIZE), "Failed to move data");
	}
	db->header->nentry -= 1;
	
	// it is the invoker's responsibility to ensure that user does not leave a zero entry database during the write-out
	if(db->header->nentry < 1) {
		log_warn("You have delete your last entry in the database, please create at least one new entry before write to file, otherwise database will be corrupted.");
	}
	return 1;
	
error:
	return 0;
}


// new htag as return
int db_set_fullname(database *db, char *htag, char *fullname, char *new_htag)
{
	// find the entry in table
	int id = db_find_entry(db, htag);
	check(id != -1, "no such entry in the database");
	
	chacha_ctx ctx[1];
	char iv[EP_IV_SIZE], key[EP_KEY_SIZE];
	memcpy(iv, db->data[id].htag, EP_IV_SIZE);
	memcpy(key, db->header->table[id].key, EP_KEY_SIZE);
	
	crypto_stream_init(ctx, key, iv);
	
	// decrypt the data (in-place)
	crypto_stream_compute(ctx, (char *)&db->data[id].data_entry, (char *)&db->data[id].data_entry, EP_DATA_ENTRY_SIZE);
	
	check(secure_strncpy(db->data[id].data_entry.name, fullname, EP_DATA_ENTRY_NAME_SIZE), "Failed to copy name");
	// must copy at most EP_TABLE_NAME_SIZE-1  bytes to avoid non-null-termination problem
	check(secure_strncpy(db->header->table[id].name, db->data[id].data_entry.name, EP_TABLE_NAME_SIZE), "Failed to copy name");
	
	// compute and update new htag
	char _htag[EP_HTAG_SIZE];
	db_compute_htag(&db->data[id].data_entry, _htag);
	check(memcpy(db->data[id].htag, _htag, EP_HTAG_SIZE), "Failed to copy htag");
	check(memcpy(db->header->table[id].htag, _htag, EP_HTAG_SIZE), "Failed to copy htag");
	
	// re-encrypt the data (in-place) with new iv and old key (I don't think using old key will damage the security)
	memcpy(iv, _htag, EP_IV_SIZE);
	crypto_stream_init(ctx, key, iv);
	crypto_stream_compute(ctx, (char *)&db->data[id].data_entry, (char *)&db->data[id].data_entry, EP_DATA_ENTRY_SIZE);
	
	if(new_htag) {
		check(memcpy(new_htag, _htag, EP_HTAG_SIZE), "Failed to copy htag");
	}
	
	return 1;
	
error:
	return 0;
}


// almost same as the previous function
int db_set_note(database *db, char *htag, char *note, char *new_htag)
{
	// find the entry in table
	int id = db_find_entry(db, htag);
	check(id != -1, "no such entry in the database");
	
	chacha_ctx ctx[1];
	char iv[EP_IV_SIZE], key[EP_KEY_SIZE];
	memcpy(iv, db->data[id].htag, EP_IV_SIZE);
	memcpy(key, db->header->table[id].key, EP_KEY_SIZE);
	
	crypto_stream_init(ctx, key, iv);
	
	// decrypt the data (in-place)
	crypto_stream_compute(ctx, (char *)&db->data[id].data_entry, (char *)&db->data[id].data_entry, EP_DATA_ENTRY_SIZE);
	
	check(secure_strncpy(db->data[id].data_entry.note, note, EP_DATA_ENTRY_NOTE_SIZE), "Failed to copy note");
	
	// compute and update new htag
	char _htag[EP_HTAG_SIZE];
	db_compute_htag(&db->data[id].data_entry, _htag);
	check(memcpy(db->data[id].htag, _htag, EP_HTAG_SIZE), "Failed to copy htag");
	check(memcpy(db->header->table[id].htag, _htag, EP_HTAG_SIZE), "Failed to copy htag");
	
	// re-encrypt the data (in-place) with new iv and old key (I don't think using old key will damage the security)
	memcpy(iv, _htag, EP_IV_SIZE);
	crypto_stream_init(ctx, key, iv);
	crypto_stream_compute(ctx, (char *)&db->data[id].data_entry, (char *)&db->data[id].data_entry, EP_DATA_ENTRY_SIZE);
	
	if(new_htag) {
		check(memcpy(new_htag, _htag, EP_HTAG_SIZE), "Failed to copy htag");
	}
	
	return 1;
	
error:
	return 0;
}

// almost same as the previous function
// value data is assumed to be encrypted externally and not handled here
int db_set_value(database *db, char *htag, char *value, char *new_htag)
{
	// find the entry in table
	int id = db_find_entry(db, htag);
	check(id != -1, "no such entry in the database");
	
	chacha_ctx ctx[1];
	char iv[EP_IV_SIZE], key[EP_KEY_SIZE];
	memcpy(iv, db->data[id].htag, EP_IV_SIZE);
	memcpy(key, db->header->table[id].key, EP_KEY_SIZE);
	
	crypto_stream_init(ctx, key, iv);
	
	// decrypt the data (in-place)
	crypto_stream_compute(ctx, (char *)&db->data[id].data_entry, (char *)&db->data[id].data_entry, EP_DATA_ENTRY_SIZE);
	
	// use memcpy to copy the exact value
	check(memcpy(db->data[id].data_entry.value, value, EP_DATA_ENTRY_VALUE_SIZE), "Failed to copy value");
	
	// compute and update new htag
	char _htag[EP_HTAG_SIZE];
	db_compute_htag(&db->data[id].data_entry, _htag);
	check(memcpy(db->data[id].htag, _htag, EP_HTAG_SIZE), "Failed to copy htag");
	check(memcpy(db->header->table[id].htag, _htag, EP_HTAG_SIZE), "Failed to copy htag");
	
	// re-encrypt the data (in-place) with new iv and old key (I don't think using old key will damage the security)
	memcpy(iv, _htag, EP_IV_SIZE);
	crypto_stream_init(ctx, key, iv);
	crypto_stream_compute(ctx, (char *)&db->data[id].data_entry, (char *)&db->data[id].data_entry, EP_DATA_ENTRY_SIZE);
	
	if(new_htag) {
		check(memcpy(new_htag, _htag, EP_HTAG_SIZE), "Failed to copy htag");
	}
	
	return 1;
	
error:
	return 0;
}

int db_get_fullname(database *db, char *htag, char *fullname)
{
	// find the entry in table
	int id = db_find_entry(db, htag);
	check(id != -1, "no such entry in the database");
	
	chacha_ctx ctx[1];
	char iv[EP_IV_SIZE], key[EP_KEY_SIZE];
	memcpy(iv, db->data[id].htag, EP_IV_SIZE);
	memcpy(key, db->header->table[id].key, EP_KEY_SIZE);
	
	crypto_stream_init(ctx, key, iv);
	
	// decrypt the data (in-place)
	crypto_stream_compute(ctx, (char *)&db->data[id].data_entry, (char *)&db->data[id].data_entry, EP_DATA_ENTRY_SIZE);
	
	check(secure_strncpy(fullname, db->data[id].data_entry.name, EP_DATA_ENTRY_NAME_SIZE), "Failed to copy name");
	
	// re-encrypt the data (in-place)
	crypto_stream_init(ctx, key, iv);
	crypto_stream_compute(ctx, (char *)&db->data[id].data_entry, (char *)&db->data[id].data_entry, EP_DATA_ENTRY_SIZE);
	
	return 1;
	
error:
	return 0;
}
	
int db_get_note(database *db, char *htag, char *note)
{
	// find the entry in table
	int id = db_find_entry(db, htag);
	check(id != -1, "no such entry in the database");
	
	chacha_ctx ctx[1];
	char iv[EP_IV_SIZE], key[EP_KEY_SIZE];
	memcpy(iv, db->data[id].htag, EP_IV_SIZE);
	memcpy(key, db->header->table[id].key, EP_KEY_SIZE);
	
	crypto_stream_init(ctx, key, iv);
	
	// decrypt the data (in-place)
	crypto_stream_compute(ctx, (char *)&db->data[id].data_entry, (char *)&db->data[id].data_entry, EP_DATA_ENTRY_SIZE);
	
	check(secure_strncpy(note, db->data[id].data_entry.note, EP_DATA_ENTRY_NOTE_SIZE), "Failed to copy note");
	
	// re-encrypt the data (in-place)
	crypto_stream_init(ctx, key, iv);
	crypto_stream_compute(ctx, (char *)&db->data[id].data_entry, (char *)&db->data[id].data_entry, EP_DATA_ENTRY_SIZE);
	
	return 1;
	
error:
	return 0;
}

int db_get_value(database *db, char *htag, char *value)
{
	// find the entry in table
	int id = db_find_entry(db, htag);
	check(id != -1, "no such entry in the database");
	
	chacha_ctx ctx[1];
	char iv[EP_IV_SIZE], key[EP_KEY_SIZE];
	memcpy(iv, db->data[id].htag, EP_IV_SIZE);
	memcpy(key, db->header->table[id].key, EP_KEY_SIZE);
	
	crypto_stream_init(ctx, key, iv);
	
	// decrypt the data (in-place)
	crypto_stream_compute(ctx, (char *)&db->data[id].data_entry, (char *)&db->data[id].data_entry, EP_DATA_ENTRY_SIZE);
	
	check(memcpy(value, db->data[id].data_entry.value, EP_DATA_ENTRY_VALUE_SIZE), "Failed to copy value");
	
	// re-encrypt the data (in-place)
	crypto_stream_init(ctx, key, iv);
	crypto_stream_compute(ctx, (char *)&db->data[id].data_entry, (char *)&db->data[id].data_entry, EP_DATA_ENTRY_SIZE);
	
	return 1;
	
error:
	return 0;
}

// create a new tag for the database
int db_create_tag(database *db, char *new_tag)
{
	int i, idx = 0;
	for(i = 0; i < EP_TAG_MAX; i++) {
		if(!db->header->tags[i]) {
			idx = i;
			db->header->tags[i] = malloc(EP_TAG_MAX_SIZE);
			check_mem(db->header->tags[i]);
			secure_strncpy(db->header->tags[i], new_tag, EP_TAG_MAX_SIZE);
			return idx;
		}
	}
	log_err("All tag fields have been used, this database support maximum %d tags.", EP_TAG_MAX);
	return -1;

error:
	return -1;
}

// create a new tag for the database
int db_delete_tag(database *db, int tag_idx)
{
	if(db->header->tags[tag_idx]) {
		free(db->header->tags[tag_idx]);
		db->header->tags[tag_idx] = NULL;
	}
	
	int id;
	// clear that bit for all entrys and recalculate the htag
	for(id = 0; id < db->header->nentry; id++) {
		//decrypt data, update the tag, and re-encrypt the data, and update the htag
		chacha_ctx ctx[1];
		char iv[EP_IV_SIZE], key[EP_KEY_SIZE];
		memcpy(iv, db->data[id].htag, EP_IV_SIZE);
		memcpy(key, db->header->table[id].key, EP_KEY_SIZE);
	
		crypto_stream_init(ctx, key, iv);
	
		// decrypt the data (in-place)
		crypto_stream_compute(ctx, (char *)&db->data[id].data_entry, (char *)&db->data[id].data_entry, EP_DATA_ENTRY_SIZE);
	
		bit_mask_0(db->data[id].data_entry.tag + tag_idx / 8,tag_idx % 8);
	
		// compute and update new htag
		char _htag[EP_HTAG_SIZE];
		db_compute_htag(&db->data[id].data_entry, _htag);
		check(memcpy(db->data[id].htag, _htag, EP_HTAG_SIZE), "Failed to copy htag");
		check(memcpy(db->header->table[id].htag, _htag, EP_HTAG_SIZE), "Failed to copy htag");
	
		// re-encrypt the data (in-place) with new iv and old key (I don't think using old key will damage the security)
		memcpy(iv, _htag, EP_IV_SIZE);
		crypto_stream_init(ctx, key, iv);
		crypto_stream_compute(ctx, (char *)&db->data[id].data_entry, (char *)&db->data[id].data_entry, EP_DATA_ENTRY_SIZE);
	}
	return 1;
	
error:
	return 0;
}

int db_set_tag(database *db, char *htag, int tag_idx, int value, char *new_htag)
{
	// find the entry in table
	int id = db_find_entry(db, htag);
	check(id != -1, "no such entry in the database");
	
	check(tag_idx < EP_TAG_MAX && tag_idx >= 0, "Invalid tag index");
	
	bit_mask_1(db->header->table[id].tag + tag_idx / 8,tag_idx % 8);
	
	//decrypt data, update the tag, and re-encrypt the data, and update the htag
	chacha_ctx ctx[1];
	char iv[EP_IV_SIZE], key[EP_KEY_SIZE];
	memcpy(iv, db->data[id].htag, EP_IV_SIZE);
	memcpy(key, db->header->table[id].key, EP_KEY_SIZE);
	
	crypto_stream_init(ctx, key, iv);
	
	// decrypt the data (in-place)
	crypto_stream_compute(ctx, (char *)&db->data[id].data_entry, (char *)&db->data[id].data_entry, EP_DATA_ENTRY_SIZE);
	
	if(value) bit_mask_1(db->data[id].data_entry.tag + tag_idx / 8,tag_idx % 8);
	if(!value) bit_mask_0(db->data[id].data_entry.tag + tag_idx / 8,tag_idx % 8);
	
	// compute and update new htag
	char _htag[EP_HTAG_SIZE];
	db_compute_htag(&db->data[id].data_entry, _htag);
	check(memcpy(db->data[id].htag, _htag, EP_HTAG_SIZE), "Failed to copy htag");
	check(memcpy(db->header->table[id].htag, _htag, EP_HTAG_SIZE), "Failed to copy htag");
	
	// re-encrypt the data (in-place) with new iv and old key (I don't think using old key will damage the security)
	memcpy(iv, _htag, EP_IV_SIZE);
	crypto_stream_init(ctx, key, iv);
	crypto_stream_compute(ctx, (char *)&db->data[id].data_entry, (char *)&db->data[id].data_entry, EP_DATA_ENTRY_SIZE);
	
	if(new_htag) {
		check(memcpy(new_htag, _htag, EP_HTAG_SIZE), "Failed to copy htag");
	}
	
	return 1;
	
error:
	return 0;
}

/** TODOs(7/23) (completed but untested)
 * TODO: Finish up the tag system for the rest of the file (db.c and db_util.c)
 *
 * New functions: (db.c)
 * db_create_tag(), 
 * db_set_tag(), 
 * db_unset_tag(), (perhaps combine to one function to the previous
 * db_delete_tag() 
 *
 * (db_util.c)
 * db_search_tag()
 * 
 * TODO: Fix the issue caused by the chang of EP_HTAG_SIZE from 16 to 8
 * db.c should be compeleted, db_util and other .c files still needs further checks
 */
 
 /** TODO (7/24)
  * TODO: Updates the functions (including new functions like show data) in enpass.c 
  * and test the entire thing
  */
