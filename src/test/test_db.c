#include <stdio.h>
#include <stdlib.h>

#include "../db.h"
#include "../stream.h"
#include "../crypto.h"

static void mem_dump(void *ptr, size_t size)
{
	size_t i;
	for(i = 0; i < size; i++) {
		printf("%02x ", ((unsigned char *)ptr)[i]);
	}
	printf("\n");
}

static db *test1(char *pub)
{
	char htag[EP_HTAG_SIZE];
	
	char name[] = "The first entry of ENPASS DB!!!";
	// over flow test
	char note[] = "The first note of the first entry of ENPASS DB!!! The first note of the first entry of ENPASS DB!!!The first note of the first entry of ENPASS DB!!!The first note of the first entry of ENPASS DB!!!The first note of the first entry of ENPASS DB!!!The first note of the first entry of ENPASS DB!!!The first note of the first entry of ENPASS DB!!!The first note of the first entry of ENPASS DB!!!";
	char value[] = "TESTTESTETSTETSTETSTETS";
	
	database *db = db_create("GIUHGIHIHI");
	
	db_add_entry(db, NULL, htag);
	
	db_set_fullname(db, htag, name, htag);
	db_set_note(db, htag, note, htag);
	db_set_value(db, htag, value, htag);
	
	//mem_dump(htag, EP_HTAG_SIZE);
	
	//db_print_status(db);
	db_print_table(db);
	
	// so fat so good
	
	db_set_db_name(db, "OJROIJDOIJOIEJOJNDOIJJEJOIJOIJ");
	db_print_status(db);
	db_print_all_data(db);
	
	// so far so good
	
	char buf[256]; 
	db_get_fullname(db, htag, buf);
	printf("fullname: %s\n", buf);
	db_get_note(db, htag, buf);
	printf("note: %s\n", buf);
	db_get_value(db, htag, buf);
	printf("value: %s\n", buf);
	//mem_dump(buf, sizeof(buf));
	//printf("\n");
	
	//write the database to a file
	stream *st = stream_create(100, -1);
	db_write(db, st, pub);
	FILE *f = fopen("test_file", "wb");
	if(f) {
		fwrite(st->buf, st->datalen, 1, f);
		fclose(f);
	}
	stream_dump(st);
	stream_close(st);
	db_close(db);
	
	return db;
}

static void test2(char *sec)
{
	//====================================
	
	// load the db
	stream *st2 = stream_create(100, -1);
	FILE *f2 = fopen("test_file", "rb");
	
	if(f2) {
		// find the file size (in bytes)
		fseek(f2, 0, SEEK_END);
		long fsize = ftell(f2);
		fseek(f2, 0, SEEK_SET);
		stream_read_from_file(st2, f2, fsize);
		stream_dump(st2);
	} else {
		printf("Failed to open file");
		abort();
	}
	
	// load from file
	database *db = db_load(st2, sec);
	
	db_print_status(db);
	db_print_table(db);
	db_print_all_data(db);
	
	stream_close(st2);
	db_close(db);
}

int main()
{
	char pub[EP_KEY_SIZE], sec[EP_KEY_SIZE];
	crypto_curve_generate_secret(sec);
	crypto_curve_compute_public(pub, sec);
	
	database *test_db = test1(pub);
	if(test_db) {
		test2(sec);
	} else {
		printf("Failed to get db handler");
	}
	return 0;
}
