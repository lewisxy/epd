#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "db.h"
#include "util.h"
#include "crypto.h"

static void print_table_entry(char *htag, int htag_len, char *name, char* fp, char *key, char **tt, char *tags)
{
	if(htag) {
		dump_bin(htag, htag_len);
		if(name || key || fp) printf(" | ");
	}
	if(name) {
		printf("%s", name);
		if(key || fp) printf(" | ");
	}
	if(fp) {
		dump_bin(fp, EP_FP_SIZE);
		if(key) printf(" | ");
	}
	if(key) {
		dump_bin(key, EP_KEY_SIZE);
	}
	printf("\n");
	if(tags && tt) {
		db_print_tags(tt, tags);
		printf("\n");
	}
}

void db_print_status(database *db)
{
	printf("================================================================================\n");
	printf("                               EPD STATUS (DUMP):                               \n");
	printf("DB NAME:        %s\n", db->header->name);
	printf("NUMBER OF ITEM: %d\n", (int)db->header->nentry);
	printf("AVAILABLE TAGS: \n");
	int i;
	for(i = 0; i < EP_TAG_MAX; i++) {
		if(db->header->tags[i] != NULL) {
			printf("  %d: %p: \n", i, db->header->tags[i]);
			printf("  %s \n", db->header->tags[i]);
		} else {
			printf("  %d: <EMPTY>\n", i);
		}
	}
	printf("================================================================================\n");
	printf("                               INDEX TABLE (DUMP):                              \n");
	printf("      HTAG       |         NAME\n");
	printf("      TAGS\n");
	printf("--------------------------------------------------\n");
	db_print_table(db, EP_HTAG_SIZE);
	printf("================================================================================\n");
	printf("                                   DATA (DUMP):                                 \n");
	db_print_all_data(db);
	printf("================================================================================\n");
	fflush(stdout);
}

void db_print_table_entry(table_entry *tn, int htag_len)
{
	print_table_entry(tn->htag, htag_len, tn->name, tn->fp, NULL, NULL, NULL);
}

void db_print_table(database *db, int htag_len)
{
	size_t i;
	for(i = 0; i < db->header->nentry; i++) {
		
		print_table_entry(db->header->table[i].htag, htag_len, \
							db->header->table[i].name, db->header->table[i].fp, \
							NULL, db->header->tags, db->header->table[i].tag);
		/* display only the first 6 bytes of htag */
		//dump_bin(db->header->table[i].htag, 6);
		//printf(" ");
		//dump_bin(db->header->table[i].name, EP_TABLE_NAME_SIZE);
		//printf(" | %s", db->header->table[i].name);
		//printf(" ");
		//dump_bin(db->header->table[i].key, EP_KEY_SIZE);
		//printf("\n");
	}
}

// tags is in bit format
void db_print_tags(char **tt, char *tags)
{
	//printf("db_print_tags\n");
	//dump_bin(tags, 8);
	//printf("\n");
	//dump_bin(tt, 8 * 64);
	//printf("\n");
	int i;
	int count = 0;
	for(i = 0; i < EP_TAG_MAX; i++) {
		if(bit_of(tags+(i / 8), i%8)) {
			printf("%s ", tt[i]);
			count++;
		}
	}
}

void db_print_data_entry(char *name, char *note, char *value, char **tt, char *tags)
{
	printf("NAME:           %s\n", (!name || !name[0]) ? "(none)" : name);
	printf("TAG:            ");
	dump_bin(tags, 8);
	printf("\n");
	/// TODO
	db_print_tags(tt, tags);
	printf("\n");
	printf("NOTE:           %s\n", (!note || !note[0]) ? "(none)" : note);
	printf("VALUE:          %s\n", (!value || !value[0]) ? "(none or hide)" : value);
}

data_entry *db_make_data_entry(char *name, char *note, char *value, char *tag)
{
	data_entry *dn = malloc(sizeof(data_entry));
	if(!dn) return NULL;
	memcpy(dn->tag, tag, 8);
	secure_strncpy(dn->name, name, EP_DATA_ENTRY_NAME_SIZE);
	secure_strncpy(dn->note, note, EP_DATA_ENTRY_NOTE_SIZE);
	memcpy(dn->value, value, EP_DATA_ENTRY_VALUE_SIZE);
	return dn;
}


void db_print_all_data(database *db)
{	
	size_t i;
	for(i = 0; i < db->header->nentry; i++) {
		chacha_ctx ctx[1];
		char iv[EP_IV_SIZE], key[EP_KEY_SIZE], buf[EP_DATA_ENTRY_SIZE];
		memcpy(iv, db->data[i].htag, EP_IV_SIZE);
		memcpy(key, db->header->table[i].key, EP_KEY_SIZE);
	
		crypto_stream_init(ctx, key, iv);
		
		// decrypt the data
		crypto_stream_compute(ctx, (char *)&db->data[i].data_entry, (char *)buf, EP_DATA_ENTRY_SIZE);
		
		printf("ENTRY:      ");
		dump_bin(db->data[i].htag, EP_HTAG_SIZE);
		printf("\n");
		
		db_print_data_entry(((data_entry *)buf)->name, ((data_entry *)buf)->note, ((data_entry *)buf)->value, db->header->tags, ((data_entry *)buf)->tag);
		
		printf("\n");
		printf("----------------------------------\n");
		printf("\n");
	}	
}

// Advanced functions

// include functions from KMP.c
long KMP_match_first(char *pat, size_t sp, char *txt, size_t st);
long KMP_match_all(char *pat, size_t sp, char *txt, size_t st, long **rtn);

// make the indicator string
static void make_str(char **s, int offset, long *arr, size_t arrlen)
{
	int i, max = 0;
	for(i = 0; i < arrlen; i++) {
		if(max < arr[i]) max = arr[i];
	}
	char *tmp = malloc(offset + max + 2);
	if(!tmp) return;
	memset(tmp, ' ', offset+max+1);
	memset(tmp+offset+max+1, 0, 1);
	//dump_bin(tmp, offset+max+1);
	//printf("\n");
	for(i = 0; i < arrlen; i++) {
		tmp[offset + arr[i]] = '^';
	}
	//printf("tmp: %s\n", tmp);
	//dump_bin(tmp, offset+max+1);
	*s = tmp;
}

///TODO: fix bug for this function !!!
void db_search_table(database *db, char *keyword)
{
	int i;
	// search tags
	char matched_tag[8] = {'\0'};
	for(i = 0; i < EP_TAG_MAX; i++) {
		int res = -1;
		if(db->header->tags[i]) {
			res = KMP_match_first(keyword, strlen(keyword), db->header->tags[i], EP_TAG_MAX_SIZE-1);
			if(res >= 0) {
				int a = i / 8;
				int o = i % 8;
				bit_mask_1(matched_tag+a, o);
			}
		}
	}
	
	int ct = 0;
	for(i = 0; i < db->header->nentry; i++) {
		long *idx = NULL;
		long count = 0;
		char *tmpstr = NULL;
		count = KMP_match_all(keyword, strlen(keyword), db->header->table[i].name, EP_TABLE_NAME_SIZE-1, &idx);
		if(count) {
			print_table_entry(db->header->table[i].htag, 6, \
								db->header->table[i].name, \
								NULL, NULL, NULL, NULL);
			//printf("count: %d\n", count);
			//long j;
			//for(j = 0; j < count; j++) {
			//	printf("%ld ", idx[j]);
			//}
			//printf("\n");
		
			make_str(&tmpstr, 12 + 3, idx, count);
			printf("%s\n", tmpstr);
			free(tmpstr);
			ct++;
		} else {
			///TODO
			char tmp[8];
			int flg = 0;
			int j;
			for(j = 0; j < 8; j++) {
				tmp[j] = db->header->table[i].tag[j] & matched_tag[j];
				if(tmp[j]) {
					flg = 1;
				}
			}
			if(flg) {
				print_table_entry(db->header->table[i].htag, 6, \
								db->header->table[i].name, \
								NULL, NULL, NULL, NULL);
				printf("MATCHED TAG: ");
				db_print_tags(db->header->tags, tmp);
				printf("\n");
				ct++;
			}
		}
		if(idx) {
			free(idx);
			idx = NULL;
		}
	}
	printf("total %d matched\n", ct);
}

// return the number of entry matched, 
// htag list is a freeable array contains all the htag of the entry that match the 
// keyword
int db_find_htag(database *db, char *keyword, char **htag_list)
{
	// allocate maximum memory
	char *ht_list = malloc(db->header->nentry * EP_HTAG_SIZE);
	
	//long KMP_match_first(char *pat, size_t sp, char *txt, size_t st);
	
	int i;
	int ct = 0;
	for(i = 0; i < db->header->nentry; i++) {
		long res = -1, res2 = -1;
		res = KMP_match_first(keyword, strlen(keyword), db->header->table[i].name, EP_TABLE_NAME_SIZE-1);
		/// TODO: Add conversion, HTAG is printed as hex and stored as byte stream
		/// it is meaningless to match hex from command line without conversion
		res2 = KMP_match_first(keyword, strlen(keyword), db->header->table[i].htag, EP_HTAG_SIZE);
		
		if(res != -1 || res2 != -1) {
			memcpy(ht_list + ct*EP_HTAG_SIZE, db->header->table[i].htag, EP_HTAG_SIZE);
			ct++;
		}
	}
	
	*htag_list = ht_list;
	return ct;
}

table_entry *db_find_table_entry_from_htag(database *db, char *htag)
{
	int i;
	for(i = 0; i < db->header->nentry; i++) {
		if(memcmp(db->header->table[i].htag, htag, EP_HTAG_SIZE) == 0) {
			//printf("!!!!");
			//dump_bin(htag, EP_HTAG_SIZE);
			//printf("\n");
			return &db->header->table[i];
		}
	}
	return NULL;
}
