#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "crypto.h"
#include "stream.h"
#include "util.h"
#include "db.h"
#include "key.h"
#include "config.h"

// require for correct build
#define OPTPARSE_IMPLEMENTATION

#include "optparse.h"
#include "dbg.h"
#include "docs.h"

enum command {
    COMMAND_UNKNOWN = -2,
    COMMAND_AMBIGUOUS = -1,
	COMMAND_KEYGEN,
    COMMAND_CREATE,
    COMMAND_LIST,
	COMMAND_SEARCH,
	COMMAND_ADD,
	COMMAND_DELETE,
	COMMAND_SHOW
};

static const char command_names[][12] = {
    "keygen", "create", "list", "search", "add", "delete", "show"
};

/**
 * Attempt to unambiguously parse the user's command into an enum.
 */
static enum command
parse_command(char *command)
{
    int found = COMMAND_UNKNOWN;
    size_t len = strlen(command);
    int i;
	/// remember to change the number to the # of actual commands
    for (i = 0; i < 7; i++) {
        if (strncmp(command, command_names[i], len) == 0) {
            if (found >= 0)
                return COMMAND_AMBIGUOUS;
            found = i;
        }
    }
    return found;
}


/* global variables */

// file path
char *keyfile = NULL;
char *dbfile = NULL;
// streams
stream *key_st = NULL;
stream *db_st = NULL;
// database object
database *db = NULL;

static void global_cleanup()
{
	if(key_st) { stream_close(key_st); key_st = NULL; }
	if(db_st) { stream_close(db_st); key_st = NULL; }
	if(db) { db_close(db); db = NULL; }
	if(keyfile) { free(keyfile); keyfile = NULL; }
	if(dbfile) { free(dbfile); dbfile = NULL; } 
}

static void global_init()
{
	key_st = stream_create(100, -1);
	db_st = stream_create(100, -1);
	check(key_st && db_st, "Failed to initialize the memory");
	
	return;

error:
	global_cleanup();
	exit(EXIT_FAILURE);
}

static int global_load_file(char *filename, stream *st)
{
	FILE *fin = NULL;
	
	check(filename && file_exists(filename), "No \"%s\" or \"%s\" is invalid", filename, filename);
	
	fin = fopen(filename, "rb");
	check(fin, "Failed to open \"%s\"", filename);
	long fsize = file_size(fin);
	check(fsize > 0, "file \"%s\" is invalid", filename);
	
	stream_read_from_file(st, fin, fsize);
	fclose(fin);
	fin = NULL;
	
	return 1;
	
error:
	global_cleanup();
	exit(EXIT_FAILURE);
	return 0;
}

static int global_write_file(char *filename, stream *st)
{
	FILE *fout = NULL;
	
	fout = fopen(filename, "wb");
	check(fout, "Failed to create file - \"%s\"", filename);
	check(fwrite(st->buf, st->datalen, 1, fout), "Failed to write file");
	check(!fflush(fout), "error flushing to file -- %s", strerror(errno));
	
	fclose(fout);
	fout = NULL;
	
	return 1;
	
error:
	global_cleanup();
	return 0;
}

static void print_usage(FILE *f)
{
    multiputs(docs_usage, f);
}

static void print_version(void)
{
    puts("EPD " EP_VERSION);
}

// command handlers

// EPD keygen <key_file>
void command_keygen(struct optparse *options)
{
	char *_keyfile = NULL;
	stream *_key_st = NULL;
	
	static const struct optparse_long keygen[] = {
        {0, 0, 0}
    };
	
	int option;
    while ((option = optparse_long(options, keygen, 0)) != -1) {
        switch (option) {
            default:
                printf("%s", options->errmsg);
				abort();
        }
    }
	
	_keyfile = optparse_arg(options);
	check(_keyfile, "You must provide the name of key file");
	
	check(key_create(&_key_st), "Failed to create key");
	
	//stream_dump(key_st);
	
	check(global_write_file(_keyfile, _key_st), "Failed to write key file");
	
	stream_close(_key_st);
	_key_st = NULL;
	return;
	
error:
	if(_key_st) stream_close(_key_st);
}

// EPD [-k <key>] create <db_name>
void command_create(struct optparse *options)
{
	char *name = NULL;
	char *filename = NULL;
	
	char pub[EP_KEY_SIZE];
	
	// handling sub commands
	static const struct optparse_long create[] = {
        {0, 0, 0}
    };

    int option;
    while ((option = optparse_long(options, create, 0)) != -1) {
        switch (option) {
            default:
                printf("%s", options->errmsg);
				abort();
        }
    }
	
	name = optparse_arg(options);
	check(name, "you have to name the database");
	
	check(keyfile , "No keyfile or keyfile is invalid");
	check(key_load_pub(key_st, pub), "Failed to load public key");
	
	/// TODO: print public key fingerprint
	
	db = db_create(name);
	db_write(db, db_st, pub);
	//stream_dump(db_st);
	db_close(db);
	db = NULL;
	
	filename = joinstr(2, name, EP_FILE_SUFFIX);
	//printf("filename: %s", filename);
	
	check(global_write_file(filename, db_st), "Failed to write database file");
	
	free(filename);
	filename = NULL;
	
	return;

error:
	if(db) { db_close(db); db = NULL; }
	if(filename) free(filename);
}

// EPD [-k <key> -d <db>] list
void command_list(struct optparse *options)
{	
	char sec[EP_KEY_SIZE];
	
	// handling sub commands
	static const struct optparse_long list[] = {
        {0, 0, 0}
    };

    int option;
    while ((option = optparse_long(options, list, 0)) != -1) {
        switch (option) {
            default:
                printf("%s", options->errmsg);
				abort();
        }
    }
	
	check(dbfile, "you have to specify the name of database");
	check(keyfile, "No keyfile or keyfile is invalid");
	
	check(key_load_sec(key_st, sec), "Failed to load secret key");
	
	db = db_load(db_st, sec);
	db_print_table(db, EP_HTAG_SIZE);
	db_close(db);
	db = NULL;
	
	return;
	
error:
	if(db) { db_close(db); db = NULL; }
}

// EPD [-k <key> -d <db>] search <keyword>
void command_search(struct optparse *options)
{
	char *keyword = NULL;
	
	char sec[EP_KEY_SIZE];
	
	// handling sub commands
	static const struct optparse_long search[] = {
        {0, 0, 0}
    };

    int option;
    while ((option = optparse_long(options, search, 0)) != -1) {
        switch (option) {
            default:
                printf("%s", options->errmsg);
				abort();
        }
    }

	keyword = optparse_arg(options);
	check(keyword && strlen(keyword), "No search keyword");

	check(dbfile, "you have to specify the name of database");
	check(keyfile, "No keyfile or keyfile is invalid");
	
	check(key_load_sec(key_st, sec), "Failed to load secret key");
	
	db = db_load(db_st, sec);
	printf("searching result of keyword \"%s\"\n", keyword);
	db_search_table(db, keyword);
	db_close(db);
	db = NULL;
	
	return;
	
error:
	if(db) { db_close(db); db = NULL; }
}

// EPD [-k <key> -d <db>] add [-e <entry name> -n <note> -v <value> -t <tag> -k <key>]
void command_add(struct optparse *options)
{
	char *entry = NULL;
	char entry_flg = 0;
	char *note = NULL;
	char note_flg = 0;
	char value[EP_DATA_ENTRY_VALUE_SIZE] = {'\0'};
	char *tag = NULL;
	char tag_buf[8] = {'\0'};
	char input_buf[256] = {'\0'};
	char **str_list = NULL;
	
	int i, res = 0;
	
	char key[EP_KEY_SIZE] = {'\0'}, fp[EP_HASH_SIZE];
	char *_keyfile = NULL;
	stream *_key_st = NULL;
	
	data_entry *new_entry = NULL;
	
	char sec[EP_KEY_SIZE], pub[EP_KEY_SIZE];
	char ht[EP_HTAG_SIZE];
	
	options->permute = 0;
	
	// handling sub commands
	static const struct optparse_long add[] = {
		{"entry", 	'e', OPTPARSE_REQUIRED},
		{"note", 	'n', OPTPARSE_REQUIRED},
		{"value", 	'v', OPTPARSE_REQUIRED},
		{"tag", 	't', OPTPARSE_REQUIRED},
		{"key",     'k', OPTPARSE_REQUIRED},
        {0, 0, 0}
    };

    int option;
    while ((option = optparse_long(options, add, 0)) != -1) {
        switch (option) {
			case 'e':
                entry = options->optarg;
				if(entry && strlen(entry) > EP_DATA_ENTRY_NAME_SIZE)
					log_warn("input too long, only first %d character will be saved", EP_DATA_ENTRY_NAME_SIZE-1);
                break;
			case 'n':
                note = options->optarg;
				if(note && strlen(note) > EP_DATA_ENTRY_NOTE_SIZE)
					log_warn("input too long, only first %d character will be saved", EP_DATA_ENTRY_NOTE_SIZE-1);
                break;
			case 'v':
				log_warn("sensitive value are shown in command line");
                check(secure_strncpy(value, options->optarg, EP_DATA_ENTRY_VALUE_SIZE), "failed to copy value");
				if(strlen(value) > EP_DATA_ENTRY_VALUE_SIZE)
					log_warn("input too long, only first %d character will be saved", EP_DATA_ENTRY_VALUE_SIZE-1);
                break;
			case 't':
				tag = options->optarg;
				if(strlen(tag) > 256) {
					log_warn("tag too long, only the first 255 characters will be parsed");
				}
				secure_strncpy(input_buf, tag, 256);
				break;
			case 'k':
				_keyfile = options->optarg;
				break;
            default:
                printf("%s", options->errmsg);
				abort();
        }
    }
    
    options->permute = 1;

	check(dbfile, "you have to specify the name of database");
	check(keyfile, "No keyfile or keyfile is invalid");
	
	check(key_load_pub(key_st, pub), "Failed to load public key");
	check(key_load_sec(key_st, sec), "Failed to load secret key");
	
	if(_keyfile) {
		_key_st = stream_create(100, -1);
		check(global_load_file(_keyfile, _key_st), "Failed to load additional key");
		check(key_load_pub(_key_st, key), "Failed to load additional key");
		stream_close(_key_st);
		_key_st = NULL;
	} else {
		log_warn("No additional key specified, using default key");
		memcpy(key, pub, EP_KEY_SIZE);
	}
	
	// compute fingerprint
	crypto_sha256(key, EP_HASH_SIZE, fp);
	printf("entry public key fingerprint: ");
	dump_bin(fp, EP_FP_SIZE);
	printf("\n");
	
	db = db_load(db_st, sec);
	//db_print_status(db);
	
	// actual work
	if(!entry) {
		entry = malloc(EP_DATA_ENTRY_NAME_SIZE);
		check_mem(entry);
		entry_flg = 1;
		check(get_input(entry, EP_DATA_ENTRY_NAME_SIZE, "entry name (leave blank for none): "), \
				"Failed to get entry name");
	}
	if(!note) {
		note = malloc(EP_DATA_ENTRY_NOTE_SIZE);
		check_mem(note);
		note_flg = 1;
		check(get_input(note, EP_DATA_ENTRY_NAME_SIZE, "note (leave blank for none): "), \
				"Failed to get note");
	}
	if(!value[0]) {
		get_passphrase(value, EP_DATA_ENTRY_VALUE_SIZE, "value (leave blank for none): ");
	}
	if(!input_buf[0]) {
		// this is not future proof, but implement anyway ...
		// this may have bugs related to endianess, which may affect the
		// portability of this program (works on little endian machine)
		get_input(input_buf, 256, "tag (enter numbers, 0 to 63, leave space between them if there is more than one, blank for none): ");
	}
	if(input_buf[0]) {
		res = split_str(input_buf, ' ', &str_list);
		check(res, "Failed to split string");
		for(i = 0; i < res; i++) {
			int tmp = -1, a, o;
			tag = str_list[i];
			check(str_to_int(tag, &tmp), "invalid input");
			check(tmp >= 0 && tmp < EP_TAG_MAX, \
				"unrecognized parameter or invalid input - \"%s\"", tag);
			a = tmp / 8;
			o = tmp % 8;
			bit_mask_1(tag_buf+a, o);
		}
		if(str_list) { free(str_list[0]); str_list[0] = NULL; free(str_list); str_list = NULL; }
	}
	
	
	// encrypt the value
	///////////////////////////////////////////
	char esec[EP_KEY_SIZE], epub[EP_KEY_SIZE], shared[EP_KEY_SIZE], iv[EP_HASH_SIZE];
	chacha_ctx ctx[1];
	
	crypto_curve_generate_secret(esec);
	crypto_curve_compute_public(epub, esec);
	
	// compute shared key for encryption
	crypto_curve_compute_shared(shared, esec, key);
	
	// compute iv using shared key
	crypto_sha256(shared, EP_KEY_SIZE, iv);
	
	crypto_stream_init(ctx, shared, iv);
	crypto_stream_compute(ctx, value, value, EP_DATA_ENTRY_VALUE_SIZE);
	
	////////////////////////////////////////////
	
	
	printf("the following entry will be added to database: \n");
	db_print_data_entry(entry, note, NULL, db->header->tags, tag_buf);
	
	if(get_confirm("Do you want to continue?")) {
		new_entry = db_make_data_entry(entry, note, value, tag_buf);
		//dump_bin(tag_buf, 8);
		check_mem(new_entry);
		check(db_add_entry(db, new_entry, epub, ht), "Failed to add entry");
		memcpy(db->header->table[db->header->nentry-1].fp, fp, EP_FP_SIZE);
		//db_print_status(db);
		free(new_entry);
		new_entry = NULL;
		log_info("data entry successfully added with htag ");
		dump_bin(ht, EP_HTAG_SIZE);
		printf("\n");
	}
	
	stream_clear(db_st);
	db_write(db, db_st, pub);

	db_close(db);
	db = NULL;
	
	check(global_write_file(dbfile, db_st), "Failed to write database file");
	
	if(entry_flg) free(entry);
	if(note_flg) free(note);
	
	return;
	
error:
	if(_key_st) stream_close(_key_st);
	if(db) { db_close(db); db = NULL; }
	
	if(str_list) { free(str_list[0]); free(str_list); }
	
	if(entry_flg) free(entry);
	if(note_flg) free(note);
	if(new_entry) free(new_entry);
}

/// TODO: Fix the bug for this function
/// Sometimes it delete the wrong item
// EPD [-k <key> -d <db>] delete <htag or name>
void command_delete(struct optparse *options)
{
	char *keyword = NULL;
	
	char sec[EP_KEY_SIZE], pub[EP_KEY_SIZE];
	
	char *ht_list = NULL;
	int res = 0, res2 = 0;
	int i;
	
	// handling sub commands
	static const struct optparse_long delete[] = {
        {0, 0, 0}
    };

    int option;
    while ((option = optparse_long(options, delete, 0)) != -1) {
        switch (option) {
            default:
                printf("%s", options->errmsg);
				abort();
        }
    }

	keyword = optparse_arg(options);
	check(keyword, "You must enter part of the htag, or part of the name of the entry");
	
	check(dbfile, "you have to specify the name of database");
	check(keyfile, "No keyfile or keyfile is invalid");
	
	check(key_load_pub(key_st, pub), "Failed to load public key");
	check(key_load_sec(key_st, sec), "Failed to load secret key");
	
	db = db_load(db_st, sec);
	
	// actuall work
	res = db_find_htag(db, keyword, &ht_list);
	check(res, "Could not find any entry matched the keyword or htag \"%s\"", keyword);
	
	//printf("\n");
	//dump_bin(ht_list, db->header->nentry*EP_HTAG_SIZE);
	//printf("\n");
	
	for(i = 0; i < res; i++) {
		table_entry *tn = NULL;
		tn = db_find_table_entry_from_htag(db, ht_list + i*EP_HTAG_SIZE);
		if(tn) {
			printf("%d: ", i);
			db_print_table_entry(tn, EP_HTAG_SIZE);
		}
	}
	char buf[5];
	check(get_input(buf, 5, "Which entry would you like to delete? \
			\nEnter the number before the entry you want to delete "), \
			"Invalid input, do nothing");
	
	check(str_to_int(buf, &res2), "Invalid input, do nothing"); 
	check(res2 >= 0 && res2 < res, "Invalid input, do nothing");
	
	db_delete_entry(db, ht_list + res2*EP_HTAG_SIZE);
	free(ht_list);
	
	stream_clear(db_st);
	db_write(db, db_st, pub);

	db_close(db);
	db = NULL;
	
	check(global_write_file(dbfile, db_st), "Failed to write database file");
	
	return;
	
error:
	if(db) { db_close(db); db = NULL; }
	if(ht_list) free(ht_list);
}

// EPD [-k <key> -d <db>] show [-k <key>] [entry/name note value] <htag>
void command_show(struct optparse *options)
{
	char sec[EP_KEY_SIZE];
	char *_command = NULL;
	char *htag_str = NULL;
	char *htag = NULL;
	
	char *name = NULL;
	char *note = NULL;
	char value[EP_DATA_ENTRY_VALUE_SIZE] = {'\0'};
	table_entry *tn = NULL;
	
	char key[EP_KEY_SIZE] = {'\0'}, key_pub[EP_KEY_SIZE], fp[EP_HASH_SIZE];
	char empty_buf[16] = {'\0'};
	char *_keyfile = NULL;
	stream *_key_st = NULL;
	
	int found = -1;
    int i, res = 0;
    
	// handling sub commands
	static const struct optparse_long show[] = {
		{"key",     'k', OPTPARSE_REQUIRED},
        {0, 0, 0}
    };
    
    #define _COMMAND_NAME 0
    #define _COMMAND_ENTRY 1
    #define _COMMAND_NOTE 2
    #define _COMMAND_VALUE 3
    
    //static const enum __command {
    //	_COMMAND_NAME, _COMMAND_ENTRY, _COMMAND_NOTE, _COMMAND_VALUE
    //};
    
    static const char _command_names[][12] = {
    	"name", "entry", "note", "value"
	};
	
	options->permute = 0;

    int option;
    while ((option = optparse_long(options, show, 0)) != -1) {
        switch (option) {
        	case 'k':
				_keyfile = options->optarg;
				break;
            default:
                printf("%s", options->errmsg);
				abort();
        }
    }
	
	options->permute = 1;
	
	_command = optparse_arg(options);
	check(_command, "You need to enter what to show");
	
	// check the htag first
	htag_str = optparse_arg(options);
	check(htag_str, "you need to enter htag");
	res = hex_to_byte(htag_str, &htag);
	check(res, "failed to read htag");
	
	/// remember to change the number to the # of actual commands
    for (i = 0; i < 4; i++) {
        if (strncmp(_command, _command_names[i], strlen(_command)) == 0) {
            if (found >= 0)
                found = -2;
            found = i;
        }
    }
    
    check(dbfile, "you have to specify the name of database");
	check(keyfile, "No keyfile or keyfile is invalid");
	
	check(key_load_sec(key_st, sec), "Failed to load secret key");
	
	db = db_load(db_st, sec);
	
	switch(found) {
		case -1:
        case -2:
        	log_err("no sub-command \"%s\" in show", _command);
        	break;
        case _COMMAND_NAME:
        case _COMMAND_ENTRY:
        	name = malloc(EP_DATA_ENTRY_NAME_SIZE);
        	check_mem(name);
        	check(db_get_fullname(db, htag, name), "Fail to get name");
        	printf("%s\n", name);
        	free(name);
        	name = NULL;
        	break;
        case _COMMAND_NOTE:
        	note = malloc(EP_DATA_ENTRY_NOTE_SIZE);
        	check_mem(note);
        	check(db_get_note(db, htag, note), "Fail to get note");
        	printf("%s\n", note);
        	free(note);
        	note = NULL;
        	break;
        case _COMMAND_VALUE:
        	check(db_get_value(db, htag, value), "Fail to get value");
        	
        	tn = db_find_table_entry_from_htag(db, htag);
        	// print the value if not encrypted
        	if(memcmp(tn->fp, empty_buf, EP_FP_SIZE) == 0) {
        		printf("%s\n", value);
        		break;
        	}
        	
        	///////////////////////////////////
			if(_keyfile) {
				log_info("loading additional key ... ");
				_key_st = stream_create(100, -1);
				check(global_load_file(_keyfile, _key_st), "Failed to load additional key");
				check(key_load_sec(_key_st, key), "Failed to load additional key");
				check(key_load_pub(_key_st, key_pub), "Failed to load additional key");
				stream_close(_key_st);
				_key_st = NULL;
			} else {
				log_warn("No additional key specified, using default key");
				memcpy(key, sec, EP_KEY_SIZE);
				check(key_load_pub(key_st, key_pub), "Failed to load public key");
			}

			// compute fingerprint
			crypto_sha256(key_pub, EP_HASH_SIZE, fp);
			printf("entry public key fingerprint: ");
			dump_bin(fp, EP_FP_SIZE);
			printf("\n");
			///////////////////////////////////
        	
        	
        	// decrypt the value
			///////////////////////////////////////////
			char epub[EP_KEY_SIZE], shared[EP_KEY_SIZE], iv[EP_HASH_SIZE];
			chacha_ctx ctx[1];
			
			tn = db_find_table_entry_from_htag(db, htag);
			
			// verify fingerprint
			check(memcmp(tn->fp, fp, EP_FP_SIZE) == 0, "You are using the wrong key - fingerprint mismatch");
			
			memcpy(epub, tn->key, EP_KEY_SIZE);
			crypto_curve_compute_shared(shared, key, epub);
			
			// compute iv using shared key
			crypto_sha256(shared, EP_KEY_SIZE, iv);
	
			crypto_stream_init(ctx, shared, iv);
			crypto_stream_compute(ctx, value, value, EP_DATA_ENTRY_VALUE_SIZE);
			////////////////////////////////////////////
        	
        	printf("%s\n", value);
        	memset(value, 0, EP_DATA_ENTRY_VALUE_SIZE);
        	break;
    }
    free(htag);
    htag = NULL;
    
    return;

error:
	if(name) free(name);
	if(note) free(note);
	
	if(htag) free(htag);
	
	// NOT COMPLETE YET
}

int
main(int argc, char **argv)
{
    static const struct optparse_long global[] = {
        {"key",      	'k', OPTPARSE_REQUIRED},
        {"database",	'd', OPTPARSE_REQUIRED},
        {"version",		'v', OPTPARSE_NONE},
        {"help",		'h', OPTPARSE_NONE},
        {0, 0, 0}
    };

    int option;
    char *command;
    struct optparse options[1];
    optparse_init(options, argv);
    options->permute = 0;
    (void)argc;
    
    global_init();

    while ((option = optparse_long(options, global, 0)) != -1) {
        switch (option) {
            case 'k':
                if(options->optarg && strlen(options->optarg) > 0) {
                	keyfile = dupstr(options->optarg);
                }
                global_load_file(keyfile, key_st);
                break;
            case 'd':
                if(options->optarg && strlen(options->optarg) > 0) {
                	dbfile = dupstr(options->optarg);
                }
                global_load_file(dbfile, db_st);
                break;
            case 'h':
                print_usage(stdout);
                exit(EXIT_SUCCESS);
                break;
            case 'v':
                print_version();
                exit(EXIT_SUCCESS);
                break;
            default:
                printf("%s", options->errmsg);
				abort();
        }
    }

    command = optparse_arg(options);
    options->permute = 1;
    if (!command) {
        fprintf(stderr, "EPD: missing command\n");
        print_usage(stderr);
        exit(EXIT_FAILURE);
    }

    switch (parse_command(command)) {
        case COMMAND_UNKNOWN:
        case COMMAND_AMBIGUOUS:
            fprintf(stderr, "EPD: unknown command, %s\n", command);
            print_usage(stderr);
            exit(EXIT_FAILURE);
            break;
        case COMMAND_KEYGEN:
            command_keygen(options);
			//printf("keygen");
            break;
        case COMMAND_CREATE:
            command_create(options);
			//printf("create");
            break;
        case COMMAND_LIST:
            command_list(options);
			//printf("list");
            break;
		case COMMAND_SEARCH:
            command_search(options);
			//printf("search");
            break;
		case COMMAND_ADD:
            command_add(options);
			//printf("add");
            break;
		case COMMAND_DELETE:
            command_delete(options);
			//printf("delete");
            break;
        case COMMAND_SHOW:
            command_show(options);
			//printf("show");
            break;
    }
    global_cleanup();

    return 0;
}
