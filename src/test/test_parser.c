#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// require for correct build
#define OPTPARSE_IMPLEMENTATION

#include "../optparse.h"

/**
 * Print a nice fingerprint of a key.
 */
//static void
//print_fingerprint(const uint8_t *key)
//{
//    int i;
//    uint8_t hash[32];
//    SHA256_CTX sha[1];
//
//    sha256_init(sha);
//    sha256_update(sha, key, 32);
//    sha256_final(sha, hash);
//    for (i = 0; i < 16; i += 4) {
//        unsigned long chunk =
//            ((unsigned long)hash[i + 0] << 24) |
//            ((unsigned long)hash[i + 1] << 16) |
//            ((unsigned long)hash[i + 2] <<  8) |
//            ((unsigned long)hash[i + 3] <<  0);
//        printf("%s%08lx", i ? "-" : "", chunk);
//    }
//}

enum command {
    COMMAND_UNKNOWN = -2,
    COMMAND_AMBIGUOUS = -1,
    COMMAND_KEYGEN,
    COMMAND_FINGERPRINT,
    COMMAND_ARCHIVE,
    COMMAND_EXTRACT
};

char *global_pubkey = NULL, *global_seckey = NULL;

static const char command_names[][12] = {
    "keygen", "fingerprint", "archive", "extract"
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
    for (i = 0; i < 5; i++) {
        if (strncmp(command, command_names[i], len) == 0) {
            if (found >= 0)
                return COMMAND_AMBIGUOUS;
            found = i;
        }
    }
    return found;
}

// command handler
void command_keygen(struct optparse *options)
{
	static const struct optparse_long fingerprint[] = {
        {0, 0, 0}
    };

    int option;
    while ((option = optparse_long(options, fingerprint, 0)) != -1) {
        switch (option) {
            default:
                printf("%s", options->errmsg);
				abort();
        }
    }
	
    printf("%s", "keygen\n");
}
void command_fingerprint(struct optparse *options)
{
	static const struct optparse_long fingerprint[] = {
        {0, 0, 0}
    };

    int option;
    while ((option = optparse_long(options, fingerprint, 0)) != -1) {
        switch (option) {
            default:
                printf("%s", options->errmsg);
				abort();
        }
    }
	
    printf("%s", "fingerprint\n");
}
void command_archive(struct optparse *options)
{
	static const struct optparse_long fingerprint[] = {
        {0, 0, 0}
    };

    int option;
    while ((option = optparse_long(options, fingerprint, 0)) != -1) {
        switch (option) {
            default:
                printf("%s", options->errmsg);
				abort();
        }
    }
	
    printf("%s", "archive\n");
}
void command_extract(struct optparse *options)
{
	static const struct optparse_long fingerprint[] = {
        {0, 0, 0}
    };

    int option;
    while ((option = optparse_long(options, fingerprint, 0)) != -1) {
        switch (option) {
            default:
                printf("%s", options->errmsg);
				abort();
        }
    }
	
    printf("%s", "extract\n");
}

int main(int argc, char **argv)
{
	// global options
    static const struct optparse_long global[] = {
        {"pubkey",        'p', OPTPARSE_REQUIRED},
        {"seckey",        's', OPTPARSE_REQUIRED},
        {"version",       'V', OPTPARSE_NONE},
        {"help",          'h', OPTPARSE_NONE},
        {0, 0, 0}
    };

    int option;
    char *command;
    struct optparse options[1];
    optparse_init(options, argv);
    options->permute = 0;
    (void)argc;

    while ((option = optparse_long(options, global, 0)) != -1) {
        switch (option) {
            case 'p':
                global_pubkey = options->optarg;
                break;
            case 's':
                global_seckey = options->optarg;
                break;
            case 'h':
                printf("%s\n", "The help message");
                exit(EXIT_SUCCESS);
                break;
            case 'V':
                printf("%s\n", "The version");
                exit(EXIT_SUCCESS);
                break;
            default:
                printf("%s", options->errmsg);
				exit(EXIT_FAILURE);
        }
    }

	
	if(global_pubkey) printf("public key: %s\n", global_pubkey);
	if(global_seckey) printf("secret key: %s\n", global_seckey);
	
    command = optparse_arg(options);
    options->permute = 1;
    if (!command) {
        fprintf(stderr, "enchive: missing command\n");
        exit(EXIT_FAILURE);
    }

    switch (parse_command(command)) {
        case COMMAND_UNKNOWN:
        case COMMAND_AMBIGUOUS:
            fprintf(stderr, "enchive: unknown command, %s\n", command);
            exit(EXIT_FAILURE);
            break;
        case COMMAND_KEYGEN:
            command_keygen(options);
            break;
        case COMMAND_FINGERPRINT:
            command_fingerprint(options);
            break;
        case COMMAND_ARCHIVE:
            command_archive(options);
            break;
        case COMMAND_EXTRACT:
            command_extract(options);
            break;
    }

    return 0;
}
