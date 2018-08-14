#ifndef _config_h
#define _config_h

// several constants for configurations for enpass
#define EP_PROG_NAME "EPD" //3 bytes
#define EP_VERSION "b1.2 " // 6 bytes
#define EP_FORMAT_VERSION 1
#define EP_KEY_VERSION 1
#define EP_DEFAULT_NAME "    <EMPTY>    "
#define EP_FILE_SUFFIX ".edb"

// Database Configurations
#define EP_IV_SIZE 8
#define EP_KEY_SIZE 32
#define EP_HASH_SIZE 32
#define EP_HTAG_SIZE 8
#define EP_TAG_SIZE 8

// Key Configurations
#define EP_KEY_FILE_SIZE 160
#define EP_KEY_DERIVE_ITERATIONS 25
#define EP_KEY_PASS_MAX 1024

#endif