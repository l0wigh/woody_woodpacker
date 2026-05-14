#ifndef WOODY_H
# define WOODY_H

#include <stddef.h>
#include <stdio.h>
#include <linux/limits.h>
#include <stdio.h>
#include <elf.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>

#include <stdlib.h>

#define BUFFER_SIZE 4096
#define NAME_MAX_LEN 256
#define CHECKSUM_SIZE 64
#define DEFAULT_KEY "FUC**** key used with a xor to crypt binary!"


#define COLOR_RED     "\033[0;31m"
#define COLOR_GREEN   "\033[0;32m"
#define COLOR_YELLOW  "\033[0;33m"
#define COLOR_BLUE    "\033[0;34m"
#define COLOR_CYAN    "\033[0;36m"
#define COLOR_RESET   "\033[0m"

#define LOG_PRINT(level, color, fmt, ...) \
	fprintf(stderr, color "[%s] [%s] " fmt COLOR_RESET "\n", level, __TIME__, ##__VA_ARGS__)

#define LOG_DEBUG(fmt, ...) \
	fprintf(stderr, COLOR_CYAN "[DEBUG] [%s] [%s:%d] " fmt COLOR_RESET "\n", \
		__TIME__, __FUNCTION__, __LINE__, ##__VA_ARGS__)
#define LOG_OK(fmt, ...)	LOG_PRINT("OK", COLOR_GREEN, fmt , ##__VA_ARGS__)
#define LOG_INFO(fmt, ...)	LOG_PRINT("INFO", COLOR_RESET, fmt, ##__VA_ARGS__)
#define LOG_WARN(fmt, ...)	LOG_PRINT("WARN", COLOR_YELLOW, fmt, ##__VA_ARGS__)
#define LOG_ERROR(fmt, ...)	LOG_PRINT("ERROR", COLOR_RED, fmt, ##__VA_ARGS__)
#define LOG_TMP(fmt, ...)	LOG_PRINT("OTHER", COLOR_BLUE, fmt, ##__VA_ARGS__)

typedef enum ERROR_E {
	ERR_OK,
	ERR_ARGS,
	ERR_NOTELF,
	ERR_NOKEY,
	ERR_NOTARGET
} STATUS;

struct packer_t;

typedef STATUS (*_checker)(const struct packer_t *pak);	// Check ELF
typedef STATUS (*_checksum)(const struct packer_t *pak);
typedef STATUS (*_encrypt)(const void *file, const size_t len, const char *key, void *result);
typedef STATUS (*_decrypt)(const void *file, const size_t len, const char *key, void *result);
typedef STATUS (*_pack)(const struct packer_t *pak);
typedef STATUS (*_unpack)(const struct packer_t *pak);
typedef STATUS (*_create_elf)(const struct packer_t *pak);

typedef struct packer_t {
	// Variables
	FILE		*file;
	ssize_t		filesize;
	Elf64_Ehdr	header;
	Elf64_Addr	original_entry;	// Point d'entré origine
	Elf64_Phdr	*prog_header;	// Pour segment LOAD
	Elf64_Xword	size_payload;
	char		checksum[CHECKSUM_SIZE];
	char		name[NAME_MAX_LEN];
	FILE		*binary;

	// Functions
	_checker	check_file;
	_checksum	get_checksum;
	_encrypt	encrypt;
	_decrypt	decrypt;
	_pack		pack;
	_unpack		unpack;
	_create_elf	create_elf;
} packer;

typedef struct var_stub {
	Elf64_Addr	 	old_entry;
	Elf64_Addr	 	to_sub;
	Elf64_Addr 	 	text_addr;
	Elf64_Addr  	text_size;
	char		  	xor_key;
} var_stub;

#endif
