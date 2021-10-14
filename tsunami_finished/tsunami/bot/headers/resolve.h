#pragma once

#include "includes.h"

#include <stdint.h>

struct dnshdr
{
	// id, options, query domain count, answer count, ns count, additional record count
    uint16_t id;
    uint16_t options;
    uint16_t qd_count;
    uint16_t answer_count;
    uint16_t ns_count;
    uint16_t ar_count;
};

struct dns_question
{
	uint16_t query_type;
	uint16_t query_class;
};

struct dns_resource
{
    uint16_t type;
    uint16_t class;
    uint32_t ttl;
    uint16_t p;
    char buf[DNS_TXT_MAX_SIZE];
} __attribute__((packed));

struct resolve
{
	char buf[DNS_TXT_MAX_SIZE];
	uint16_t data_len;
};

struct grehdr
{
    uint16_t protocol;
    uint16_t options;
};

enum
{
	QUERY_TYPE_TXT = 16,
	QUERY_CLASS_IP = 1,
	QUERY_TYPE_A = 1,
};

struct resolve *dns_lookup(char *, uint8_t);
void domain_to_name(char *, char *, int);
