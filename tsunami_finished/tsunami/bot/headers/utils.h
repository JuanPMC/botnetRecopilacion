#pragma once

#include "includes.h"
#include "scan.h"

int util_strlen(char *);
void util_memcpy(void *, void *, int);
void util_null(void *, char, int);
void util_strcpy(char *, char *);
void util_strcat(char *, char *);
uint32_t util_get_local_addr(void);
BOOL util_strcmp(char *, char *);
uint32_t get_random_dns_resolver(void);
