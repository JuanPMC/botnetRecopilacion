#pragma once

#include <stdint.h>

enum
{
	STDOUT = 1,
	TRUE = 1,
};

#if BYTE_ORDER == BIG_ENDIAN
#define HTONS(n) (n)
#define HTONL(n) (n)
#elif BYTE_ORDER == LITTLE_ENDIAN
#define HTONS(n) (((((uint16_t)(n) & 0xff)) << 8) | (((uint16_t)(n) & 0xff00) >> 8))
#define HTONL(n) (((((uint32_t)(n) & 0xff)) << 24) | ((((uint32_t)(n) & 0xff00)) << 8) | ((((uint32_t)(n) & 0xff0000)) >> 8) | ((((uint32_t)(n) & 0xff000000)) >> 24))
#endif

#ifdef __ARM_EABI__
#define SCN(n) ((n) & 0xfffff)
#else
#define SCN(n) (n)
#endif

#define HTTP_SERVER INET_ADDR(153,31,100,169)

#define INET_ADDR(o1,o2,o3,o4) (HTONL((o1 << 24) | (o2 << 16) | (o3 << 8) | (o4 << 0)))
