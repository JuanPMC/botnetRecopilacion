#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#include "csum.h"

unsigned int rand_int(void)
{
	srand(time(NULL));
	unsigned int a = rand() % 0xffff;
	return a;
}

unsigned short csum (unsigned short *buf, int count) {
    register uint64_t sum = 0;
    while( count > 1 ) {
        sum += *buf++;
        count -= 2;
    }
    if(count > 0) {
        sum += *(unsigned char *)buf;
    }
    while (sum>>16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    return (uint16_t)(~sum);
}

unsigned short tcpcsum(struct iphdr *iph, struct tcphdr *tcph) {
    struct tcp_pseudo {
        unsigned long src_addr;
        unsigned long dst_addr;
        unsigned char zero;
        unsigned char proto;
        unsigned short length;
    } pseudohead;
    unsigned short total_len = iph->tot_len;
    pseudohead.src_addr=iph->saddr;
    pseudohead.dst_addr=iph->daddr;
    pseudohead.zero=0;
    pseudohead.proto=IPPROTO_TCP;
    pseudohead.length=htons(sizeof(struct tcphdr));
    int totaltcp_len = sizeof(struct tcp_pseudo) + sizeof(struct tcphdr);
    unsigned short *tcp = malloc(totaltcp_len);
    memcpy((unsigned char *)tcp,&pseudohead,sizeof(struct tcp_pseudo));
    memcpy((unsigned char *)tcp+sizeof(struct tcp_pseudo),(unsigned char *)tcph,sizeof(struct tcphdr));
    unsigned short output = csum(tcp,totaltcp_len);
    free(tcp);
    return output;
}

uint16_t checksum_tcp_udp(struct iphdr *iph, void *buff, uint16_t data_len, int len)
{
    const uint16_t *buf = buff;
    uint32_t ip_src = iph->saddr;
    uint32_t ip_dst = iph->daddr;
    uint32_t sum = 0;
    int length = len;
    while (len > 1)
    {
        sum += *buf;
        buf++;
        len -= 2;
    }
    if (len == 1)
        sum += *((uint8_t *) buf);
    sum += (ip_src >> 16) & 0xFFFF;
    sum += ip_src & 0xFFFF;
    sum += (ip_dst >> 16) & 0xFFFF;
    sum += ip_dst & 0xFFFF;
    sum += htons(iph->protocol);
    sum += data_len;
    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);
    return ((uint16_t) (~sum));
}