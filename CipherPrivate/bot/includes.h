#define INET_ADDR(o1,o2,o3,o4) (htonl((o1 << 24) | (o2 << 16) | (o3 << 8) | (o4 << 0))) // yes i got this idea from mirai...

#define TRUE 1
#define FALSE 0
#define cip(gg)   (gg) + 0x44
#define ciu(cip)  do { char * crypts = cip ; while (*crypts) *crypts++ -= 0x44; } while(0)
#define cih(cip)  do {char * crypts = cip ; while (*crypts) *crypts++ += 0x44;} while(0)

typedef char BOOL;
typedef uint32_t ipv4_t;
typedef uint16_t port_t;
#define INET_ADDR(o1,o2,o3,o4) (htonl((o1 << 24) | (o2 << 16) | (o3 << 8) | (o4 << 0)))
ipv4_t LOCAL_ADDR;
#define LOCALHOST (INET_ADDR(127, 0, 0, 1))
