#define _GNU_SOURCE

#include <time.h>
#include <stdint.h>
#include <unistd.h>
#include <stdlib.h>

static uint32_t t = 0, p = 0, c = 0, f = 0;
static char alpha_set[32] = "pdlbwairmoheqc18k5fgstv4jn072u63";

void init_rand(void)
{
    // Allow us every second to generate a new seed.
	t = time(NULL);
    // We call getppid() just incase we are inside a child.
    p = getpid() ^ getppid();
    c = clock();
	f = c ^ p;
}

uint32_t rand_new(void)
{
    uint32_t tmp = t;
    tmp ^= tmp << 15;
    tmp ^= tmp >> 9;
    t = p;
    p = c;
    c = f;
    f ^= f >> 13;
    f ^= tmp;
    return f;
}

void rand_string(uint8_t *b, int len)
{
    int i = 0;
    uint32_t e = 0;

    for(i = 0; i < len; i++)
    {
        e = rand_new();

        // Keep this value below 255
        uint8_t t = e & 0xff;

        // Some shifts to keep below 32
        e = e >> 8;
        t = t >> 3;

        *b++ = alpha_set[t];
    }

    return;
}
