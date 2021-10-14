unsigned int rand_int(void);
unsigned short csum (unsigned short *, int );
unsigned short tcpcsum(struct iphdr *, struct tcphdr *);
uint16_t checksum_tcp_udp(struct iphdr *, void *, uint16_t , int );