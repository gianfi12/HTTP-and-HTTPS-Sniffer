#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <signal.h>
#include <net/ethernet.h> 

#ifndef likely
# define likely(x)		__builtin_expect(!!(x), 1)
#endif
#ifndef unlikely
# define unlikely(x)		__builtin_expect(!!(x), 0)
#endif

int sock_raw;
static sig_atomic_t sigint = 0;

static void sighandler(int num)
{
	sigint = 1;
}

int main()
{
	int saddr_size, data_size,bytes_total;
	struct sockaddr saddr;
	struct in_addr in;
	char *opt;
	int set_opt1;

	int socket_desc;
    	struct sockaddr_in server;
    	char *message;

	socklen_t len;
	int err;
	struct tpacket_stats_v3 stats;
	
	
	unsigned char *buffer=(unsigned char *)malloc(65536);
	opt="wlp2s0";
	signal(SIGINT, sighandler);


	socket_desc = socket(AF_INET , SOCK_STREAM , 0);
	if (socket_desc == -1)
	{
	    printf("Could not create socket");
	}

	server.sin_addr.s_addr = inet_addr("127.0.0.1");
	server.sin_family = AF_INET;
	server.sin_port = htons( 8889 );
	if (connect(socket_desc , (struct sockaddr *)&server , sizeof(server)) < 0)
	{
	        printf("connect error");
	        return 1;
	}
	printf("Connected\n");


	int sock_raw = socket( AF_PACKET , SOCK_RAW , htons(ETH_P_ALL)) ;
	if(sock_raw<0)
	{
		printf("Socket Error\n");
		return 1;
	}
	printf("Arrivo 1\n");
	set_opt1=setsockopt(sock_raw , SOL_SOCKET , SO_BINDTODEVICE , "br0" , strlen("br0")+ 1 );
	if(set_opt1<0)
	{
		printf("Failler set opt interface\n");
	}
	bytes_total=0;
	printf("Arrivo 2\n");
	while(likely(!sigint))
	{
		saddr_size=sizeof saddr;
		data_size=recvfrom(sock_raw,buffer,65536,0,&saddr,&saddr_size);
		if (data_size<0)
		{
			printf("Recv error\n");
			return 1;
		}
		if( send(socket_desc , buffer , data_size, 0) < 0)
		{
			printf("Send failed");
		}
		bytes_total+=data_size;
	}

	close(sock_raw);
	printf("Finished\n %d",bytes_total);
	return 0;
}



