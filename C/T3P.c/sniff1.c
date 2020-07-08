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
#include <pcap.h>

#ifndef likely
# define likely(x)		__builtin_expect(!!(x), 1)
#endif
#ifndef unlikely
# define unlikely(x)		__builtin_expect(!!(x), 0)
#endif

void process_packet(u_char *, const struct pcap_pkthdr *, const u_char *);

int sock_raw;
static sig_atomic_t sigint = 0;

static void sighandler(int num)
{
	sigint = 1;
}

int main()
{
	pcap_if_t *alldevsp , *device;
    	pcap_t *handle;
    	char errbuf[100] , *devname , devs[100][100];
    	int count = 1 , n;   

	int socket_desc,bytes_total;
    	struct sockaddr_in server;
    	char *message;

	socklen_t len;
	int err;
	struct tpacket_stats_v3 stats;
	
	
	unsigned char *buffer=(unsigned char *)malloc(65536);
	signal(SIGINT, sighandler);


	socket_desc = socket(AF_INET , SOCK_STREAM , 0);
	if (socket_desc == -1)
	{
	    printf("Could not create socket");
	}

	server.sin_addr.s_addr = inet_addr("127.0.0.1");
	server.sin_family = AF_INET;
	server.sin_port = htons( 8888 );
	if (connect(socket_desc , (struct sockaddr *)&server , sizeof(server)) < 0)
	{
	        printf("connect error");
	        return 1;
	}
	printf("Connected %d\n",socket_desc);

    	printf("Finding available devices ... ");
    	if( pcap_findalldevs( &alldevsp , errbuf) )
    	{
        	printf("Error finding devices : %s" , errbuf);
        	exit(1);
    	}
    	printf("Done");
     
    	printf("\nAvailable Devices are :\n");
    	for(device = alldevsp ; device != NULL ; device = device->next)
    	{
        	printf("%d. %s - %s\n" , count , device->name , device->description);
        	if(device->name != NULL)
        	{
        	    strcpy(devs[count] , device->name);
        	}
        	count++;
    	}
     
    	printf("Enter the number of the device you want to sniff : ");
    	scanf("%d" , &n);
    	devname = devs[n];

    	printf("Opening device %s for sniffing ... " , devname);
    	handle = pcap_open_live(devname , 65536 , 1 , 0 , errbuf);
     
    	if (handle == NULL) 
    	{
    	    fprintf(stderr, "Couldn't open device %s : %s\n" , devname , errbuf);
    	    exit(1);
    	}
    	printf("Done\n");
	pcap_loop(handle , -1 , process_packet , (u_char*)socket_desc);

	printf("Finished\n %d",bytes_total);
	return 0;
}

void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer)
{
	if( send((int)args , buffer , header->caplen, 0) < 0)
	{
		printf("Send failed");
	}
}
