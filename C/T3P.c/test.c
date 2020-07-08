#include <pcap.h> 
#include <string.h> 
#include <stdlib.h> 
#include <net/if.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <netinet/tcp.h>
#include <sys/socket.h>

#define MAXBYTES2CAPTURE 65536 





void processPacket(u_char *arg, const struct pcap_pkthdr* pkthdr, const u_char * packet){ 

 int i=0, *counter = (int *)arg; 
 int socket_desc;
 struct sockaddr_in server;
 
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
         printf("Connect error");
	 return;
     }
 /*else
 {
 	printf("Connected\n");
 }+/
 /*printf("Packet Count: %d\n", ++(*counter));*/ 
 /*printf("Received Packet Size: %d\n", pkthdr->len);*/ 
 /*printf("Payload:\n"); */
 if( send(socket_desc , packet , (int)pkthdr->len , 0) < 0)
 {
 	printf("Send failed");
 }
 /*else 
 {
 printf("Send OK\n");
 }*/
 return; 
} 




int main(int argc, char *argv[] ){ 
    
 int i=0, count=0; 
 pcap_t *descr = NULL; 
 char errbuf[PCAP_ERRBUF_SIZE], *device=NULL; 
 memset(errbuf,0,PCAP_ERRBUF_SIZE); 

 if( argc > 1){  /* If user supplied interface name, use it. */
    device = argv[1];
 }
 else{  /* Get the name of the first device suitable for capture */ 

    if ( (device = pcap_lookupdev(errbuf)) == NULL){
        fprintf(stderr, "ERROR: %s\n", errbuf);
        exit(1);
    }
 }


 printf("Opening device %s\n", device); 
 
 if ( (descr = pcap_open_live(device, MAXBYTES2CAPTURE, 1,  512, errbuf)) == NULL){
    fprintf(stderr, "ERROR: %s\n", errbuf);
    exit(1);
 }
 if ( pcap_loop(descr, -1, processPacket, (u_char *)&count) == -1){
    fprintf(stderr, "ERROR: %s\n", pcap_geterr(descr) );
    exit(1);
 }

return 0; 

} 


