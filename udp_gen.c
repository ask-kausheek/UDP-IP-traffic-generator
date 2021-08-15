#include <unistd.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <libnet.h>
#include<time.h>

    // The packet length

     //#define PCKT_LEN 8192
struct ipheader 
{
    unsigned char      iph_ihl:4, iph_ver:4;
    unsigned char      iph_tos;
    unsigned short int iph_len;
    unsigned short int iph_ident;
    unsigned char      iph_flag;
    unsigned short int iph_offset;
    unsigned char      iph_ttl;
    unsigned char      iph_protocol;
    unsigned short int iph_chksum;
    unsigned int       iph_sourceip;
    unsigned int       iph_destip;
};

     

    // UDP header's structure

struct udpheader 
{
    unsigned short int udph_srcport;
    unsigned short int udph_destport;
    unsigned short int udph_len;
    unsigned short int udph_chksum;
};


struct dnsheader 
{
    unsigned short int query_id;
    unsigned short int flags;
    unsigned short int QDCOUNT;
    unsigned short int ANCOUNT;
    unsigned short int NSCOUNT;
    unsigned short int ARCOUNT;
};
struct dataEnd
{
	unsigned short int  type;
	unsigned short int  class;
};

    unsigned int checksum(uint16_t *usBuff, int isize)
    {
        unsigned int cksum=0;
        for(;isize>1;isize-=2){
        cksum+=*usBuff++;
        }
        if(isize==1){
        cksum+=*(uint16_t *)usBuff;
            }


        return (cksum);
    }
    uint16_t check_udp_sum(uint8_t *buffer, int len)
    {
        unsigned long sum=0;
        struct ipheader *tempI=(struct ipheader *)(buffer);
        struct udpheader *tempH=(struct udpheader *)(buffer+sizeof(struct ipheader));
        struct dnsheader *tempD=(struct dnsheader *)(buffer+sizeof(struct ipheader)+sizeof(struct udpheader));
        tempH->udph_chksum=0;
        sum=checksum( (uint16_t *)   &(tempI->iph_sourceip) ,8 );
        sum+=checksum((uint16_t *) tempH,len);
        sum+=ntohs(IPPROTO_UDP+len);
        sum=(sum>>16)+(sum & 0x0000ffff);
        sum+=(sum>>16);
        return (uint16_t)(~sum);
        
    }
    unsigned short csum(unsigned short *buf, int nwords)
        {       //
                unsigned long sum;
                for(sum=0; nwords>0; nwords--)
                        sum += *buf++;
                sum = (sum >> 16) + (sum &0xffff);
                sum += (sum >> 16);
                return (unsigned short)(~sum);
        }
 char * gen_random(char *s, const int len) {
     static const char alphanum[] =     "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    srand(time(0));
     for (int i = 0; i < len; ++i) {
         
         s[i] = alphanum[rand() % (sizeof(alphanum) - 1)];
     }

     s[len] = 0;
     return s;
 }

int main(int argc, char *argv[])
{
// buffer to hold the packet
int DATA_Rate =atoi(argv[2]);
int PCKT_LEN =atoi(argv[1]);
int k;
k = (PCKT_LEN/DATA_Rate);
// int PCKT_LEN =1000;
    char buffer[PCKT_LEN];

// set the buffer to 0 for all bytes
    memset(buffer, 0, PCKT_LEN);

    // Our own headers' structures

    struct ipheader *ip = (struct ipheader *) buffer;


    struct udpheader *udp = (struct udpheader *) (buffer + sizeof(struct ipheader));


    // struct dnsheader *dns=(struct dnsheader*) (buffer +sizeof(struct ipheader)+sizeof(struct udpheader));

// data is the pointer points to the first byte of the dns payload  
    char *data=(buffer +sizeof(struct ipheader)+sizeof(struct udpheader));
     char dupl[PCKT_LEN];
     char *random_str= gen_random(dupl,PCKT_LEN);
    strcpy(data,random_str);
// iperf, rate and payload size 
// dns->flags=htons(FLAG_Q);
// dns->QDCOUNT=htons(1);

int length= strlen(data)+1;
    struct dataEnd * end=(struct dataEnd *)(data+length);
    end->type=htons(1);
    end->class=htons(1);
    // dns->query_id=rand();
    ip->iph_ihl = 5;

    ip->iph_ver = 4;


    ip->iph_tos = 0; // Low delay


    unsigned short int packetLength =(sizeof(struct ipheader) + sizeof(struct udpheader)+length+sizeof(struct dataEnd)); // length + dataEnd_size == UDP_payload_size

     ip->iph_len=htons(packetLength);

    ip->iph_ident = htons(rand()); // we give a random number for the identification#


    ip->iph_ttl = 110; // hops

    ip->iph_protocol = 17; // UDP

    // Source IP address, can use spoofed address here!!!

    ip->iph_sourceip = inet_addr("127.0.0.1");

    // The destination IP address

    ip->iph_destip = inet_addr("127.0.0.1");

     

    // Fabricate the UDP header. Source port number, redundant

    udp->udph_srcport = htons(40000+rand()%10000);  // source port number, I make them random... remember the lower number may be reserved

    // Destination port number

    udp->udph_destport = htons(53);


    udp->udph_len = htons(sizeof(struct udpheader)+length+sizeof(struct dataEnd)); // udp_header_size + udp_payload_sizem
    // Calculate the checksum for integrity//

    ip->iph_chksum = csum((unsigned short *)buffer, sizeof(struct ipheader) + sizeof(struct udpheader));
 

    udp->udph_chksum=check_udp_sum(buffer, packetLength-sizeof(struct ipheader));
/*******************************************************************************8
Tips

the checksum is quite important to pass the checking integrity. You need 
to study the algorithem and what part should be taken into the calculation.

!!!!!If you change anything related to the calculation of the checksum, you need to re-
calculate it or the packet will be dropped.!!!!!

Here things became easier since I wrote the checksum function for you. You don't need
to spend your time writing the right checksum function.
Just for knowledge purpose,
remember the seconed parameter
for UDP checksum:
ipheader_size + udpheader_size + udpData_size  
for IP checksum: 
ipheader_size + udpheader_size
*********************************************************************************/
	
// This is to generate different query in xxxxx.example.edu
	udp->udph_chksum=check_udp_sum(buffer, packetLength-sizeof(struct ipheader)); // recalculate the checksum for the UDP packet
printf("Packet with headers : ");
	// send the packet out.
    
    for (int bff = 0; bff < packetLength; bff++)
    {        
        printf("%c",buffer[bff]);
        
    }

    printf("\n");
   
    printf("Packet without headers : ");
for (int bff = 0; bff < packetLength-sizeof(struct ipheader)-sizeof(struct udpheader)-sizeof(struct dataEnd); bff++)
    {
        /* code */
        //sleep(3);
        printf(" %c",buffer[bff+sizeof(struct ipheader)+sizeof(struct udpheader)]);
        
    }
   printf("\n");

}




