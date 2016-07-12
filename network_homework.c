#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<pcap/pcap.h>
#include<errno.h>
#include<sys/socket.h>
#include<netinet/in.h>
#include<arpa/inet.h>
#include<net/ethernet.h>
#include<netinet/ip.h>
#include<netinet/tcp.h>
#include<signal.h>
#include<unistd.h>
#include<sys/time.h>

#define NONPROMISCUOUS 0
#define PROMISCUOUS 1 

//save mac_address
typedef struct mac_address{
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
	u_char byte5;
	u_char byte6;
}macaddress;

struct ip *iph; 
struct tcphdr *tcph;

void callback(u_char *useless, const struct pcap_pkthdr *pkthdr, const u_char *packet) 
{
	static int count = 1;
	struct ether_header *ep;
	unsigned short ether_type;
	int chcnt =0;
	int length=pkthdr->len;
	
	//MAC address save space 
	macaddress* Sourcemac;
	macaddress* Destinationmac;
	
	//Packet start ether_header!
	ep =(struct ether_header *)packet;
	
	//Struct Ethernet header
	//DestinationAddress * SourceAddress *  Packet
	// 6 byte               6byte           2byte
	//^^packet
	Destinationmac=(macaddress*)packet;
	//			^^packet+6
	Sourcemac=(macaddress*)(packet+6);


	packet += sizeof(struct ether_header);
	 	
	iph = (struct ip*)packet;
	// or iph = (struct ip*)(packet+16)
	ether_type = ntohs(ep->ether_type);
	// ntohs -> Network to host short	
	if(ether_type == ETHERTYPE_IP)
	{
	if(iph->ip_p == IPPROTO_TCP){
	//struct ip header
	// version  * IHL(Header Length) * TOS * Total_length
	// ^^ packet
	//32bitword = 32/8 = 4byte
	//ip_hl = 5 ~15 byte
	//ip_hl * 4byte = ip_header_length
	//packet point = tcp source port
	tcph=(struct tcp*)(packet + iph->ip_hl*4);
	
	
	//print Mac Address
	printf("##############################################\n");
	printf("**Mac Address Session\n");
	printf("Source MAC Address: %02x.%02x.%02x.%02x.%02x.%02x\n",
	Sourcemac->byte1,
	Sourcemac->byte2,
	Sourcemac->byte3,
	Sourcemac->byte4,
	Sourcemac->byte5,
	Sourcemac->byte6
	);
	printf("Destinationmac MAC Address: %02x.%02x.%02x.%02x.%02x.%02x\n",
	Destinationmac->byte1,
	Destinationmac->byte2,
	Destinationmac->byte3,
	Destinationmac->byte4,
	Destinationmac->byte5,
	Destinationmac->byte6
	);

	//print IP Address
	printf("**IP Address Session\n");
	// inet_ntoa = Big-Endian 32bit -> Dotted-Decimal Notation
	printf("Source IP Address : %s\n", inet_ntoa(iph->ip_src));
	printf("Destination IP Address : %s\n", inet_ntoa(iph->ip_dst));
	
	//print TCP port
	printf("**TCP Port Session\n");
	printf("Source Tcp port : %d\n", ntohs(tcph->th_sport));
	printf("Destination IP port : %d\n", ntohs(tcph->th_dport));
	printf("##############################################");
	printf("\n\n\n");
	}
	}

}
int main(int argc, char **argv){
	char *dev;
	char *net;
	char *mask;

	bpf_u_int32 netp;
	bpf_u_int32 maskp;
	char errbuf[PCAP_ERRBUF_SIZE];
	int ret;
	
//	bpf_u_int32 netp;
//	bpf_u_int32 maskp;	
	struct pcap_pkthdr hdr;
	struct in_addr net_addr, mask_addr;
	struct ether_header *eptr;
	const u_char *packet;
	struct bpf_program fp;
	
	pcap_t *pcd; // packet capture descriptor
	
	dev = pcap_lookupdev(errbuf);
	
	pcd = pcap_open_live(dev, BUFSIZ, NONPROMISCUOUS, -1, errbuf);
	if(pcd==NULL){
	printf("%s\n", errbuf);
	exit(1);
	}
	
	if (pcap_compile(pcd, &fp, argv[2], 0, netp) ==1){
	pcap_perror(pcd, "pcap_compile failure");
	exit(1);
	}
	
	if(pcap_setfilter(pcd, &fp)==-1){
	printf("setfilter error\n");
	exit(0);
	}

	pcap_loop(pcd, atoi(argv[1]), callback, NULL);
}


