#include <pcap.h>
#include <stdio.h>
#include <stdint.h>
#define ETHER_ADDR_LEN 6
#define IP_ADDR_LEN 4
#define TCP_ADDR_LEN 2
#define ETHER_SIZE 14
#define IP_PROTOCOL 8
#define TCP_PROTOCOL 6
struct ethernet_h{
  u_char ether_dest[ETHER_ADDR_LEN];
  u_char ether_src[ETHER_ADDR_LEN];
  u_short ether_type;
};
struct ip_h{
  u_char ihl:4;
  u_char ip_version:4;
  u_char service;
  u_char total_len[2];
  u_short ident;
  u_short ip_off;
  u_char ttl;
  u_char ip_protocol;
  u_short checksum;
  u_char ip_src[IP_ADDR_LEN];
  u_char ip_dest[IP_ADDR_LEN];
};
struct tcp_h{
  u_char src_port[TCP_ADDR_LEN];
  u_char dest_port[TCP_ADDR_LEN];
  u_int seq;
  u_int ack;
  u_char res:4;
  u_char tcp_offset:4;
};

void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

void print_line(){
  printf("----------------------------------------------\n");
}

void print_MAC(struct pcap_pkthdr* header, const u_char* packet){
	const struct ethernet_h* ethernet;
	ethernet = (struct ethernet_h*)(packet);
	print_line();
	printf("dest mac: %02x:%02x:%02x:%02x:%02x:%02x\n",ethernet->ether_dest[0],ethernet->ether_dest[1],ethernet->ether_dest[2],ethernet->ether_dest[3],ethernet->ether_dest[4],ethernet->ether_dest[5]);
	printf("src mac: %02x:%02x:%02x:%02x:%02x:%02x\n",ethernet->ether_src[0],ethernet->ether_src[1],ethernet->ether_src[2],ethernet->ether_src[3],ethernet->ether_src[4],ethernet->ether_src[5]);
}


void print_IP(struct pcap_pkthdr* header, const u_char* packet){
	const struct ip_h* ip;
	ip = (struct ip_h*)(packet + ETHER_SIZE);
	print_line();
        printf("src IP:%u.%u.%u.%u\n",ip->ip_src[0],ip->ip_src[1],ip->ip_src[2],ip->ip_src[3]);
	printf("dest IP:%u.%u.%u.%u\n",ip->ip_dest[0],ip->ip_dest[1],ip->ip_dest[2],ip->ip_dest[3]);
}

int main(int argc, char* argv[]) {
  const struct ethernet_h* ethernet;
  const struct ip_h* ip;
  const struct tcp_h* tcp;
  if (argc != 2) {
    usage();
    return -1;
  }

  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  while (true) {

    struct pcap_pkthdr* header;
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);
    int i;
    u_int ip_size =0;
    u_int tcp_size =0;
    u_int src_port =0;
    u_int dest_port =0;
    u_int data_size=0;
    u_int total_len=0;
    u_char* data_addr=0;
    ethernet = (struct ethernet_h*)(packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;
    printf("\n%u bytes captured\n", header->caplen);
    print_MAC(header,packet);
    if(ethernet->ether_type != IP_PROTOCOL){
	    print_line();
	    printf("is not IP protocol\n");
    }else{
	    ip = (struct ip_h*)(packet + ETHER_SIZE);
	    ip_size = ip->ihl*4;
	    print_IP(header,packet);

	    if(ip->ip_protocol != TCP_PROTOCOL){
		    print_line();
		    printf("is not TCP protocol\n");
	    }else{
		    tcp = (struct tcp_h*)(packet + ETHER_SIZE + ip_size);
		    tcp_size = tcp->tcp_offset *4;
		    src_port = tcp->src_port[0]*256 + tcp->src_port[1];
		    dest_port = tcp->dest_port[0]*256 + tcp->dest_port[1];
		    total_len = ip->total_len[0]*256+ip->total_len[1];
		    data_size = total_len - ip_size - tcp_size;

		    print_line();
		    printf("src port:%d \ndest port:%d \n",src_port,dest_port);

		    if(data_size !=0){
			    data_addr = (u_char*)(packet+ETHER_SIZE+ip_size+tcp_size);
			    if(data_size>15){data_size=15;}
			    print_line();
			    for(i=0;i<data_size;i++){
				    printf("%02x ",*(data_addr+i));
			    }
			    printf("\n");
		    }
	    }
    }
   } 
  pcap_close(handle);
  return 0;
}
