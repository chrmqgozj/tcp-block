#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <pcap.h>
#include <libnet.h>
#include <netinet/in.h>

void usage() {
	printf("syntax : tcp-block <interface> <pattern>\n");
	printf("sample : tcp-block wlan0 \"Host: test.gilgil.net\"\n");
}

// checksum calculation (ip, tcp)
unsigned short checksum(unsigned short *buffer, int size){
	unsigned long cksum=0;
	while(size >1) {
		cksum+=*buffer++;
		size -=sizeof(unsigned short);    
	}
	if(size) {
		cksum += *(unsigned char*)buffer;
	}
	cksum = (cksum >> 16) + (cksum & 0xffff);
	cksum += (cksum >>16);
	return (unsigned short)(~cksum);
}

// send packet to server (forward)
void send_forward_packet(pcap_t* pcap, struct libnet_ethernet_hdr *eth_hdr, struct libnet_ipv4_hdr *ipv4_hdr, struct libnet_tcp_hdr *tcp_hdr, int data_len) {
	int eth_hl, ipv4_hl, tcp_hl;
	eth_hl = LIBNET_ETH_H;
	ipv4_hl = (ipv4_hdr -> ip_hl) * 4;
	tcp_hl = (tcp_hdr -> th_off) * 4;

	u_char packet[eth_hl + ipv4_hl + tcp_hl];
        memset(packet, 0, sizeof(packet));

	struct libnet_ethernet_hdr* new_eth = (struct libnet_ethernet_hdr*)packet;
	memcpy(new_eth, eth_hdr, eth_hl);

	struct libnet_ipv4_hdr* new_ipv4 = (struct libnet_ipv4_hdr*)(packet + eth_hl);
	memcpy(new_ipv4, ipv4_hdr, ipv4_hl);

	// tcp rst packet
	struct libnet_tcp_hdr* new_tcp = (struct libnet_tcp_hdr*)(packet + eth_hl + ipv4_hl);
	memcpy(new_tcp, tcp_hdr, tcp_hl);
	new_tcp->th_flags = TH_ACK | TH_RST;
	new_tcp->th_seq = htonl(ntohl(tcp_hdr->th_seq) + data_len);
	new_tcp->th_sum = 0;

	// calculate tcp checksum
	u_char pseudo_hdr[12 + tcp_hl];
	memcpy(pseudo_hdr, &new_ipv4->ip_src.s_addr, 4);
	memcpy(pseudo_hdr + 4, &new_ipv4->ip_dst.s_addr, 4);
	pseudo_hdr[8] = 0;
	memcpy(pseudo_hdr + 9, &new_ipv4->ip_p, 1);
	unsigned short tcp_len = htons(tcp_hl);
	memcpy(pseudo_hdr + 10, &tcp_len, 2);
	memcpy(pseudo_hdr + 12, new_tcp, tcp_hl);

	new_tcp->th_sum = checksum((unsigned short*)pseudo_hdr, 12 + tcp_hl);

	pcap_sendpacket(pcap, packet, sizeof(packet));
	return;
}

// send packet to client (backward)
void send_backward_packet(pcap_t* pcap, struct libnet_ethernet_hdr *eth_hdr, struct libnet_ipv4_hdr *ipv4_hdr, struct libnet_tcp_hdr *tcp_hdr, int data_len) {
	const char* warning = "HTTP/1.0 302 Redirect\r\nLocation: http://warning.or.kr\r\n\r\n";
	int payload_len = strlen(warning);

	int ipv4_hl, tcp_hl;
        ipv4_hl = (ipv4_hdr -> ip_hl) * 4;
        tcp_hl = (tcp_hdr -> th_off) * 4;

	// raw socket
	int sd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	if (sd == -1) {
		fprintf(stderr, "socket open error\n");
		return;
	}

	char on = 1;
	setsockopt(sd, IPPROTO_IP, IP_HDRINCL, (char *)&on, sizeof(on));	

	u_char packet[ipv4_hl + tcp_hl + payload_len];
	memset(packet, 0, sizeof(packet));

	// exchange server <-> client
	struct libnet_ipv4_hdr* new_ipv4 = (struct libnet_ipv4_hdr*)packet;
	memcpy(new_ipv4, ipv4_hdr, ipv4_hl);
	new_ipv4->ip_src = ipv4_hdr->ip_dst;
	new_ipv4->ip_dst = ipv4_hdr->ip_src;
	new_ipv4->ip_len = htons(ipv4_hl + tcp_hl + payload_len);
	new_ipv4->ip_sum = 0;
	new_ipv4->ip_sum = checksum((unsigned short*)new_ipv4, ipv4_hl);

	// exchange server <-> client / tcp fin packet
	struct libnet_tcp_hdr* new_tcp = (struct libnet_tcp_hdr*)(packet + ipv4_hl);
	memcpy(new_tcp, tcp_hdr, tcp_hl);
	new_tcp->th_sport = tcp_hdr->th_dport;
	new_tcp->th_dport = tcp_hdr->th_sport;
	new_tcp->th_seq = tcp_hdr->th_ack;
	new_tcp->th_ack = htonl(ntohl(tcp_hdr->th_seq) + data_len); 
	new_tcp->th_flags = TH_ACK | TH_FIN;
	new_tcp->th_sum = 0;

	// add warning payload
	memcpy(packet + ipv4_hl + tcp_hl, warning, payload_len);

	// calculate tcp checksum
	u_char pseudo_hdr[12 + tcp_hl + payload_len];
        memcpy(pseudo_hdr, &new_ipv4->ip_src.s_addr, 4);
        memcpy(pseudo_hdr + 4, &new_ipv4->ip_dst.s_addr, 4);
        pseudo_hdr[8] = 0;
        memcpy(pseudo_hdr + 9, &new_ipv4->ip_p, 1);
        unsigned short tcp_len = htons(tcp_hl + payload_len);
        memcpy(pseudo_hdr + 10, &tcp_len, 2);
        memcpy(pseudo_hdr + 12, new_tcp, tcp_hl);
	memcpy(pseudo_hdr + 12 + tcp_hl, warning, payload_len);

        new_tcp->th_sum = checksum((unsigned short*)pseudo_hdr, 12 + tcp_hl + payload_len);

	// send through socket
	struct sockaddr_in address;
	address.sin_family = AF_INET;
	address.sin_port = 0;
	address.sin_addr.s_addr = new_ipv4->ip_src.s_addr;

	int ret = sendto(sd, packet, sizeof(packet), 0x0, (struct sockaddr *)&address, sizeof(address));
	if (ret < 0) {
		fprintf(stderr, "Failed to send backward packet\n");
	}
	close(sd);
	return;
}

int main(int argc, char* argv[]) {
	if (argc != 3) {
		usage();
		return -1;
	}	

	char* dev = argv[1];
	char* pattern = argv[2];
	char errbuf[PCAP_ERRBUF_SIZE];

	pcap_t* pcap = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

	printf("Searching start...\n");
	struct pcap_pkthdr* header;
	const u_char* packet;

	while (1) {
		int ret = pcap_next_ex(pcap, &header, &packet);

		if (ret == 0) continue;
		if (ret == PCAP_ERROR || ret == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex error: %s\n", pcap_geterr(pcap));
			break;
		}

		int eth_hl = LIBNET_ETH_H;
		int ipv4_hl, tcp_hl;
		struct libnet_ethernet_hdr *eth_header = (struct libnet_ethernet_hdr *)packet;

		struct libnet_ipv4_hdr *ipv4_header = (struct libnet_ipv4_hdr *)(packet + LIBNET_ETH_H);
		ipv4_hl = (ipv4_header -> ip_hl) * 4;
		
		struct libnet_tcp_hdr *tcp_header = (struct libnet_tcp_hdr *)(packet + LIBNET_ETH_H + ipv4_hl);
		tcp_hl = (tcp_header -> th_off) * 4;
		
		const char* data = (const char *)(packet + LIBNET_ETH_H + ipv4_hl + tcp_hl);
		int data_len = ntohs(ipv4_header->ip_len) - ipv4_hl - tcp_hl;
		
		if (data_len > 0) {
			if(strncmp(data, "GET", 3) == 0){
				if(memmem(data, data_len, pattern, strlen(pattern)) != NULL){
					printf("Harmful!\n");
					send_forward_packet(pcap, eth_header, ipv4_header, tcp_header, data_len);
					send_backward_packet(pcap, eth_header, ipv4_header, tcp_header, data_len);
				}
			}
		}
	}

	pcap_close(pcap);
	return 0;
}
