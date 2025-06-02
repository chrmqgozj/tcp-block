#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <pcap.h>
#include <libnet.h>


void usage() {
	printf("syntax : tcp-block <interface> <pattern>\n");
	printf("sample : tcp-block wlan0 \"Host: test.gilgil.net\"\n");
}

void send_forward_packet(pcap_t* pcap, struct libnet_ethernet_hdr *eth_hdr, struct libnet_ipv4_hdr *ipv4_hdr, struct libnet_tcp_hdr *tcp_hdr) {
	u_char* packet[LIBNET_ETH_H + LIBNET_IPV4_H + LIBNET_TCP_H];
	memset(packet, 0, sizeof(packet));
	
	struct libnet_ethernet_hdr* new_eth = (struct libnet_ethernet_hdr*)packet;
	memcpy(new_eth, eth_hdr, LIBNET_ETH_H);

	struct libnet_ipv4_hdr* new_ipv4 = (struct libnet_ipv4_hdr*)(packet + LIBNET_ETH_H);
	memcpy(new_ipv4, ipv4_hdr, LIBNET_IPV4_H);
	
	struct libnet_tcp_hdr* new_tcp = (struct libnet_tcp_hdr*)(packet + LIBNET_ETH_H + LIBNET_IPV4_H);
	memcpy(new_tcp, tcp_hdr, LIBNET_TCP_H);
	new_tcp->th_flags = TH_ACK | TH_RST;

	pcap_sendpacket(pcap, packet, sizeof(packet));
	return;
}

void send_backward_packet(pcap_t* pcap, struct libnet_ethernet_hdr *eth_hdr, struct libnet_ipv4_hdr *ipv4_hdr, struct libnet_tcp_hdr *tcp_hdr) {
	const char* warning = "HTTP/1.0 302 Redirect\r\nLocation: http://warning.or.kr\r\n\r\n";

	u_char* packet[LIBNET_ETH_H + LIBNET_IPV4_H + LIBNET_TCP_H + strlen(warning)];
        memset(packet, 0, sizeof(packet));

	struct libnet_ethernet_hdr* new_eth = (struct libnet_ethernet_hdr*)packet;
        memcpy(new_eth, eth_hdr, LIBNET_ETH_H);
	new_eth->ether_dhost = eth_hdr->ether_shost;
	
        struct libnet_ipv4_hdr* new_ipv4 = (struct libnet_ipv4_hdr*)(packet + LIBNET_ETH_H);
        memcpy(new_ipv4, ipv4_hdr, LIBNET_IPV4_H);
	new_ipv4->ip_dst = ipv4_hdr->ip_src;

        struct libnet_tcp_hdr* new_tcp = (struct libnet_tcp_hdr*)(packet + LIBNET_ETH_H + LIBNET_IPV4_H);
        memcpy(new_tcp, tcp_hdr, LIBNET_TCP_H);
	new_tcp->th_dport = new_tcp->th_sport;
        new_tcp->th_flags = TH_ACK | TH_FIN;

	memcpy(packet + LIBNET_ETH_H + LIBNET_IPV4_H + LIBNET_TCP_H, warning, strlen(warning));

        pcap_sendpacket(pcap, packet, sizeof(packet));
        return;
}

int main(int argc, char* argv[]) {
	if (argc < 3) {
		usage();
		return -1;
	}	

	char* dev = argv[1];
	char* pattern = argv[2];
	char errbuf[PCAP_ERRBUF_SIZE];

	printf("%d\n", strlen(pattern));

	printf("%s\n", pattern);

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
		
		struct libnet_ethernet_hdr *eth_header = (struct libnet_ethernet_hdr *)packet;
		struct libnet_ipv4_hdr *ipv4_header = (struct libnet_ipv4_hdr *)(packet + sizeof(*eth_header));
		struct libnet_tcp_hdr *tcp_header = (struct libnet_tcp_hdr *)(packet + sizeof(*eth_header) + sizeof(*ipv4_header));
		const char* data = (const char *)(packet + sizeof(*eth_header) + sizeof(*ipv4_header) + sizeof(*tcp_header));
		int data_len = ipv4_header->ip_len - sizeof(ipv4_header) - sizeof(tcp_header);
		if (data_len > 0) {
			if(strncmp(data, "GET", 3) == 0){
				if(memmem(data, data_len, pattern, strlen(pattern)) != NULL){
					printf("Harmful!\n");
					send_forward_packet(pcap, eth_header, ipv4_header, tcp_header);
				}
			}
		}
			
		
		
	}

	pcap_close(pcap);
	return 0;
}
