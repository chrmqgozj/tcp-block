#include <stdio.h>
#include <string.h>
#include <pcap.h>
#include <libnet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

void usage() {
	printf("syntax : tcp-block <interface> <pattern>\n");
	printf("sample : tcp-block wlan0 \"Host: test.gilgil.net\"\n");
}

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
void send_forward_packet(pcap_t* pcap, const u_char* org_packet, struct libnet_ipv4_hdr* iphdr, struct libnet_tcp_hdr* tcphdr, int data_len, uint8_t* my_mac) {
	int ethdr_len, iphdr_len, tcphdr_len, packet_len;
	ethdr_len = LIBNET_ETH_H;
	iphdr_len = (iphdr -> ip_hl) * 4;
	tcphdr_len = (tcphdr -> th_off) * 4;
	packet_len = LIBNET_ETH_H + iphdr_len + tcphdr_len;

	u_char packet[packet_len];
	memset(packet, 0, packet_len);
	memcpy(packet, org_packet, packet_len);

	struct libnet_ethernet_hdr* ethdr = (struct libnet_ethernet_hdr*)packet;
	memcpy(ethdr->ether_shost, my_mac, ETHER_ADDR_LEN);

	struct libnet_ipv4_hdr* new_iphdr = (struct libnet_ipv4_hdr*)(packet + ethdr_len);
	new_iphdr->ip_len = htons(iphdr_len + tcphdr_len);
	new_iphdr->ip_sum = 0;
	new_iphdr->ip_sum = checksum((unsigned short*)new_iphdr, iphdr_len);

	// tcp rst packet
	struct libnet_tcp_hdr* new_tcphdr = (struct libnet_tcp_hdr*)(packet + ethdr_len + iphdr_len);
	new_tcphdr->th_seq = htonl(ntohl(tcphdr->th_seq) + data_len);
	new_tcphdr->th_flags = TH_RST | TH_ACK;
	new_tcphdr->th_sum = 0;

	// calculate tcp checksum using pseudo header
	u_char pseudo_hdr[12 + tcphdr_len];
	memcpy(pseudo_hdr, &new_iphdr->ip_src.s_addr, 4);
	memcpy(pseudo_hdr + 4, &new_iphdr->ip_dst.s_addr, 4);
	pseudo_hdr[8] = 0;
	pseudo_hdr[9] = IPPROTO_TCP;
	unsigned short tcp_len = htons(tcphdr_len);
	memcpy(pseudo_hdr + 10, &tcp_len, 2);
	memcpy(pseudo_hdr + 12, new_tcphdr, tcphdr_len);

	new_tcphdr->th_sum = checksum((unsigned short*)pseudo_hdr, 12 + tcphdr_len);

	if (pcap_sendpacket(pcap, (const u_char*)packet, packet_len)) {
		fprintf(stderr, "pcap_sendpacket error: %s\n", pcap_geterr(pcap));
	}
}

// send packet to client (backward)
void send_backward_packet(struct libnet_ipv4_hdr* iphdr, struct libnet_tcp_hdr* tcphdr, uint32_t data_len) {
	// Fin은 직접 패킷 정보 입력해줘야 무한로딩 안 걸림. 정확한 이유는 모르겠지만 패킷의 어떤 정보가 소켓으로 전송하는 것과 안 맞는듯하다.
	const char* payload = "HTTP/1.0 302 Redirect\r\nLocation: http://warning.or.kr\r\n\r\n";

	int iphdr_len, tcphdr_len, payload_len, packet_len;
	iphdr_len = (iphdr -> ip_hl) * 4;
	tcphdr_len = (tcphdr -> th_off) * 4;
	payload_len = strlen(payload);
	packet_len = iphdr_len + tcphdr_len + payload_len;

	u_char packet[packet_len];
	memset(packet, 0, packet_len);

	// exchange server <-> client
	struct libnet_ipv4_hdr* new_iphdr = (struct libnet_ipv4_hdr*)packet;
	new_iphdr->ip_src = iphdr->ip_dst;
	new_iphdr->ip_dst = iphdr->ip_src;
	new_iphdr->ip_hl = iphdr_len / 4;
	new_iphdr->ip_v = 4;
	new_iphdr->ip_len = htons(packet_len);
	new_iphdr->ip_ttl = 128;
	new_iphdr->ip_p = IPPROTO_TCP;
	new_iphdr->ip_sum = 0;
	new_iphdr->ip_sum = checksum((unsigned short*)new_iphdr, iphdr_len);

	// exchange server <-> client / tcp fin packet
	struct libnet_tcp_hdr* new_tcphdr = (struct libnet_tcp_hdr*)(packet + iphdr_len);
	new_tcphdr->th_sport = tcphdr->th_dport;
	new_tcphdr->th_dport = tcphdr->th_sport;
	new_tcphdr->th_seq = tcphdr->th_ack;
	new_tcphdr->th_ack = htonl(ntohl(tcphdr->th_seq) + data_len);
	new_tcphdr->th_flags = TH_FIN | TH_ACK;
	new_tcphdr->th_off = tcphdr_len / 4;
	new_tcphdr->th_win = htons(60000);
	new_tcphdr->th_sum = 0;

	// add warning payload
	memcpy(packet + iphdr_len + tcphdr_len, payload, payload_len);

	// calculate tcp checksum using pseudo header
	u_char pseudo_hdr[12 + tcphdr_len + payload_len];
	memcpy(pseudo_hdr, &new_iphdr->ip_src.s_addr, 4);
	memcpy(pseudo_hdr + 4, &new_iphdr->ip_dst.s_addr, 4);
	pseudo_hdr[8] = 0;
	pseudo_hdr[9] = IPPROTO_TCP;
	unsigned short tcp_len = htons(tcphdr_len + payload_len);
	memcpy(pseudo_hdr + 10, &tcp_len, 2);
	memcpy(pseudo_hdr + 12, new_tcphdr, tcphdr_len);
	memcpy(pseudo_hdr + 12 + tcphdr_len, payload, payload_len);

	new_tcphdr->th_sum = checksum((unsigned short*)pseudo_hdr, 12 + tcphdr_len + payload_len);

	// send through raw socket
	int sd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
	int on = 1;
	setsockopt(sd, IPPROTO_IP, IP_HDRINCL, (char *)&on, sizeof(on));

	struct sockaddr_in address;
	address.sin_family = AF_INET;
	address.sin_port = new_tcphdr->th_dport;
	address.sin_addr.s_addr = new_iphdr->ip_dst.s_addr;

	if (sendto(sd, packet, packet_len, 0, (struct sockaddr *)&address, sizeof(address)) < 0) {
		fprintf(stderr, "Failed to send backward packet\n");
	}
	close(sd);
}

int main(int argc, char* argv[]) {
	if (argc != 3) {
		usage();
		return 0;
	}

	char* dev = argv[1];
	char* pattern = argv[2];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

	uint8_t mac[6];

	libnet_t* ln = libnet_init(LIBNET_LINK, dev, NULL);
	if (ln == NULL) {
		fprintf(stderr, "libnet_init failed\n");
		libnet_destroy(ln);
		return -1;
	}

	struct libnet_ether_addr* my_mac = libnet_get_hwaddr(ln);
	if (my_mac == NULL) {
		fprintf(stderr, "libnet_get_hwaddr failed\n");
		libnet_destroy(ln);
		return -1;
	}

	memcpy(mac, my_mac->ether_addr_octet, 6);
	libnet_destroy(ln);

	printf("Searching start...\n");
	struct pcap_pkthdr* header;
	const u_char* packet;

	while (1) {
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}

		uint32_t ethdr_len, iphdr_len, tcphdr_len;

		struct libnet_ethernet_hdr* ethdr = (struct libnet_ethernet_hdr*)packet;
		ethdr_len = LIBNET_ETH_H;

		struct libnet_ipv4_hdr* iphdr = (struct libnet_ipv4_hdr*)(packet + ethdr_len);
		iphdr_len = (iphdr->ip_hl) * 4;

		struct libnet_tcp_hdr* tcphdr = (struct libnet_tcp_hdr*)((uint8_t*)iphdr + iphdr_len);
		tcphdr_len = (tcphdr->th_off) * 4;

		const char* data = (const char *)(packet + ethdr_len + iphdr_len + tcphdr_len);
		uint32_t data_len = ntohs(iphdr->ip_len) - iphdr_len - tcphdr_len;

		if (data_len > 0) {
			if (strncmp(data, "GET", 3) == 0) {
				if (memmem(data, data_len, pattern, strlen(pattern)) != NULL) {
					printf("Harmful!\n");
					send_backward_packet(iphdr, tcphdr, data_len);
					send_forward_packet(pcap, packet, iphdr, tcphdr, data_len, mac);
				}
			}
		}
	}

	pcap_close(pcap);
	return 0;
}
