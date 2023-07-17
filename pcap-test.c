#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>

#define ETHER_ADDR_LEN 6
#define MIN(a, b) (((a) < (b)) ? (a) : (b))

struct libnet_ethernet_hdr {
    u_int8_t  ether_dhost[ETHER_ADDR_LEN];
    u_int8_t  ether_shost[ETHER_ADDR_LEN];
    u_int16_t ether_type;
};

struct libnet_ipv4_hdr {
	uint32_t ip_src;
	uint32_t ip_dst;
};

struct libnet_tcp_hdr {
    u_int16_t th_sport;
    u_int16_t th_dport;
};

struct my_tcp_payload {
	u_int8_t payload[10];
};

void print_mac(u_int8_t* m) {
	printf("%02x:%02x:%02x:%02x:%02x:%02x\n", m[0], m[1], m[2], m[3], m[4], m[5]);
}

void print_ip(uint32_t i) {
	uint32_t ip = ntohl(i);

	unsigned char a = ip >> 24;
	unsigned char b = ip << 8 >> 24;
	unsigned char c = ip << 16 >> 24;
	unsigned char d = ip << 24 >> 24;

	printf("%d.%d.%d.%d\n", a, b, c, d);
}

void print_tcp(u_int16_t t) {
	unsigned short port = ntohs(t);

	printf("%d\n", port);
}

void print_payload(u_int8_t* p, int payload_length) {
	for (int i = 0; i < payload_length; i++)
		printf("%02x ", p[i]);
	printf("\n");
}

void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}

		if (*(unsigned short*)(packet + 12) == 0x0008) {
			if (*(unsigned char*)(packet + 14 + 9) == 0x06) {

				printf("\n%u bytes captured\n", header->caplen);
				
				struct libnet_ethernet_hdr* eth_hdr = (struct libnet_ethernet_hdr*)packet;
				printf("Src MAC : ");
				print_mac(eth_hdr->ether_shost);
				printf("Dst MAC : ");
				print_mac(eth_hdr->ether_dhost);

				struct libnet_ipv4_hdr* ip_hdr = (struct libnet_ipv4_hdr*)(packet + 14 + 12);
				printf("Scr IP : ");
				print_ip(ip_hdr->ip_src);
				printf("Dst IP : ");
				print_ip(ip_hdr->ip_dst);

				struct libnet_tcp_hdr* tcp_hdr = (struct libnet_tcp_hdr*)(packet + 14 + 20);
				printf("Scr Port : ");
				print_tcp(tcp_hdr->th_sport);
				printf("Dst Port : ");
				print_tcp(tcp_hdr->th_dport);

				unsigned char data_offset = *(unsigned char*)(packet + 14 + 20 + 12) >> 4;
				data_offset = MIN((data_offset - 5) * 4, 10);
				struct my_tcp_payload* tcp_payload = (struct my_tcp_payload*)(packet + 14 + 20 + 20);
				printf("Payload : ");
				print_payload(tcp_payload->payload, data_offset);
		
			}
		}
	}

	pcap_close(pcap);
}
