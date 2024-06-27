#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

// Define Ethernet, IP, and TCP header sizes
#define SIZE_ETHERNET 14

// SMB2 packet structure
struct smb2_packet {
    uint16_t credit_charge;
    uint16_t channel_sequence;
    uint16_t reserved;
    uint16_t command;
    uint32_t message_id;
    uint32_t reserved2;
    uint32_t tree_id;
    uint64_t session_id;
    uint64_t signature[2];
};

// Function to parse and display packet details
void parse_smb(const u_char *packet, struct pcap_pkthdr packet_header) {
    const u_char *ip_header = packet + SIZE_ETHERNET;
    // Calculate IP header size dynamically
    int ip_header_size = ((struct ip*)ip_header)->ip_hl * 4;
    const u_char *tcp_header = ip_header + ip_header_size;
    // Calculate TCP header size dynamically
    int tcp_header_size = ((struct tcphdr*)tcp_header)->th_off * 4;
    const u_char *smb_header = tcp_header + tcp_header_size;

    struct ip *ip = (struct ip*)(ip_header);
    struct tcphdr *tcp = (struct tcphdr*)(tcp_header);

    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];

    inet_ntop(AF_INET, &(ip->ip_src), src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip->ip_dst), dst_ip, INET_ADDRSTRLEN);

    printf("Source IP: %s\n", src_ip);
    printf("Destination IP: %s\n", dst_ip);
    printf("Source Port: %d\n", ntohs(tcp->th_sport));
    printf("Destination Port: %d\n", ntohs(tcp->th_dport));

    struct smb2_packet *smb2 = (struct smb2_packet *)(smb_header);

    uint16_t command = ntohs(smb2->command);
    printf("SMB2 Command: 0x%x\n", command);

    // Handling SMB2 commands for Read and Write
    if (command == 0x0009) { // SMB2 READ
        printf("SMB2 Read Request\n");
        // Extract Read Request Metadata
    } else if (command == 0x0008) { // SMB2 WRITE
        printf("SMB2 Write Request\n");
        // Extract Write Request Metadata
    }
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <pcap file>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    char *filename = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_offline(filename, errbuf);

    if (handle == NULL) {
        fprintf(stderr, "Could not open file %s: %s\n", filename, errbuf);
        return 2;
    }

    struct pcap_pkthdr header;
    const u_char *packet;

    while ((packet = pcap_next(handle, &header)) != NULL) {
        parse_smb(packet, header);
    }

    pcap_close(handle);
    return 0;
}
