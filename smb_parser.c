#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/stat.h>
#include <json-c/json.h>

// Ethernet header size
#define SIZE_ETHERNET 14
// IP header size
#define SIZE_IP 20
// TCP header size
#define SIZE_TCP 20

// Structure to represent an SMB2 packet
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

// Function to create a directory if it doesn't exist
void create_directory(const char *dir_name) {
    struct stat st = {0};
    if (stat(dir_name, &st) == -1) {
        mkdir(dir_name, 0700);
    }
}

// Function to write metadata to a JSON file
void write_metadata_to_json(const char *metadata_filename, json_object *metadata) {
    FILE *file = fopen(metadata_filename, "w");
    if (file != NULL) {
        fprintf(file, "%s", json_object_to_json_string_ext(metadata, JSON_C_TO_STRING_PRETTY));
        fclose(file);
    }
}

// Function to parse SMB packets and extract metadata
void parse_smb(const u_char *packet, struct pcap_pkthdr packet_header, json_object *metadata_array) {
    // Extract IP, TCP, and SMB headers from the packet
    const u_char *ip_header = packet + SIZE_ETHERNET;
    const u_char *tcp_header = ip_header + SIZE_IP;
    const u_char *smb_header = tcp_header + SIZE_TCP;

    struct ip *ip = (struct ip*)(ip_header);
    struct tcphdr *tcp = (struct tcphdr*)(tcp_header);

    // Convert source and destination IP addresses to strings
    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip->ip_src), src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip->ip_dst), dst_ip, INET_ADDRSTRLEN);

    // Extract SMB2 command from the SMB header
    struct smb2_packet *smb2 = (struct smb2_packet *)(smb_header);
    uint16_t command = ntohs(smb2->command);

    // Create JSON object for metadata
    json_object *metadata = json_object_new_object();
    json_object_object_add(metadata, "Source IP", json_object_new_string(src_ip));
    json_object_object_add(metadata, "Destination IP", json_object_new_string(dst_ip));
    json_object_object_add(metadata, "Source Port", json_object_new_int(ntohs(tcp->th_sport)));
    json_object_object_add(metadata, "Destination Port", json_object_new_int(ntohs(tcp->th_dport)));
    json_object_object_add(metadata, "SMB2 Command", json_object_new_int(command));
    json_object_array_add(metadata_array, metadata);

    // Print command type for debugging purposes
    if (command == 0x0009) { // SMB2 READ
        printf("SMB2 Read Request\n");
        // Extract Read Request Metadata (if any additional extraction needed)
    } else if (command == 0x0008) { // SMB2 WRITE
        printf("SMB2 Write Request\n");
        // Extract Write Request Metadata (if any additional extraction needed)
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

    // Create directory for extracted files
    create_directory("extracted_files");

    // Create a JSON object to store metadata
    json_object *metadata_array = json_object_new_array();

    struct pcap_pkthdr header;
    const u_char *packet;

    // Process each packet in the pcap file
    while ((packet = pcap_next(handle, &header)) != NULL) {
        parse_smb(packet, header, metadata_array);
    }

    pcap_close(handle);

    // Write metadata to JSON file
    write_metadata_to_json("extracted_files/metadata.json", metadata_array);

    // Free JSON object
    json_object_put(metadata_array);

    return 0;
}
