#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <string.h>
#include <arpa/inet.h>

#define MAX_PCAP_FILE_LEN 256

void process_packet(const u_char *packet, int packet_length) {
    struct ip *ip_header = (struct ip *)(packet + 14); // Skip Ethernet header (14 bytes)

    // Check if the packet is TCP
    if (ip_header->ip_p == IPPROTO_TCP) {
        struct tcphdr *tcp_header = (struct tcphdr *)(packet + 14 + (ip_header->ip_hl << 2)); // Skip IP header

        // Check if the packet contains specific details based on questions
        const char *packet_data = (const char *)(packet + 14 + (ip_header->ip_hl << 2) + (tcp_header->th_off << 2)); // Skip TCP header

        // Question 1: My username is secret. Identify my secret.
        if (strstr(packet_data, "username=secret") != NULL) {
            printf("Connection Secret: %s\n", strstr(packet_data, "username=secret"));
        }

        // Question 2: I have a TCP checksum “0xf436”. I have instructions in my path.
        if (ntohs(tcp_header->th_sum) == 0xf436) {
            printf("TCP Checksum: 0x%x\n", ntohs(tcp_header->th_sum));
            printf("Path Instructions: %s\n", packet_data); // Assuming path instructions are present in the packet data
        }

        // Question 3: My device has an IP Address “123.134.156.178”. Sum of my connection ports will lead you to a person.
        char source_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(ip_header->ip_src), source_ip, INET_ADDRSTRLEN);
        if (strcmp(source_ip, "123.134.156.178") == 0) {
            int source_port = ntohs(tcp_header->th_sport);
            int dest_port = ntohs(tcp_header->th_dport);
            printf("Source IP: %s\n", source_ip);
            printf("Source Port: %d\n", source_port);
            printf("Destination Port: %d\n", dest_port);
            int sum_of_ports = source_port + dest_port;
            printf("Sum of Ports: %d\n", sum_of_ports);
        }

        // Question 4: I come from localhost, I requested a milkshake. Find my flavour.
        if (ntohl(ip_header->ip_src.s_addr) == 0x7F000001 && strstr(packet_data, "milkshake") != NULL) {
            const char *flavour_start = strstr(packet_data, "milkshake") + strlen("milkshake");
            const char *flavour_end = strchr(flavour_start, '\n');
            if (flavour_end != NULL) {
                int flavour_length = flavour_end - flavour_start;
                char flavour[flavour_length + 1];
                strncpy(flavour, flavour_start, flavour_length);
                flavour[flavour_length] = '\0';
                printf("Requested Milkshake Flavour: %s\n", flavour);
            }
        }
    }
}

int main(int argc, char *argv[]) {
    char pcap_filename[MAX_PCAP_FILE_LEN];

    if (argc != 2) {
        printf("Usage: %s <pcap_file>\n", argv[0]);
        return 1;
    }

    // Open the pcap file
    snprintf(pcap_filename, MAX_PCAP_FILE_LEN, "%s", argv[1]);
    pcap_t *handle = pcap_open_offline(pcap_filename, NULL);
    if (handle == NULL) {
        fprintf(stderr, "Error opening pcap file %s\n", pcap_filename);
        return 1;
    }

    // Loop through the packets in the pcap file
    struct pcap_pkthdr header;
    const u_char *packet;

    while ((packet = pcap_next(handle, &header))) {
        process_packet(packet, header.len);
    }

    pcap_close(handle);
    return 0;
}
