#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netdb.h>

#define BUFFER_SIZE 65536

// Structure to represent a 4-tuple
struct FlowKey
{
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
};

int main()
{
    int sockfd;
    char buffer[BUFFER_SIZE];

    // Create a raw socket
    sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sockfd == -1)
    {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    // Create a hash table to store 4-tuple counts
    struct FlowKey flow_keys[BUFFER_SIZE]; // Assuming a reasonable number of flows
    int flow_counts[BUFFER_SIZE] = {0};
    int num_flows = 0;

    // Store IP addresses for reverse DNS lookup
    char observed_ips[5][INET_ADDRSTRLEN] = {"192.168.1.1", "192.168.1.2", "192.168.1.3", "192.168.1.4", "192.168.1.5"};

    while (1)
    {
        ssize_t packet_size = recv(sockfd, buffer, BUFFER_SIZE, 0);
        if (packet_size == -1)
        {
            perror("recv");
            close(sockfd);
            exit(EXIT_FAILURE);
        }

        // Parse and process the packet
        struct ip *ip_header = (struct ip *)buffer;
        struct tcphdr *tcp_header = (struct tcphdr *)(buffer + (ip_header->ip_hl << 2));

        // Extract 4-tuple
        struct FlowKey flow_key;
        flow_key.src_ip = ip_header->ip_src.s_addr;
        flow_key.dst_ip = ip_header->ip_dst.s_addr;
        flow_key.src_port = ntohs(tcp_header->th_sport);
        flow_key.dst_port = ntohs(tcp_header->th_dport);

        // Check if this 4-tuple is already in the hash table
        int i, found = -1;
        for (i = 0; i < num_flows; i++)
        {
            if (memcmp(&flow_key, &flow_keys[i], sizeof(struct FlowKey)) == 0)
            {
                found = i;
                break;
            }
        }

        // If not found, add it to the hash table
        if (found == -1)
        {
            if (num_flows < BUFFER_SIZE)
            {
                memcpy(&flow_keys[num_flows], &flow_key, sizeof(struct FlowKey));
                found = num_flows;
                num_flows++;
            }
            else
            {
                fprintf(stderr, "Too many flows to track.\n");
                continue;
            }
        }

        // Increment the flow count
        flow_counts[found]++;

        // Display packet information
        printf("Source IP: %s\n", inet_ntoa(ip_header->ip_src));
        printf("Destination IP: %s\n", inet_ntoa(ip_header->ip_dst));
        printf("Source Port: %d\n", ntohs(tcp_header->th_sport));
        printf("Destination Port: %d\n", ntohs(tcp_header->th_dport));

        // Output the flow count
        printf("Flow Count: %d\n", flow_counts[found]);

        // You can add more packet processing logic here

        printf("\n");
    }
    close(sockfd);
    return 0;
}
