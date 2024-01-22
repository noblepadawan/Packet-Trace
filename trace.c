#include "checksum.h"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define IP 0x0800
#define ARP 0x0806

#define ICMP 1
#define TCP 6
#define UDP 17

void check_args(int argc) 
{
  if (argc != 2) 
  {
    fprintf(stderr, "Usage: ./trace <pcap file>\n");
    exit(1);
  }
}

void process_icmp(const u_char *packet, unsigned char ip_header_len) 
{
  // Print ICMP header
  unsigned char type;
  memcpy(&type, packet + 14 + ip_header_len, 1);

  printf("\n\tICMP Header\n");
  if (ip_header_len > 28) {
    printf("\t\tType: 109\n");
  } else if (type == 0) {
    printf("\t\tType: Reply\n");
  } else if (type == 8) {
    printf("\t\tType: Request\n");
  } else {
    printf("\t\tType: 0x%x\n", type);
  }
}

unsigned short validate_tcp_checksum(const u_char *packet)
{
    unsigned char header_len, reserved = 0;
    unsigned short pdu_len, tcp_len, tcp_network_len;

    // Detemine IP header length
    memcpy(&header_len, packet + 14, 1);
    header_len = (header_len & 0x0F) * 4;

    // Determine IP PDU length
    memcpy(&pdu_len, packet + 16, 2);
    pdu_len = ntohs(pdu_len);

    // Calculate TCP length
    tcp_len = pdu_len - header_len;
    tcp_network_len = htons(tcp_len);

    // Create a TCP pseudo-header for checksum calculation
    unsigned char pseudo_header[12];
    memcpy(pseudo_header, packet + 26, 4); // Source IP
    memcpy(pseudo_header + 4, packet + 30, 4); // Destination IP
    memcpy(pseudo_header + 8, &reserved, 1); // Reserved
    memcpy(pseudo_header + 9, packet + 23, 1); // Protocol (TCP)
    memcpy(pseudo_header + 10, &tcp_network_len, 2); // TCP length

    // Copy TCP header and data to a buffer
    unsigned char *buf = malloc(tcp_len + 12);
    memcpy(buf, pseudo_header, 12);
    memcpy(buf + 12, packet + 14 + header_len, tcp_len);

    // Validate TCP checksum using the pseudo-header
    unsigned short checksum = in_cksum((unsigned short *)buf, tcp_len + 12);

    free(buf);
    return checksum;
}

void process_tcp(const u_char *packet, unsigned char ip_header_len) 
{
  // Print TCP header

  // Create local variables to hold the TCP header fields
  unsigned short src_port;
  unsigned short dest_port;
  unsigned int seq_num;
  unsigned int ack_num;
  unsigned char data_offset_reserved;
  unsigned char flags;
  unsigned short window_size;
  unsigned short checksum;
  unsigned short urgent_pointer;

  // Copy TCP header fields from packet to local variables
  memcpy(&src_port, packet + 14 + ip_header_len, 2);
  memcpy(&dest_port, packet + 14 + ip_header_len + 2, 2);
  memcpy(&seq_num, packet + 14 + ip_header_len + 4, 4);
  memcpy(&ack_num, packet + 14 + ip_header_len + 8, 4);
  memcpy(&data_offset_reserved, packet + 14 + ip_header_len + 12, 1);
  memcpy(&flags, packet + 14 + ip_header_len + 13, 1);
  memcpy(&window_size, packet + 14 + ip_header_len + 14, 2);
  memcpy(&checksum, packet + 14 + ip_header_len + 16, 2);
  memcpy(&urgent_pointer, packet + 14 + ip_header_len + 18, 2);

  // Convert header fields from network byte order (big-endian) to host byte order (little-endian)
  src_port = ntohs(src_port);
  dest_port = ntohs(dest_port);
  seq_num = ntohl(seq_num);
  ack_num = ntohl(ack_num);
  window_size = ntohs(window_size);
  checksum = ntohs(checksum);
  urgent_pointer = ntohs(urgent_pointer);

  // Extract control flags
  unsigned char fin_flag = (flags & 0x01) ? 1 : 0;
  unsigned char syn_flag = (flags & 0x02) ? 1 : 0;
  unsigned char rst_flag = (flags & 0x04) ? 1 : 0;
  unsigned char ack_flag = (flags & 0x10) ? 1 : 0;

  // Verify checksum
  unsigned short tcp_checksum = validate_tcp_checksum(packet);

  // Print TCP header fields
  printf("\n\tTCP Header\n");
  (src_port == 80) ? printf("\t\tSource Port:  HTTP\n") 
      : printf("\t\tSource Port: : %u\n", src_port);
  (dest_port == 80) ? printf("\t\tDest Port:  HTTP\n") 
      : printf("\t\tDest Port: : %u\n", dest_port);
  printf("\t\tSequence Number: %u\n", seq_num);  
  (!ack_flag) ? printf("\t\tACK Number: <not valid>\n") 
      : printf("\t\tACK Number: %u\n", ack_num);
  printf("\t\tACK Flag: %s\n", ack_flag ? "Yes" : "No");
  printf("\t\tSYN Flag: %s\n", syn_flag ? "Yes" : "No");
  printf("\t\tRST Flag: %s\n", rst_flag ? "Yes" : "No");
  printf("\t\tFIN Flag: %s\n", fin_flag ? "Yes" : "No");
  printf("\t\tWindow Size: %u\n", window_size);
  (tcp_checksum == 0) ? printf("\t\tChecksum: Correct (0x%x)\n", checksum)
      : printf("\t\tChecksum: Incorrect (0x%x)\n", checksum);
}

void process_udp(const u_char *packet, unsigned char ip_header_len)
{
  // Print UDP header
  // UDP Header fields: Source Port (2 bytes), Destination Port (2 bytes)

  // Create local variables to hold the UDP header fields
  unsigned short src_port;
  unsigned short dest_port;

  // Copy UDP header fields from packet to local variables
  memcpy(&src_port, packet + 14 + ip_header_len, 2);
  memcpy(&dest_port, packet + 14 + ip_header_len + 2, 2);

  // Convert header fields from network byte order (big-endian) to host byte order (little-endian)
  src_port = ntohs(src_port);
  dest_port = ntohs(dest_port);

  // Print UDP header fields
  printf("\n\tUDP Header\n");
  printf("\t\tSource Port: : %u\n", src_port);
  printf("\t\tDest Port: : %u\n", dest_port);
}

void process_ip(const u_char *packet) 
{
  // Print IP header
  // IP Header Length (4 bits), Type of Service (1 byte), Time to Live (1 byte),
  // Total Length (2 bytes) Protocol (1 byte), Header Checksum (2 bytes), Source
  // IP (4 bytes), Destination IP (4 bytes)

  // Create local variables to hold the IP header fields
  unsigned char version_header_len;
  unsigned char type_of_service;
  unsigned short total_length;
  unsigned char time_to_live;
  unsigned char protocol;
  unsigned short checksum;
  unsigned char source_ip[4];
  unsigned char dest_ip[4];

  // Copy IP header fields from packet to local variables
  memcpy(&version_header_len, packet + 14, 1);
  memcpy(&type_of_service, packet + 15, 1);
  memcpy(&total_length, packet + 16, 2);
  memcpy(&time_to_live, packet + 22, 1);
  memcpy(&protocol, packet + 23, 1);
  memcpy(&checksum, packet + 24, 2);
  memcpy(source_ip, packet + 26, 4);
  memcpy(dest_ip, packet + 30, 4);

  // Determine header length
  unsigned char header_len = (version_header_len & 0x0F) * 4;

  // Verify checksum
  unsigned short ip_checksum = in_cksum((unsigned short *)(packet + 14), header_len);

  // Convert header fields from network byte order (big-endian) to host byte order (little-endian)
  total_length = ntohs(total_length);

  // Print IP header fields
  printf("\n\tIP Header\n");
  printf("\t\tHeader Len: %d (bytes)\n", header_len);
  printf("\t\tTOS: 0x%x\n", type_of_service);
  printf("\t\tTTL: %d\n", time_to_live);

  // Print IP PDU Length
  printf("\t\tIP PDU Len: %d (bytes)\n", total_length);
  if (protocol == ICMP)
    printf("\t\tProtocol: ICMP\n");
  else if (protocol == TCP)
    printf("\t\tProtocol: TCP\n");
  else if (protocol == UDP)
    printf("\t\tProtocol: UDP\n");
  else
    printf("\t\tProtocol: Unknown\n");

  // Print Checksum
  (ip_checksum == 0) ? printf("\t\tChecksum: Correct (0x%x)\n", checksum)
      : printf("\t\tChecksum: Incorrect (0x%x)\n", checksum);

  // Print Source and Destination IP addresses
  printf("\t\tSender IP: %d.%d.%d.%d\n", source_ip[0], source_ip[1],
         source_ip[2], source_ip[3]);
  printf("\t\tDest IP: %d.%d.%d.%d\n", dest_ip[0], dest_ip[1], dest_ip[2],
         dest_ip[3]);

  // Process ICMP, TCP, or UDP
  if (protocol == ICMP) {
    process_icmp(packet, header_len);
  } else if (protocol == TCP) {
    process_tcp(packet, header_len);
  } else if (protocol == UDP) {
    process_udp(packet, header_len);
  }
}

void process_arp(const u_char *packet) 
{
  // Print ARP header
  // ARP Opcode (2 bytes), Sender MAC (6 bytes), Sender IP (4 bytes), Target MAC (6 bytes), Target IP (4 bytes)

  // Create local variables to hold the ARP header fields
  unsigned short opcode;
  unsigned char sender_mac[6];
  unsigned char sender_ip[4];
  unsigned char target_mac[6];
  unsigned char target_ip[4];

  // Copy ARP header fields from packet to local variables
  memcpy(&opcode, packet + 20, 2);
  memcpy(sender_mac, packet + 22, 6);
  memcpy(sender_ip, packet + 28, 4);
  memcpy(target_mac, packet + 32, 6);
  memcpy(target_ip, packet + 38, 4);

  // Convert opcode from network byte order (big-endian) to host byte order (little-endian)
  opcode = ntohs(opcode);

  // Print ARP header fields
  printf("\n\tARP header\n");
  if (opcode == 1) {
    printf("\t\tOpcode: Request\n");
  } else if (opcode == 2) {
    printf("\t\tOpcode: Reply\n");
  } else {
    printf("\t\tOpcode: 0x%x\n", opcode);
  }
  printf("\t\tSender MAC: %x:%x:%x:%x:%x:%x\n", sender_mac[0], sender_mac[1],
         sender_mac[2], sender_mac[3], sender_mac[4], sender_mac[5]);
  printf("\t\tSender IP: %d.%d.%d.%d\n", sender_ip[0], sender_ip[1],
         sender_ip[2], sender_ip[3]);
  printf("\t\tTarget MAC: %x:%x:%x:%x:%x:%x\n", target_mac[0], target_mac[1],
         target_mac[2], target_mac[3], target_mac[4], target_mac[5]);
  printf("\t\tTarget IP: %d.%d.%d.%d\n", target_ip[0], target_ip[1],
         target_ip[2], target_ip[3]);
  printf("\n");
}

void process_ethernet(const u_char *packet) 
{
  // Print Ethernet header
  // Ethernet header fields: Destination MAC (6 bytes), Source MAC (6 bytes), EtherType (2 bytes)

  // Create local variables to hold the Ethernet header fields
  unsigned char dest_mac[6];
  unsigned char src_mac[6];
  unsigned short type;

  // Copy MAC addresses and EthernetType from packet to local variables
  memcpy(dest_mac, packet, 6);
  memcpy(src_mac, packet + 6, 6);
  memcpy(&type, packet + 12, 2);

  // Convert type from network byte order (big-endian) to host byte order (little-endian)
  type = ntohs(type);

  // Print Ethernet header fields
  printf("\n\tEthernet Header\n");
  printf("\t\tDest MAC: %x:%x:%x:%x:%x:%x\n", dest_mac[0], dest_mac[1],
         dest_mac[2], dest_mac[3], dest_mac[4], dest_mac[5]);
  printf("\t\tSource MAC: %x:%x:%x:%x:%x:%x\n", src_mac[0], src_mac[1],
         src_mac[2], src_mac[3], src_mac[4], src_mac[5]);

  if (type == IP) {
    printf("\t\tType: IP\n");
    process_ip(packet);
  } else if (type == ARP) {
    printf("\t\tType: ARP\n");
    process_arp(packet);
  } else {
    printf("\t\tType: 0x%x\n", type);
  }
}

int main(int argc, char *argv[]) 
{
  check_args(argc);

  // Open the pcap file
  pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];
  handle = pcap_open_offline(argv[1], errbuf);
  if (handle == NULL) 
  {
    fprintf(stderr, "Error opening pcap file %s: %s\n", argv[1], errbuf);
    exit(1);
  }

  // Loop through the packets in the pcap file
  struct pcap_pkthdr *header;
  const u_char *packet;

  int packet_num = 1;

  while (pcap_next_ex(handle, &header, (const u_char **)&packet) == 1) 
  {

    printf("\nPacket number: %d  Frame Len: %d\n", packet_num++, header->len);

    process_ethernet(packet);
  }

  // Close the pcap file
  pcap_close(handle);

  return 0;
}
