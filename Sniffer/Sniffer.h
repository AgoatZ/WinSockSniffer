#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <winsock2.h>
#include <stdio.h>
#include <ws2tcpip.h>

#pragma comment(lib, "Ws2_32.lib")

#define SIO_RCVALL _WSAIOW(IOC_VENDOR,1)

#define ICMP 1
#define IGMP 2
#define TCP 6
#define UDP 17

void sniff(SOCKET Sock);
void process_packet(char*, int);
void print_ip_header(char*);
void print_icmp_packet(char*, int);
void print_udp_packet(char*, int);
void print_tcp_packet(char*, int);
void print_data(char*, int);

typedef struct ipv4_header
{
	unsigned char ip_header_size : 4;
	unsigned char ip_version : 4;
	unsigned char ip_service_type;
	unsigned short ip_total_length;
	unsigned short ip_id;
	unsigned char ip_fragment_offset : 5;
	unsigned char ip_more_fragment : 1;
	unsigned char ip_dont_fragment : 1;
	unsigned char ip_reserved_zero : 1;
	unsigned char ip_fragment_offset_head;
	unsigned char ip_time_to_live;
	unsigned char ip_protocol;
	unsigned short ip_checksum;
	unsigned int ip_src_address;
	unsigned int ip_dst_address;

} IPV4_HEADER;

typedef struct udp_header
{
	unsigned short udp_src_port;
	unsigned short udp_dst_port;
	unsigned short udp_length;
	unsigned short udp_checksum;
} UDP_HEADER;

typedef struct tcp_header
{
	unsigned short tcp_src_port;
	unsigned short tcp_dst_port;
	unsigned int tcp_sequence_num;
	unsigned int tcp_ack_num;
	unsigned char tcp_nonce_sum : 1;
	unsigned char tcp_reserved_part1 : 3;
	unsigned char tcp_data_offset : 4;
	unsigned char tcp_fin : 1;
	unsigned char tcp_syn : 1;
	unsigned char tcp_rst : 1;
	unsigned char tcp_psh : 1;
	unsigned char tcp_ack : 1;
	unsigned char tcp_urg : 1;
	unsigned char tcp_ecn : 1;
	unsigned char tcp_cwr : 1;
	unsigned short tcp_window;
	unsigned short tcp_checksum;
	unsigned short tcp_urgent_ptr;
} TCP_HEADER;

typedef struct icmp_header
{
	BYTE icmp_type;
	BYTE icmp_code;
	USHORT icmp_cheacksum;
	USHORT icmp_id;
	USHORT icmp_sequence;
} ICMP_HEADER;