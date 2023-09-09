#include "Sniffer.h"

FILE* snifflog = NULL;
int tcp = 0, udp = 0, icmp = 0, others = 0, igmp = 0, total_packets = 0, i, j;
struct sockaddr_in source, destination;
char hexadecimal[2];

IPV4_HEADER* ipv4header;
TCP_HEADER* tcpheader;
UDP_HEADER* udpheader;
ICMP_HEADER* icmpheader;

int main()
{
    SOCKET sniffingsocket;
    struct in_addr address;
    int in;
    char hostname[101];
    HOSTENT* localhost;
    WSADATA winsockapidata;
    int fileerror;
    LINGER zero;

    fileerror = fopen_s(&snifflog, "snifflog.txt", "w+");
    if (snifflog == NULL)
    {
        printf("\nError making log file.\n");
    }

    printf("\nInitializing Winsock...\n");
    if (WSAStartup(MAKEWORD(2, 2), &winsockapidata) != 0)
    {
        printf("WSAStartup function failed.\nExiting now.\n");
        return 1;
    }
    printf("Initialised\n");

    printf("Opening raw socket now...\n");
    sniffingsocket = socket(AF_INET, SOCK_RAW, IPPROTO_IP);
    if (sniffingsocket == INVALID_SOCKET)
    {
        printf("Failed opening raw socket, closing now...\n");
        return 1;
    }
    printf("Raw socket opened successfully.\n");

    if (gethostname(hostname, sizeof(hostname)) == SOCKET_ERROR)
    {
        printf("Error from Winsockapi : %d\n", WSAGetLastError());
        return 1;
    }
    printf("Host name is : %s\n", hostname);

    localhost = gethostbyname(hostname);
    if (localhost == NULL)
    {
        printf("Error from Winsockapi : %d.\n", WSAGetLastError());
        return 1;
    }
    printf("Available network interfaces : \n");
    for (i = 0; localhost->h_addr_list[i] != 0; ++i)
    {
        memcpy(&address, localhost->h_addr_list[i], sizeof(struct in_addr));
        printf("Interface number : %d Address : %s\n", i, inet_ntoa(address));
    }

    printf("Enter interface number to sniff : \n");
    scanf_s("%d", &in);

    memset(&destination, 0, sizeof(destination));
    memcpy(&destination.sin_addr.s_addr, localhost->h_addr_list[in], sizeof(destination.sin_addr.s_addr));
    destination.sin_family = AF_INET;
    destination.sin_port = 0;

    printf("Binding socket to local system and port 0 ...\n");
    if (bind(sniffingsocket, (struct sockaddr*)&destination, sizeof(destination)) == SOCKET_ERROR)
    {
        printf("Bind(%s) failed.\n", inet_ntoa(address));
        return 1;
    }
    printf("Binding done successfully\n");

    j = 1;
    printf("Setting socket to sniff...\n");
    if (WSAIoctl(sniffingsocket, SIO_RCVALL, &j, sizeof(j), 0, 0, (LPDWORD)&in, 0, 0) == SOCKET_ERROR)
    {
        printf("WSAIoctl function failed.\n");
        return 1;
    }
    printf("Socket is set.\n");

    printf("Started Sniffing...\n");
    printf("Packet Capture Statistics : \n");

    /*set linger so RST flag will be sent on shutdown*/
    zero.l_linger = 0;
    zero.l_onoff = 1;
    setsockopt(sniffingsocket, SOL_SOCKET, SO_LINGER, (char*) & zero, sizeof(zero));
    sniff(sniffingsocket);

    closesocket(sniffingsocket);
    WSACleanup();

    return 0;
}

void sniff(SOCKET sniffingsocket)
{
    char* buffer = (char*)malloc(65536);
    int mangobyte;

    if(buffer == NULL)
    {
        printf("Memory allocation failed.\n");
    }

    /*start receiving packets from the socket connected to the interface*/
    do
    {
        mangobyte = recvfrom(sniffingsocket, buffer, 65536, 0, 0, 0);
        if (mangobyte > 0)
        {
            process_packet(buffer, mangobyte);
            /*send RST flag while kipping the rawsocket alive*/
            shutdown(sniffingsocket, SD_SEND);
        }
        else
        {
            printf("recvfrom function failed.\n");
        }
    } while (mangobyte > 0);

    free(buffer);
}

void process_packet(char* buffer, int size)
{
    ipv4header = (IPV4_HEADER*)buffer;
    ++total_packets;
    switch (ipv4header->ip_protocol)
    {
        case ICMP:
            icmp++;
            print_icmp_packet(buffer, size);
            break;
        case IGMP:
            igmp++;
            break;
        case UDP:
            udp++;
            print_udp_packet(buffer, size);
            break;
        case TCP:
            tcp++;
            print_tcp_packet(buffer, size);
            break;
        default:
            others++;
            print_tcp_packet(buffer, size);
            break;
    }
    printf("TCP : %d UDP : %d ICMP : %d IGMP : %d Others : %d Total : %d\r", tcp, udp, icmp, igmp, others, total_packets);
}

void print_ip_header(char* buffer)
{
    unsigned short ip_header_length;
    
    ipv4header = (IPV4_HEADER*)buffer;
    ip_header_length = ipv4header->ip_header_size * 4;

    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = ipv4header->ip_src_address;

    memset(&destination, 0, sizeof(destination));
    destination.sin_addr.s_addr = ipv4header->ip_dst_address;

    fprintf(snifflog, "\n");
    fprintf(snifflog, "IP Header\n");
    fprintf(snifflog, " |-- IP Version : %d\n", (unsigned int)ipv4header->ip_version);
    fprintf(snifflog, " |-- IP Header Length : %d DWORDS or %d Bytes\n", (unsigned int)ipv4header->ip_header_size, ((unsigned int)(ipv4header->ip_header_size)) * 4);
    fprintf(snifflog, " |-- Type Of Service : %d\n", (unsigned int)ipv4header->ip_service_type);
    fprintf(snifflog, " |-- IP Total Length : %d Bytes(Size of Packet)\n", ntohs(ipv4header->ip_total_length));
    fprintf(snifflog, " |-- Identification : %d\n", ntohs(ipv4header->ip_id));
    fprintf(snifflog, " |-- Reserved ZERO Field : %d\n", (unsigned int)ipv4header->ip_reserved_zero);
    fprintf(snifflog, " |-- Dont Fragment Field : %d\n", (unsigned int)ipv4header->ip_dont_fragment);
    fprintf(snifflog, " |-- More Fragment Field : %d\n", (unsigned int)ipv4header->ip_more_fragment);
    fprintf(snifflog, " |-- TTL : %d\n", (unsigned int)ipv4header->ip_time_to_live);
    fprintf(snifflog, " |-- Protocol : %d\n", (unsigned int)ipv4header->ip_protocol);
    fprintf(snifflog, " |-- Checksum : %d\n", ntohs(ipv4header->ip_checksum));
    fprintf(snifflog, " |-- Source IP : %s\n", inet_ntoa(source.sin_addr));
    fprintf(snifflog, " |-- Destination IP : %s\n", inet_ntoa(destination.sin_addr));
    fflush(snifflog);
}

void print_icmp_packet(char* buffer, int size)
{
    unsigned short ip_header_length;

    ipv4header = (IPV4_HEADER*)buffer;
    ip_header_length = ipv4header->ip_header_size * 4;
    icmpheader = (ICMP_HEADER*)(buffer + ip_header_length);

    fprintf(snifflog, "\n\n***********************ICMP Packet*************************\n");
    print_ip_header(buffer);

    fprintf(snifflog, "\n");
    fprintf(snifflog, "ICMP Header\n");
    fprintf(snifflog, " |-- Type : %d", (unsigned int)(icmpheader->icmp_type));

    if ((unsigned int)(icmpheader->icmp_type) == 11)
    {
        fprintf(snifflog, " (TTL Expired)\n");
    }
    else if ((unsigned int)(icmpheader->icmp_type) == 0)
    {
        fprintf(snifflog, " (ICMP Echo Reply)\n");
    }

    fprintf(snifflog, " |-- Code : %d\n", (unsigned int)(icmpheader->icmp_code));
    fprintf(snifflog, " |-- Checksum : %d\n", ntohs(icmpheader->icmp_cheacksum));
    fprintf(snifflog, " |-- ID : %d\n", ntohs(icmpheader->icmp_id));
    fprintf(snifflog, " |-- Sequence : %d\n", ntohs(icmpheader->icmp_sequence));
    fprintf(snifflog, "\n");

    fprintf(snifflog, "IP Header\n");
    print_data(buffer, ip_header_length);

    fprintf(snifflog, "UDP Header\n");
    print_data(buffer + ip_header_length, sizeof(ICMP_HEADER));

    fprintf(snifflog, "Data Payload\n");
    print_data(buffer + ip_header_length + sizeof(ICMP_HEADER), (size - sizeof(ICMP_HEADER) - ipv4header->ip_header_size * 4));

    fprintf(snifflog, "\n###########################################################");
    fflush(snifflog);
}

void print_udp_packet(char* buffer, int size)
{
    unsigned short ip_header_length;

    ipv4header = (IPV4_HEADER*)buffer;
    ip_header_length = ipv4header->ip_header_size * 4;
    udpheader = (UDP_HEADER*)(buffer + ip_header_length);

    fprintf(snifflog, "\n\n***********************UDP Packet*************************\n");

    print_ip_header(buffer);

    fprintf(snifflog, "\nUDP Header\n");
    fprintf(snifflog, " |-- Source Port : %d\n", ntohs(udpheader->udp_src_port));
    fprintf(snifflog, " |-- Destination Port : %d\n", ntohs(udpheader->udp_dst_port));
    fprintf(snifflog, " |-- UDP Length : %d\n", ntohs(udpheader->udp_length));
    fprintf(snifflog, " |-- UDP Checksum : %d\n", ntohs(udpheader->udp_checksum));

    fprintf(snifflog, "\n");
    fprintf(snifflog, "IP Header\n");

    print_data(buffer, ip_header_length);

    fprintf(snifflog, "UDP Header\n");

    print_data(buffer + ip_header_length, sizeof(UDP_HEADER));

    fprintf(snifflog, "Data Payload\n");

    print_data(buffer + ip_header_length + sizeof(UDP_HEADER), (size - sizeof(UDP_HEADER) - ipv4header->ip_header_size * 4));

    fprintf(snifflog, "\n###########################################################");
    fflush(snifflog);
}

void print_tcp_packet(char* buffer, int size)
{
    unsigned short ip_header_length;

    ipv4header = (IPV4_HEADER*)buffer;
    ip_header_length = ipv4header->ip_header_size * 4;
    tcpheader = (TCP_HEADER*)(buffer + ip_header_length);

    fprintf(snifflog, "\n\n***********************TCP Packet*************************\n");
    print_ip_header(buffer);

    fprintf(snifflog, "\n");
    fprintf(snifflog, "TCP Header\n");
    fprintf(snifflog, " |-- Source Port : %u\n", ntohs(tcpheader->tcp_src_port));
    fprintf(snifflog, " |-- Destination Port : %u\n", ntohs(tcpheader->tcp_dst_port));
    fprintf(snifflog, " |-- Sequence Number : %u\n", ntohl(tcpheader->tcp_sequence_num));
    fprintf(snifflog, " |-- Acknowledge Number : %u\n", ntohl(tcpheader->tcp_ack_num));
    fprintf(snifflog, " |-- Header Length : %d DWORDS or %d BYTES\n"
        , (unsigned int)tcpheader->tcp_data_offset, (unsigned int)tcpheader->tcp_data_offset * 4);
    fprintf(snifflog, " |-- CWR Flag : %d\n", (unsigned int)tcpheader->tcp_cwr);
    fprintf(snifflog, " |-- ECN Flag : %d\n", (unsigned int)tcpheader->tcp_ecn);
    fprintf(snifflog, " |-- Urgent Flag : %d\n", (unsigned int)tcpheader->tcp_urg);
    fprintf(snifflog, " |-- Acknowledgement Flag : %d\n", (unsigned int)tcpheader->tcp_ack);
    fprintf(snifflog, " |-- Push Flag : %d\n", (unsigned int)tcpheader->tcp_psh);
    fprintf(snifflog, " |-- Reset Flag : %d\n", (unsigned int)tcpheader->tcp_rst);
    fprintf(snifflog, " |-- Synchronise Flag : %d\n", (unsigned int)tcpheader->tcp_syn);
    fprintf(snifflog, " |-- Finish Flag : %d\n", (unsigned int)tcpheader->tcp_fin);
    fprintf(snifflog, " |-- Window : %d\n", ntohs(tcpheader->tcp_window));
    fprintf(snifflog, " |-- Checksum : %d\n", ntohs(tcpheader->tcp_checksum));
    fprintf(snifflog, " |-- Urgent Pointer : %d\n", tcpheader->tcp_urgent_ptr);
    fprintf(snifflog, "\n");
    fprintf(snifflog, " DATA Dump ");
    fprintf(snifflog, "\n");

    fprintf(snifflog, "IP Header\n");
    print_data(buffer, ip_header_length);

    fprintf(snifflog, "TCP Header\n");
    print_data(buffer + ip_header_length, tcpheader->tcp_data_offset * 4);

    fprintf(snifflog, "Data Payload\n");
    print_data(buffer + ip_header_length + tcpheader->tcp_data_offset * 4
        , (size - tcpheader->tcp_data_offset * 4 - ipv4header->ip_header_size * 4));

    fprintf(snifflog, "\n###########################################################");
    fflush(snifflog);
}

void print_data(char* data, int size)
{
    char add, line[17], chr;
    int j;

    for (i = 0; i < size; i++)
    {
        chr = data[i];
        fprintf(snifflog, " %.2x", (unsigned char)chr); /*Print Hexadecimal*/
        add = (chr > 31 && chr < 129) ? (unsigned char)chr : '.'; /*Add char to line*/
        line[i % 16] = add;
        if (i != 0 && (i + 1) % 16 == 0 || i == size - 1)
        {
            line[i % 16 + 1] = '\0';
            fprintf(snifflog, "          ");

            for (j = strlen(line); j < 16; j++)
            {
                fprintf(snifflog, "   ");
            }
            fprintf(snifflog, "%s \n", line);
        }
    }
    fprintf(snifflog, "\n");
    fflush(snifflog);
}