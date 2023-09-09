# Winsock Simple Packet Tracer with RST

## Description

This is a simple packet tracer, written in c for windows environment.
It utilizes the WinSock2 technology, and uses rawsocket as the sniffer.
By default, it will also try to send a RST flagged packet,
in order to perform some tiny DOS on the local machine.

## Getting Started

### Building and Running

1. Build project
2. Run as administrator
3. Select network interface to sniff
4. Find log in "snifflog.txt"

### Run Example
 ```
 Initializing Winsock...
Initialised
Opening raw socket now...
Raw socket opened successfully.
Host name is : HOSTNAME-YOURS
Available network interfaces :
Interface number : 0 Address : 192.123.456.1
Interface number : 1 Address : 192.123.45.1
Interface number : 2 Address : 192.123.1.234
Enter interface number to sniff :
2
Binding socket to local system and port 0 ...
Binding done successfully
Setting socket to sniff...
Socket is set.
Started Sniffing...
Packet Capture Statistics :
 CP : 33 UDP : 5 ICMP : 0 IGMP : 0 Others : 0 Total : 38
 ```
 ### Log Example
 ```
 ***********************TCP Packet*************************

IP Header
 |-- IP Version : 4
 |-- IP Header Length : 5 DWORDS or 20 Bytes
 |-- Type Of Service : 0
 |-- IP Total Length : 78 Bytes(Size of Packet)
 |-- Identification : 60701
 |-- Reserved ZERO Field : 0
 |-- Dont Fragment Field : 1
 |-- More Fragment Field : 0
 |-- TTL : 118
 |-- Protocol : 6
 |-- Checksum : 12909
 |-- Source IP : 12.345.67.89
 |-- Destination IP : 192.123.1.234

TCP Header
 |-- Source Port : 443
 |-- Destination Port : 54324
 |-- Sequence Number : 2996998059
 |-- Acknowledge Number : 2870636504
 |-- Header Length : 5 DWORDS or 20 BYTES
 |-- CWR Flag : 0
 |-- ECN Flag : 0
 |-- Urgent Flag : 0
 |-- Acknowledgement Flag : 1
 |-- Push Flag : 1
 |-- Reset Flag : 0
 |-- Synchronise Flag : 0
 |-- Finish Flag : 0
 |-- Window : 16384
 |-- Checksum : 15098
 |-- Urgent Pointer : 0

 DATA Dump 
IP Header
 01 bb 38 38 38 38 38 38 38 38 38 38 38 38 38 00          ...1......a.A.@. 
 3a fa 00 00                                              .... 

TCP Header
 01 bb 38 38 38 38 38 38 38 38 38 38 38 38 38 00          ...1......a.A.@. 
 3a fa 00 00                                              :... 

Data Payload
 38 38 03 38 21 00 00 00 00 00 00 00 38 38 38 1e          ....!........... 
 38 38 38 38 38 38 38 38 38 38 38 38 38 38 38 38          A.A:a.A .,....)A 
 f6 d0 d7 38 38 38                                        .....R 


###########################################################

***********************UDP Packet*************************

IP Header
 |-- IP Version : 4
 |-- IP Header Length : 5 DWORDS or 20 Bytes
 |-- Type Of Service : 0
 |-- IP Total Length : 122 Bytes(Size of Packet)
 |-- Identification : 50221
 |-- Reserved ZERO Field : 0
 |-- Dont Fragment Field : 1
 |-- More Fragment Field : 0
 |-- TTL : 255
 |-- Protocol : 17
 |-- Checksum : 5273
 |-- Source IP : 192.123.1.234
 |-- Destination IP : 12.345.67.89

UDP Header
 |-- Source Port : 5353
 |-- Destination Port : 5353
 |-- UDP Length : 102
 |-- UDP Checksum : 7039

IP Header
 38 00 00 7a 38 38 38 00 38 38 38 38 38 38 38 38          E..z.-@......... 
 e0 00 00 fb                                              .... 

UDP Header
 14 38 14 38 00 38 1b 38                                  .....f. 

Data Payload
 14 1b 00 00 00 02 00 00 00 00 00 00 2a 5f 25 39          ............*_%8 
 45 38 38 38 38 38 38 38 38 38 38 39 35 32 36 43          E7E7C8A87887778A 
 39 38 38 38 39 38 38 38 38 38 38 34 46 36 46 30          7EAA78A88887A7A7 
 42 38 38 43 35 45 44 04 38 38 75 62 0b 5f 67 6f          E77C7EE._snob._n 
 38 38 38 38 38 38 73 38 38 5f 74 63 70 05 6c 6f          obleover._tcp.lo 
 63 61 6c 00 00 0c 00 01 c0 3c 00 0c 00 01                cal......<.... 


###########################################################
 ```