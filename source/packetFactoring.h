/*

Anguille - client/server program establishing dynamic UDP tunnel to carry TCP traffic

Copyright (C) 2015 Florent DELAHAYE <delahaye.florent@gmail.com>

This file is part of Anguille.

Anguille is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Anguille is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Anguille.  If not, see <http://www.gnu.org/licenses/>.

*/

#ifndef PACKETANALYZE_H
#define PACKETANALYZE_H

#include <pthread.h>
#include <arpa/inet.h>
#include <stdbool.h>

/*********************************Structures**********************************/

typedef struct
{
    uint8_t* buffer;
    ssize_t size;
} Raw_Packet;

typedef struct
{
    int32_t packetSize;
    int32_t protocol;
    int32_t IPSource;
    int32_t IPDest;
    uint16_t portSource;
    uint16_t portDest;
} PacketInfo;

typedef struct
{
    uint32_t source;
    uint32_t dest;
    uint8_t mbz;
    uint8_t type;
    uint16_t length;
} PseudoHeader;

typedef struct
{
    struct sockaddr_in saddrin;
    pthread_mutex_t lock;
} Sin;

typedef struct
{
    int sock;
    Sin dest;
} Connection;

/*********************************Enumerations********************************/

typedef enum
{
    PACKET_TCP,
    PACKET_UTMP,
    PACKET_UNKNOWN
} Packet_type;

/*********************************Functions***********************************/

PacketInfo get_info_from_l3_packet(Raw_Packet* l3_packet);
int32_t get_IP_header_length(uint8_t* ip_packet);
int32_t get_TCP_payload_offset(uint8_t* tcp_packet);
uint16_t get_TCP_src_port_from_TCP_header(uint8_t* tcp_packet);
uint16_t get_TCP_dst_port_from_TCP_header(uint8_t* tcp_packet);

void set_TCP_dst_port(uint8_t* tcp_packet, uint16_t port);
void set_TCP_src_port(uint8_t* tcp_packet, uint16_t port);

void print_packetInfo(PacketInfo* pi);
void print_sender(PacketInfo* pi);
void print_tcphdr(uint8_t* tcp_packet);

void transfer_from_TCP_to_UDP(Connection* remote_host, Raw_Packet* packet);
void transfer_from_UDP_to_TCP(Connection* app, Raw_Packet* packet, uint16_t port_src, uint16_t port_dst);
void send_UDP_packet(Connection* remote_host, uint8_t* payload, uint32_t payload_size);
bool bookTCPPort(int* sock, uint16_t port);
bool unbookTCPPort(int* sock);
void iptables_block(uint16_t srv_app_port, uint16_t clt_app_port);
void iptables_unblock(uint16_t srv_app_port, uint16_t clt_app_port);
void set_TCP_checksum(uint8_t* tcp_packet, uint32_t tcp_header_length, uint32_t tcp_payload_size, uint32_t ip_src, uint32_t ip_dst);
uint16_t checksum(uint16_t *data, uint32_t data_size);

#endif
