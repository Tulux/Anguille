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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <errno.h>

#include "defines.h"
#include "memory.h"
#include "UTMP.h"

PacketInfo get_info_from_l3_packet(Raw_Packet* packet)
{
    PacketInfo info;
        info.packetSize = packet->size;
        info.protocol = 0;
        info.IPSource = 0;
        info.IPDest = 0;
        info.portSource = 0;
        info.portDest = 0;

    // Minimum IP Header
    if(packet->size <= IP_HEADER_SIZE_MIN)
    {
        // Not an IP packet
        return info;
    }
    else
    {
        uint8_t l3_version = packet->buffer[0];
        l3_version = l3_version >> 4;

        if(l3_version != 4)
        {
            // Not IPv4 packet
            return info;
        }
        else
        {
            uint8_t l3_field_proto = packet->buffer[9];

            if(l3_field_proto == IPPROTO_TCP)        info.protocol = IPPROTO_TCP;
            else if(l3_field_proto == IPPROTO_UDP)   info.protocol = IPPROTO_UDP;

            info.IPSource =  packet->buffer[12];
            info.IPSource = info.IPSource << 8;
            info.IPSource += packet->buffer[13];
            info.IPSource = info.IPSource << 8;
            info.IPSource += packet->buffer[14];
            info.IPSource = info.IPSource << 8;
            info.IPSource += packet->buffer[15];

            info.IPDest =  packet->buffer[16];
            info.IPDest = info.IPDest << 8;
            info.IPDest += packet->buffer[17];
            info.IPDest = info.IPDest << 8;
            info.IPDest += packet->buffer[18];
            info.IPDest = info.IPDest << 8;
            info.IPDest += packet->buffer[19];
        }


        if(info.protocol == IPPROTO_TCP || info.protocol == IPPROTO_UDP)
        {
            int32_t ip_hdr_length;

            ip_hdr_length = get_IP_header_length(packet->buffer);
            info.portSource = get_TCP_src_port_from_TCP_header(packet->buffer + ip_hdr_length);
            info.portDest = get_TCP_dst_port_from_TCP_header(packet->buffer + ip_hdr_length);
        }

    }

    return info;
}

int32_t get_IP_header_length(uint8_t* ip_packet)
{
    uint8_t ip_header_IHL = ip_packet[0];

    ip_header_IHL = ip_header_IHL << 4;
    ip_header_IHL = ip_header_IHL >> 4;

    return ip_header_IHL * 4;
}

int32_t get_TCP_payload_offset(uint8_t* tcp_packet)
{
    return (tcp_packet[12] >> 4) * 4;
}

uint16_t get_TCP_src_port_from_TCP_header(uint8_t* tcp_packet)
{
    return (tcp_packet[0] << 8) + tcp_packet[1];
}

uint16_t get_TCP_dst_port_from_TCP_header(uint8_t* tcp_packet)
{
    return (tcp_packet[2] << 8) + tcp_packet[3];
}

void set_TCP_dst_port(uint8_t* tcp_packet, uint16_t port)
{
    tcp_packet[2] = port >> 8;
    tcp_packet[3] = (uint8_t) port;
}

void set_TCP_src_port(uint8_t* tcp_packet, uint16_t port)
{
    tcp_packet[0] = port >> 8;
    tcp_packet[1] = (uint8_t) port;
}

void print_packetInfo(PacketInfo* pi)
{
    uint8_t ipSource[4];
    uint8_t ipDest[4];

    ipSource[0] = pi->IPSource >> 24;
    ipSource[1] = pi->IPSource >> 16;
    ipSource[2] = pi->IPSource >> 8;
    ipSource[3] = pi->IPSource;

    ipDest[0] = pi->IPDest >> 24;
    ipDest[1] = pi->IPDest >> 16;
    ipDest[2] = pi->IPDest >> 8;
    ipDest[3] = pi->IPDest;

    info("print_packetInfo()");
    printf("Packet (%dB): IP Source: %d.%d.%d.%d - IP Dest: %d.%d.%d.%d - Port source: %d - Port dest: %d\n",
           pi->packetSize, ipSource[0], ipSource[1], ipSource[2], ipSource[3],
           ipDest[0], ipDest[1], ipDest[2], ipDest[3], pi->portSource, pi->portDest);
}

void print_sender(PacketInfo* pi)
{
    uint8_t ipSource[4];

    ipSource[0] = pi->IPSource >> 24;
    ipSource[1] = pi->IPSource >> 16;
    ipSource[2] = pi->IPSource >> 8;
    ipSource[3] = pi->IPSource;

    info("print_sender()");
    printf("%d.%d.%d.%d:%d\n", ipSource[0], ipSource[1], ipSource[2], ipSource[3], pi->portSource);
}

void transfer_from_TCP_to_UDP(Connection* remote_host, Raw_Packet* packet)
{
    uint32_t l4_payload_size;
    uint8_t ip_hdr_length;

    // Récupération de la longueur du payload à envoyer
    ip_hdr_length = get_IP_header_length(packet->buffer);
    l4_payload_size = packet->size - ip_hdr_length;

    // Si la taille du paquet TCP hors en-tête IP est supérieure à 65535 - 8 (taille de l'en-tête UDP),
    // alors le paquet ne peut pas rentrer dans un paquet UDP
    if(l4_payload_size > (UDP_SIZE_MAX - UDP_HEADER_SIZE) )
    {
        // Il faut fragmenter le paquet en 2 paquets UDP..
        if(debug(2))
            warning("transfer_from_TCP_to_UDP(): packet too big, needs to be fragmented but not functionnal yet :(");
    }
    else
    {
        send_UDP_packet(remote_host, packet->buffer+ip_hdr_length, l4_payload_size);
    }
}

void transfer_from_UDP_to_TCP(Connection* app, Raw_Packet* packet, uint16_t port_src, uint16_t port_dst)
{
    int32_t retSend;

    if(port_src != 0 || port_dst != 0)
    {
        int32_t tcp_header_length = get_TCP_payload_offset(packet->buffer);

        if(port_src != 0)   set_TCP_src_port(packet->buffer, port_src);
        if(port_dst != 0)   set_TCP_dst_port(packet->buffer, port_dst);

        set_TCP_checksum(packet->buffer,
                         tcp_header_length,
                         packet->size - tcp_header_length,
                         inet_addr("127.0.0.1"),
                         inet_addr("127.0.0.1"));
    }

    if(debug(4))
    {
        char ip[INET_ADDRSTRLEN] = "";

        inet_ntop(AF_INET, &(app->dest.saddrin.sin_addr), ip, INET_ADDRSTRLEN);
        info("transfer_from_UDP_to_TCP(): sending TCP packet to %s:%u with size of %d", ip, ntohs(app->dest.saddrin.sin_port), packet->size);
    }

    if(debug(5))
        print_hex_dump(packet->buffer, packet->size);

    retSend = sendto(app->sock, packet->buffer, packet->size, 0, (struct sockaddr *) &(app->dest.saddrin), sizeof(app->dest.saddrin));

    if((uint32_t) retSend != packet->size || retSend == -1)
    {
        if(debug(2))
            warning( "transfer_from_UDP_to_TCP(): unable to send final TCP packet to the application! errno : %d, retSend %d",
                    errno,
                    retSend);
    }
}

void send_UDP_packet(Connection* remote_host, uint8_t* payload, uint32_t payload_size)
{
    int32_t retSend;

    // Envoi du paquet UDP
    // Warning, ip & ports used are read from UDP header and not from sockaddr_in descriptor
    pthread_mutex_lock(&remote_host->dest.lock);
    {
        if(debug(4))
        {
            char ip[INET_ADDRSTRLEN] = "";

            inet_ntop(AF_INET, &(remote_host->dest.saddrin.sin_addr), ip, INET_ADDRSTRLEN);

            if(payload_size > 1)
            {
                info("transfer_from_TCP_to_UDP(): sending UDP packet to %s:%u with size of %d", ip, ntohs(remote_host->dest.saddrin.sin_port), payload_size);
            }
            else if(debug(6))
            {
                info("transfer_from_TCP_to_UDP(): sending magic packet to %s:%u", ip, ntohs(remote_host->dest.saddrin.sin_port));
            }
        }

        if(debug(5))
            print_hex_dump(payload, payload_size);

        retSend = sendto(remote_host->sock,
                         payload,
                         payload_size,
                         0,
                         (struct sockaddr *) &(remote_host->dest),
                         sizeof(remote_host->dest));
    }
    pthread_mutex_unlock(&remote_host->dest.lock);

    if((uint32_t) retSend != payload_size || retSend == -1)
    {
        if(debug(2))
            warning("send_UDP_packet(): unable to send UDP packet to the server! errno %d", errno);
    }
}

bool bookTCPPort(int* sock, uint16_t port)
{
    struct sockaddr_in sin_local;
        sin_local.sin_family = AF_INET;
        sin_local.sin_addr.s_addr = inet_addr("127.0.0.1");
        sin_local.sin_port = htons(port);

    if((*sock = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        error("bookTCPPort(): socket(): errno %d", errno);
    }

    if(bind(*sock, (struct sockaddr*) &sin_local, sizeof(sin_local)) != 0)
    {
        error("bookTCPPort(): bind(): errno %d", errno);
    }

    if(debug(1))
        info("bookTCPPort(): TCP/%d has been binded.", port);

    return RETURN_SUCCESS;
}

bool unbookTCPPort(int* sock)
{
    if(sock != 0)
    {
        close(*sock);
    }

    return RETURN_SUCCESS;
}

void iptables_block(uint16_t srv_app_port, uint16_t clt_app_port)
{
    char iptables_rule[IPTABLES_RULE_lENGTH] = "";

    if(srv_app_port != 0)
    {
        sprintf(iptables_rule, "iptables -t raw -A OUTPUT -p tcp -o lo --dport %u --tcp-flags RST RST -j DROP", srv_app_port);
        system(iptables_rule);

        if(debug(1))
        {
            info("iptables_block(): rule «%s» executed", iptables_rule);
        }
    }

    if(clt_app_port != 0)
    {
        sprintf(iptables_rule, "iptables -t raw -A OUTPUT -p tcp -o lo --sport %u --tcp-flags RST RST -j DROP", clt_app_port);
        system(iptables_rule);

        if(debug(1))
        {
            info("iptables_block(): rule «%s» executed", iptables_rule);
        }
    }
}

void iptables_unblock(uint16_t srv_app_port, uint16_t clt_app_port)
{
    char iptables_rule[IPTABLES_RULE_lENGTH] = "";

    if(srv_app_port != 0)
    {
        sprintf(iptables_rule, "iptables -t raw -D OUTPUT -p tcp -o lo --dport %u --tcp-flags RST RST -j DROP", srv_app_port);
        system(iptables_rule);

        if(debug(1))
        {
            info("iptables_block(): rule «%s» executed", iptables_rule);
        }
    }

    if(clt_app_port != 0)
    {
        sprintf(iptables_rule, " iptables -t raw -D OUTPUT -p tcp -o lo --sport %u --tcp-flags RST RST -j DROP", clt_app_port);
        system(iptables_rule);

        if(debug(1))
        {
            info("iptables_block(): rule «%s» executed", iptables_rule);
        }
    }
}

void set_TCP_checksum(uint8_t* tcp_packet, uint32_t tcp_header_length, uint32_t tcp_payload_size, uint32_t ip_src, uint32_t ip_dst)
{
    PseudoHeader tcp_pseudoheader;
    uint8_t tcp_pseudo_packet[TCP_SIZE_MAX] = {0};
    struct tcphdr* tcp_header = (struct tcphdr*) tcp_packet;
    uint8_t* tcp_payload = tcp_packet + tcp_header_length;

    tcp_pseudoheader.source = ip_src;
    tcp_pseudoheader.dest = ip_dst;
    tcp_pseudoheader.mbz = 0;
    tcp_pseudoheader.type = IPPROTO_TCP;
    tcp_pseudoheader.length = htons(tcp_header_length + tcp_payload_size);
    tcp_header->check = 0;

    memcpy(tcp_pseudo_packet, &tcp_pseudoheader, sizeof(PseudoHeader));
    memcpy(tcp_pseudo_packet + sizeof(PseudoHeader), tcp_packet, tcp_header_length);
    memcpy(tcp_pseudo_packet + sizeof(PseudoHeader) + tcp_header_length, tcp_payload, tcp_payload_size);

    tcp_header->check = checksum((uint16_t*) tcp_pseudo_packet, sizeof(PseudoHeader) + tcp_header_length + tcp_payload_size);
}

uint16_t checksum(uint16_t *data, uint32_t data_size)
{
    uint32_t checksum = 0;

    while(data_size > 1)
    {
        checksum = checksum + *data++;
        data_size = data_size - sizeof(uint16_t);
    }
    if(data_size)
        checksum = checksum + *(uint8_t*) data;

    checksum = (checksum >> 16) + (checksum &0xffff);
    checksum = checksum + (checksum >> 16);

    return (uint16_t) (~checksum);
}

void print_tcphdr(uint8_t* tcp_packet)
{
    uint16_t src_p = (tcp_packet[0] << 8) + tcp_packet[1];
    uint16_t dst_p = (tcp_packet[2] << 8) + tcp_packet[3];
    uint32_t seq_n = (tcp_packet[4] << 24) + (tcp_packet[5] << 16) + (tcp_packet[6] << 8) + tcp_packet[7];
    uint32_t ack_n = (tcp_packet[8] << 24) + (tcp_packet[9] << 16) + (tcp_packet[10] << 8) + tcp_packet[11];

    info("print_tcphdr()");
    printf("Src port: %d\n", src_p);
    printf("Dst port: %d\n", dst_p);
    printf("Seq numb: %u\n", seq_n);
    printf("Ack numb: %u\n", ack_n);
}
