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

#ifndef UTMP_H
#define UTMP_H

#include <stdint.h>

typedef enum
{
    SRV_PORT_START,
    SRV_PORT_END,
    CLT_IP,
    SRV_LISN_PORT,
    CLT_LISN_PORT
} UTMP_field_type;

typedef enum
{
    OPEN,
    CLOSE,
    BROKEN
} Tunnel_state;

/*********************************Functions***********************************/

uint8_t get_UTMP_version(uint8_t* utmp_msg);
uint8_t get_UTMP_type(uint8_t* utmp_msg);
int parse_UTMP_fields(int utmp_type, UTMP_field_type field_type, uint8_t* utmp_msg, void* result);
void dump_UTMP_packet(uint8_t* buff, int size);

uint16_t get_random_srv_port(Entity* ent);
uint16_t get_random_clt_port(Entity* ent);
int valid_listening_ports(Entity* ent, uint16_t new_srv_port, uint16_t new_clt_port);

int recv_UTMP_msg(int sock, uint8_t* buff_rcv, int buff_rcv_size);
int send_UTMP_msg(int sock, uint8_t* buff_snd, int buff_snd_size);
void make_UTMP_auth(uint8_t** buff, int* buff_size, Entity* ent);
void make_UTMP_chgPort(uint8_t** buff, int* buff_size, uint16_t srv_port, uint16_t clt_port);
void make_UTMP_authOK(uint8_t** buff, int* buff_size, Entity* ent);
void make_UTMP_authNOK(uint8_t** buff, int* buff_size);
void make_UTMP_chgPortOK(uint8_t** buff, int* buff_size);
void make_UTMP_chgPortNOK(uint8_t** buff, int* buff_size);
void make_UTMP_newTun(uint8_t** buff, int* buff_size, uint16_t srv_port, uint16_t clt_port);
void make_UTMP_newTunOK(uint8_t** buff, int* buff_size);
void make_UTMP_newTunNOK(uint8_t** buff, int* buff_size);
void make_UTMP_closeTun(uint8_t** buff, int* buff_size);
void make_UTMP_closeTunACK(uint8_t** buff, int* buff_size);
void make_UTMP_unknown(uint8_t** buff, int* buff_size);

#endif
