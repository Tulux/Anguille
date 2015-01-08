#ifndef MEM_H
#define MEM_H

#include "entity.h"
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

#include "packetFactoring.h"

typedef struct
{
    bool opt_verbose;
    bool opt_tunnelttl;
    bool opt_portrange;
    bool opt_localport;
    bool opt_password;
    bool opt_managerport;
    bool opt_serverip;
    bool opt_servermode;

    uint8_t verbose_level;
    uint32_t tunnel_ttl;
    uint16_t port_start;
    uint16_t port_end;
    uint16_t port_manager;
    uint16_t port_local;
    char* password;
    char* serverip;
} Args;

/*********************************Functions***********************************/

void error(const char* str, ...);
void warning(const char* str, ...);
void info(const char* str, ...);
bool debug(unsigned int level);

void* s_malloc(size_t size);
void set_rcv_buffer(int* sock);
void print_hex_dump(void* mem, uint32_t len);
Connection* new_connection(void);
Sin* new_sin(void);
void init_connection(Connection* c);
void init_sin(Sin* s);
void copySin(Sin* src, Sin* dst);
void print_usage(void);
bool u8cmp(uint8_t* a, uint8_t* b);
void sig_handler(int sign);

void init_args(Args* args);
void print_args(const Args* args);
void arg_error(const char* arg);
void check_arg_verbose(Args* args, char* str);
void check_arg_tunnelttl(Args* args, char* str);
void check_arg_portrange(Args* args, char* str);
void check_arg_localport(Args* args, char* str);
void check_arg_password(Args* args, char* str);
void check_arg_managerport(Args* args, char* str);
void check_arg_serverip(Args* args, char* str);

#endif
