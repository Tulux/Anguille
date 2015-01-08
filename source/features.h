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

#ifndef FEATURES_H
#define FEATURES_H

#include "entity.h"
#include "packetFactoring.h"
#include "UTMP.h"

/*********************************Structures**********************************/

typedef struct
{
    Entity* ent;
    bool stop;
    int remoteSock;
    Sin* remoteSin;
} Param_th_tunnel;

typedef struct
{
    Entity* ent;

    void* remote2local_retvalue;
    void* local2remote_retvalue;

    Param_th_tunnel p_remote2local;
    Param_th_tunnel p_local2remote;

    pthread_t th_remote2local;
    pthread_t th_local2remote;

    int local_tcp_sock;

} Param_manager;

/*********************************Functions***********************************/

void init_manager(Param_manager* p, Entity* ent);
void init_param_tunnel(Param_th_tunnel* p, Entity* ent);
void* th_wrapper(void* param);
void* th_unwrapper(void* param);
bool wrap_tcp_to_udp(Entity* ent, int remoteSock, Sin* remoteSin, bool* stop);
bool unwrap_tcp_from_udp(Entity* ent, int remoteSock, Sin* remoteSin, bool* stop);
bool set_timeout_socket(int sock, int time_sec, int time_usec);
bool set_linger_socket(int sock, int time_sec);
void update_sin(Sin* remoteSin, struct sockaddr_in* last_saddrin);
bool tunnel_start(Param_manager* p);
void tunnel_stop(Param_manager* p);
Tunnel_state get_tunnel_state(Param_manager* p);

void client(Entity* clt);
bool client_manager(Param_manager* param);

void server(Entity* srv);
bool server_manager(Param_manager* param);

#endif
