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

#ifndef ENTITY_H
#define ENTITY_H

#include <stdint.h>
#include <pthread.h>

#include "defines.h"

typedef enum
{
    UNKNOWN,
    SERVER,
    CLIENT
} Entity_type;

typedef struct
{
    Entity_type type;

    uint32_t server_ip;
    uint16_t server_listening_port;
    uint16_t server_listening_port_range[2];
    uint16_t server_local_target_port;
    uint16_t server_manager_port;
    uint8_t  server_password[SERVER_PASSWORD_MAX_LENGTH+1];

    uint32_t client_ip;
    uint16_t client_listening_port;
    uint16_t client_listening_port_range[2];
    uint16_t client_app_dst_port;
    uint32_t client_tunnel_ttl;

    pthread_mutex_t lock;
} Entity;

void init_entity(Entity* ent);
void copyEnt(Entity* src, Entity* dest);

#endif
