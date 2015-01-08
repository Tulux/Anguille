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
#include <string.h>
#include <pthread.h>

#include "entity.h"

void init_entity(Entity* ent)
{
    ent->type = UNKNOWN;

    ent->server_ip = 0;
    ent->server_listening_port = 0;
    memset(ent->server_listening_port_range, 0, 2);
    ent->server_local_target_port = 0;
    ent->server_manager_port = 0;
    memset(ent->server_password, 0, SERVER_PASSWORD_MAX_LENGTH + 1);

    ent->client_ip = 0;
    ent->client_listening_port = 0;
    memset(ent->client_listening_port_range, 0, 2);
    ent->client_app_dst_port = 0;

    pthread_mutex_init(&ent->lock, NULL);
}

void copyEnt(Entity* src, Entity* dest)
{
    pthread_mutex_lock(&dest->lock);
    pthread_mutex_lock(&src->lock);
    {
        dest->type = src->type;

        dest->server_ip = src->server_ip;
        dest->server_listening_port = src->server_listening_port;
        dest->server_listening_port_range[0] = src->server_listening_port_range[0];
        dest->server_listening_port_range[1] = src->server_listening_port_range[1];
        dest->server_local_target_port = src->server_local_target_port;
        dest->server_manager_port = src->server_manager_port;
        memcpy(dest->server_password, src->server_password, SERVER_PASSWORD_MAX_LENGTH+1);

        dest->client_ip = src->client_ip;
        dest->client_listening_port = src->client_listening_port;
        dest->client_listening_port_range[0] = src->client_listening_port_range[0];
        dest->client_listening_port_range[1] = src->client_listening_port_range[1];
        dest->client_app_dst_port = src->client_app_dst_port;
    }
    pthread_mutex_unlock(&src->lock);
    pthread_mutex_unlock(&dest->lock);
}
