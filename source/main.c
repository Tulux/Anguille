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
#include <getopt.h>
#include <arpa/inet.h>
#include <signal.h>

#include "entity.h"
#include "features.h"
#include "memory.h"

bool glb_signal_stop = false;
unsigned int glb_debug_level = 0;

int main(int argc, char *argv[])
{
    int option;

    Entity ent;
    Args args;

    init_entity(&ent);
    init_args(&args);

    /* On active les signaux */
    if(signal(SIGINT, sig_handler) == SIG_ERR)
        error("main(): signal(): Unable to catch SIGINT");

    /* Optional args */
    while ((option = getopt(argc, argv,"hv:d:r:t:p:m:i:s")) != -1)
    {
        switch(option)
        {
            case 'h':
                print_usage();
                exit(0);
            break;

            case 'v':
                check_arg_verbose(&args, optarg);
            break;

            case 'd':
                check_arg_tunnelttl(&args, optarg);
            break;

            case 'r':
                check_arg_portrange(&args, optarg);
            break;

            case 't':
                check_arg_localport(&args, optarg);
            break;

            case 'p':
                check_arg_password(&args, optarg);
            break;

            case 'm':
                check_arg_managerport(&args, optarg);
            break;

            case 'i':
                check_arg_serverip(&args, optarg);
            break;

            case 's':
                args.opt_servermode = true;
            break;

            case '?':
                arg_error(NULL);
            break;

            default:
                arg_error(NULL);
            break;
        }
    }

    /* Set verbose level */
    if(args.opt_verbose)
        glb_debug_level = args.verbose_level;

    /* Checking program mode */
    if((args.opt_servermode && args.opt_serverip) ||
       (!args.opt_servermode && !args.opt_serverip))
    {
        arg_error("program mode");
    }

    if(debug(3))
        print_args(&args);

    /* Launching program client/server mode */
    if(args.opt_servermode)
    {
        ent.type                           = SERVER;
        ent.server_listening_port_range[0] = (args.opt_portrange)   ? args.port_start   : DEFAULT_SERVER_LISTENING_RANGE_START;
        ent.server_listening_port_range[1] = (args.opt_portrange)   ? args.port_end     : DEFAULT_SERVER_LISTENING_RANGE_END;
        ent.server_local_target_port       = (args.opt_localport)   ? args.port_local   : DEFAULT_SERVER_LOCAL_TARGET_PORT;
        ent.server_manager_port            = (args.opt_managerport) ? args.port_manager : DEFAULT_SERVER_MANAGER_PORT;

        if(args.opt_password) memcpy(ent.server_password, (uint8_t*) args.password, strlen(args.password));
        else                  memcpy(ent.server_password, (uint8_t*) DEFAULT_SERVER_PASSWORD, strlen(DEFAULT_SERVER_PASSWORD));

        server(&ent);
    }
    else if(args.opt_serverip)
    {
        ent.type                           = CLIENT;
        ent.server_manager_port            = (args.opt_managerport) ? args.port_manager : DEFAULT_SERVER_MANAGER_PORT;
        ent.client_listening_port_range[0] = (args.opt_portrange)   ? args.port_start   : DEFAULT_CLIENT_LISTENING_RANGE_START;
        ent.client_listening_port_range[1] = (args.opt_portrange)   ? args.port_end     : DEFAULT_CLIENT_LISTENING_RANGE_END;
        ent.client_app_dst_port            = (args.opt_localport)   ? args.port_local   : DEFAULT_CLIENT_APPLICATION_DEST_PORT;
        ent.client_tunnel_ttl              = (args.opt_tunnelttl)   ? args.tunnel_ttl   : DEFAULT_CLIENT_TUNNEL_TTL;

        if(args.opt_password) memcpy(ent.server_password, (uint8_t*) args.password, strlen(args.password));
        else                  memcpy(ent.server_password, (uint8_t*) DEFAULT_SERVER_PASSWORD, strlen(DEFAULT_SERVER_PASSWORD));

        inet_pton(AF_INET, args.serverip, &ent.server_ip);

        client(&ent);
    }

    return EXIT_SUCCESS;
}
