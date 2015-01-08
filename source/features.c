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

#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <errno.h>
#include <unistd.h>
#include <sys/time.h>
#include <string.h>

#include "features.h"
#include "memory.h"
#include "UTMP.h"

extern bool glb_signal_stop;

void init_manager(Param_manager* p, Entity* ent)
{
    p->ent = ent;
    p->remote2local_retvalue = NULL;
    p->local2remote_retvalue = NULL;

    /* UDP threads init */
    init_param_tunnel(&p->p_local2remote, ent);
    init_param_tunnel(&p->p_remote2local, ent);

    p->th_remote2local = 0;
    p->th_local2remote = 0;

    p->local_tcp_sock = 0;
}

void init_param_tunnel(Param_th_tunnel* p, Entity* ent)
{
    p->ent = ent;
    p->stop = false;
    p->remoteSock = 0;
    p->remoteSin = NULL;
}

void* th_wrapper(void* param)
{
    Param_th_tunnel* p = param;
    Entity* ent = p->ent;

    return (void*) wrap_tcp_to_udp(ent, p->remoteSock, p->remoteSin, &p->stop);
}

void* th_unwrapper(void* param)
{
    Param_th_tunnel* p = param;
    Entity* ent = p->ent;

    return (void*) unwrap_tcp_from_udp(ent, p->remoteSock, p->remoteSin, &p->stop);
}

bool wrap_tcp_to_udp(Entity* ent, int remoteSock, Sin* remoteSin, bool* stop)
{
    bool ret = RETURN_SUCCESS;
    int listeningTCPSock;

    // On initie la socket d'écoute locale
    if((listeningTCPSock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) < 0)
    {
        if(debug(3))
            warning("wrap_tcp_to_udp(): socket(): errno %d", errno);

        ret = RETURN_ERROR;
    }
    else
    {
        // timeout sur la socket TCP d'écoute pour garder le contrôle du thread
        if(set_timeout_socket(listeningTCPSock, 0, SOCKET_NONBLOCK_DURATION_US) == RETURN_ERROR)
        {
            if(debug(3))
                warning("wrap_tcp_to_udp(): set_timeout_socket(): error");

            ret = RETURN_ERROR;
        }
        else
        {
            Raw_Packet currentPacket;
            PacketInfo pkt_info;
            Entity ent_tmp;
                init_entity(&ent_tmp);
            Connection remoteHost;
                init_connection(&remoteHost);
                remoteHost.sock = remoteSock;

            // On change la taille du buffer
            set_rcv_buffer(&listeningTCPSock);

            currentPacket.buffer = (uint8_t*) s_malloc(sizeof(uint8_t) * TCP_SIZE_MAX);

            while(!*stop)
            {
                currentPacket.size = recvfrom(listeningTCPSock, currentPacket.buffer, TCP_SIZE_MAX, 0, 0, 0);

                copyEnt(ent, &ent_tmp);
                copySin(remoteSin, &remoteHost.dest);

                if(currentPacket.size > 0)
                {
                    if(debug(6))
                        info("wrap_tcp_to_udp(): catch TCP packet");

                    pkt_info = get_info_from_l3_packet(&currentPacket);

                    /* Local TCP packet 127.x.x.x (RFC 1122) */
                    if(pkt_info.IPDest >> 24 == 127)
                    {
                        if((ent_tmp.type == CLIENT && pkt_info.portDest == ent_tmp.client_app_dst_port) ||
                           (ent_tmp.type == SERVER && pkt_info.portSource == ent_tmp.server_local_target_port))
                        {
                           if(debug(4))
                                info("wrap_tcp_to_udp(): received local TCP packet");

                            transfer_from_TCP_to_UDP(&remoteHost, &currentPacket);
                        }
                    }
                }
                else
                {
                    if(errno == EAGAIN || errno == EWOULDBLOCK)
                    {
                        /* Send regular packets to keep server aware of NAT client UDP port */
                        if(ent_tmp.type == CLIENT)
                        {
                            /* Magic packet is one byte length packet containing M letter (or whatever you want we don't care) */
                            currentPacket.buffer[0] = 'M';
                            currentPacket.size = 1;
                            send_UDP_packet(&remoteHost, currentPacket.buffer, currentPacket.size);
                        }
                    }
                    else
                    {
                        if(errno != EINTR)
                        {
                            if(debug(3))
                                warning("wrap_tcp_to_udp(): recvfrom(): errno %d", errno);
                        }

                        break;
                    }
                }
            }
            free(currentPacket.buffer);
        }
        close(listeningTCPSock);
    }

    close(remoteSock);

    if(debug(4))
        info("wrap_tcp_to_udp(): wrapper closing");

    return ret;
}

bool unwrap_tcp_from_udp(Entity* ent, int remoteSock, Sin* remoteSin, bool* stop)
{
    bool ret = RETURN_SUCCESS;
    Connection localHost;

    /* Configure localHost connection */
    init_connection(&localHost);
    localHost.dest.saddrin.sin_family = AF_INET;
    localHost.dest.saddrin.sin_addr.s_addr = inet_addr("127.0.0.1");
    pthread_mutex_lock(&ent->lock);
    {
        if(ent->type == SERVER)      localHost.dest.saddrin.sin_port = htons(ent->server_local_target_port);
        else if(ent->type == CLIENT) localHost.dest.saddrin.sin_port = htons(ent->client_app_dst_port);
    }
    pthread_mutex_unlock(&ent->lock);

    // On initie la socket d'envoi à TARGET
    if((localHost.sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) < 0)
    {
        if(debug(3))
            warning("unwrap_tcp_from_udp(): socket(): errno %d", errno);

        ret = RETURN_ERROR;
    }
    else
    {
        Raw_Packet currentPacket;
        Entity ent_tmp;
            pthread_mutex_init(&ent_tmp.lock, NULL);
        struct sockaddr_in last_remote_sin;
        socklen_t slen = sizeof(struct sockaddr_in);

        currentPacket.buffer = (uint8_t*) s_malloc(sizeof(uint8_t) * UDP_SIZE_MAX);

        while(!*stop)
        {
            currentPacket.size = recvfrom(remoteSock, currentPacket.buffer, UDP_SIZE_MAX, 0, (struct sockaddr *) &last_remote_sin, &slen);

            // Copy of ent to ent_tmp to prevent partial reading from ent modification
            copyEnt(ent, &ent_tmp);

            /* Magic packet, used to keep connection through NAT */
            if(currentPacket.size == 1)
            {
                if(debug(6))
                    info("unwrap_tcp_from_udp(): magic packet received");

                if(ent_tmp.type == SERVER)
                {
                    update_sin(remoteSin, &last_remote_sin);
                }
            }
            else if(currentPacket.size > 1)
            {
                if(debug(4))
                {
                    char ip[INET_ADDRSTRLEN] = "";

                    inet_ntop(AF_INET, &last_remote_sin.sin_addr, ip, INET_ADDRSTRLEN);

                    info("unwrap_tcp_from_udp(): received UDP packet from %s:%u", ip, ntohs(last_remote_sin.sin_port));
                }

                if(debug(6))
                    print_hex_dump(currentPacket.buffer, currentPacket.size);

                if(ent_tmp.type == CLIENT)
                {
                    transfer_from_UDP_to_TCP(&localHost, &currentPacket, ent_tmp.client_app_dst_port, 0);
                }
                else if(ent_tmp.type == SERVER)
                {
                    /* Because of NAT, UDP remote port must be checked and redefined in server mode */
                    update_sin(remoteSin, &last_remote_sin);

                    transfer_from_UDP_to_TCP(&localHost, &currentPacket, 0, ent_tmp.server_local_target_port);
                }
            }
            else
            {
                if(errno != EAGAIN && errno != EWOULDBLOCK)
                {
                    if(errno != EINTR)
                    {
                        if(debug(3))
                            warning("unwrap_tcp_from_udp(): recvfrom(): errno %d", errno);
                    }

                    break;
                }
            }
        }
        free(currentPacket.buffer);
        close(localHost.sock);
    }
    close(remoteSock);

    if(debug(4))
        info("unwrap_tcp_from_udp(): unwrapper closing");

    return ret;
}

bool set_timeout_socket(int sock, int time_sec, int time_usec)
{
    struct timeval packet_timeout;

    packet_timeout.tv_sec = time_sec;
    packet_timeout.tv_usec = time_usec;

    if(setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char *) &packet_timeout, sizeof(struct timeval)) != 0)
    {
        if(debug(3))
            warning("set_timeout_socket(): setsockopt(): errno %d", errno);

        return RETURN_ERROR;
    }

    return RETURN_SUCCESS;
}

bool set_linger_socket(int sock, int time_sec)
{
    struct linger lin;
        lin.l_onoff = 1;
        lin.l_linger = time_sec;

    if(setsockopt(sock, SOL_SOCKET, SO_LINGER, (void*)(&lin), sizeof(lin)) != 0)
    {
        if(debug(3))
            warning("set_linger_socket(): setsockopt(): errno %d", errno);

        return RETURN_ERROR;
    }

    return RETURN_SUCCESS;
}

void update_sin(Sin* remoteSin, struct sockaddr_in* last_saddrin)
{
    pthread_mutex_lock(&remoteSin->lock);
    {
        if(last_saddrin->sin_port != remoteSin->saddrin.sin_port)
        {
            if(debug(4))
                info("update_sin(): NAT detected, changing remote UDP from %u to %u",
                     htons(remoteSin->saddrin.sin_port),
                     ntohs(last_saddrin->sin_port));

            remoteSin->saddrin.sin_port = last_saddrin->sin_port;
        }
    }
    pthread_mutex_unlock(&remoteSin->lock);
}

bool tunnel_start(Param_manager* p)
{
    int remoteSockUDP;
    Sin* UDP_remote = new_sin();
    struct sockaddr_in UDP_local_host;
    int32_t on = 1;

    /* Kill tunnel if running */
    if(get_tunnel_state(p) != CLOSE)
    {
        if(debug(3))
            warning("tunnel_start(): a tunnel is already running. Killing it.");

        tunnel_stop(p);
    }

    pthread_mutex_lock(&p->ent->lock);
    {
        if(p->ent->type == SERVER)
        {
            UDP_remote->saddrin.sin_family = AF_INET;
            UDP_remote->saddrin.sin_addr.s_addr = p->ent->client_ip;
            /* Setting it to 0 because it's impossible to know remote port if client is NATted.
                Client port will be know later. */
            UDP_remote->saddrin.sin_port = 0;

            UDP_local_host.sin_family = AF_INET;
            UDP_local_host.sin_addr.s_addr = INADDR_ANY;
            UDP_local_host.sin_port = htons(p->ent->server_listening_port);
        }
        else if(p->ent->type == CLIENT)
        {
            UDP_remote->saddrin.sin_family = AF_INET;
            UDP_remote->saddrin.sin_addr.s_addr = p->ent->server_ip;
            UDP_remote->saddrin.sin_port = htons(p->ent->server_listening_port);

            UDP_local_host.sin_family = AF_INET;
            UDP_local_host.sin_addr.s_addr = INADDR_ANY;
            UDP_local_host.sin_port = htons(p->ent->client_listening_port);
        }
    }
    pthread_mutex_unlock(&p->ent->lock);

    // On initie la socket UDP
    if((remoteSockUDP = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
    {
        if(debug(3))
            warning("tunnel_start(): socket(): errno %d", errno);

        return RETURN_ERROR;
    }

    // timeout sur la socket UDP pour garder le contrôle du thread
    if(set_timeout_socket(remoteSockUDP, 0, SOCKET_NONBLOCK_DURATION_US) == RETURN_ERROR)
    {
        if(debug(3))
            warning("tunnel_start(): set_timeout_socket(): error");

        return RETURN_ERROR;
    }

    // On active cette option qui permet de prévenir lorsque que l'on dépasse le buffer d'envoi local
    // sinon sendto ne renvoit pas d'erreur lors d'un dépassement de buffer
    if(setsockopt(remoteSockUDP, SOL_IP, IP_RECVERR, &on, sizeof(on)) != 0)
    {
        if(debug(3))
            warning("tunnel_start(): setsockopt(): errno %d", errno);

        return RETURN_ERROR;
    }

    // On change la taille du buffer
    set_rcv_buffer(&remoteSockUDP);

    // On bind la socket avec le port UDP local et non un port arbitraire
    if(bind(remoteSockUDP, (struct sockaddr*) &UDP_local_host, sizeof(UDP_local_host)) != 0)
    {
        if(debug(3))
            warning("tunnel_start(): bind(): errno %d", errno);

        return RETURN_ERROR;
    }

    p->p_remote2local.remoteSock = remoteSockUDP;
    p->p_local2remote.remoteSock = remoteSockUDP;

    p->p_remote2local.remoteSin = UDP_remote;
    p->p_local2remote.remoteSin = UDP_remote;

    p->p_remote2local.stop = false;
    p->p_local2remote.stop = false;

    if(debug(4))
        info("============================================START TUNNEL============================================");

    pthread_create(&p->th_remote2local, 0, th_unwrapper, &p->p_remote2local);
    pthread_create(&p->th_local2remote, 0, th_wrapper, &p->p_local2remote);

    return RETURN_SUCCESS;
}

void tunnel_stop(Param_manager* p)
{
    if(get_tunnel_state(p) != CLOSE)
    {
        p->p_local2remote.stop = true;
        p->p_remote2local.stop = true;

        pthread_join(p->th_local2remote, &p->local2remote_retvalue);
        pthread_join(p->th_remote2local, &p->remote2local_retvalue);

        free(p->p_local2remote.remoteSin);

        p->p_local2remote.remoteSin = NULL;
        p->p_remote2local.remoteSin = NULL;

        if(debug(4))
            info("============================================STOP  TUNNEL============================================");
    }
}

Tunnel_state get_tunnel_state(Param_manager* p)
{
    if(p->th_local2remote == 0 && p->th_remote2local == 0)
    {
        return CLOSE;
    }
    else if((p->th_local2remote == 0 && p->th_remote2local != 0) ||
            (p->th_local2remote != 0 && p->th_remote2local == 0))
    {
        return BROKEN;
    }
    else
    {
        int state_l2r = pthread_kill(p->th_local2remote, 0);
        int state_r2l = pthread_kill(p->th_remote2local, 0);

        if(state_l2r == 0 && state_r2l == 0)        return OPEN;
        else if(state_l2r != 0 && state_r2l != 0)   return CLOSE;
        else                                        return BROKEN;
    }
}

/********************************************************************
 *                                                                  *
 *                                                                  *
 *                            Client part                           *
 *                                                                  *
 *                                                                  *
 ********************************************************************/

void client(Entity* clt)
{
    Param_manager p_m;

    init_manager(&p_m, clt);

    if(debug(1))
        info("============== CLIENT SIDE ==============");

    // Réservation du port local TCP
    bookTCPPort(&p_m.local_tcp_sock, clt->client_app_dst_port);
    iptables_block(0, clt->client_app_dst_port);

    client_manager(&p_m);

    unbookTCPPort(&p_m.local_tcp_sock);
    iptables_unblock(0, clt->client_app_dst_port);
}

bool client_manager(Param_manager* p)
{
    Entity* clt = p->ent;

    Connection remoteServer;
            remoteServer.sock = 0;
            pthread_mutex_init(&remoteServer.dest.lock, NULL);

    uint8_t utmp_msg[MANAGER_RCVBUFFLEN] = {0};
    uint8_t* utmp_rqt;
    int utmp_rqt_size;
    bool keep_connection = true;
    bool authenticated = false;
    int tunnel_state = CLOSE;
    int tunnel_ttl = clt->client_tunnel_ttl;

    srand (time(NULL));

    /* Socket configuration */
    remoteServer.dest.saddrin.sin_family = AF_INET;
    remoteServer.dest.saddrin.sin_addr.s_addr = clt->server_ip;
    remoteServer.dest.saddrin.sin_port = htons(clt->server_manager_port);


    /* Interaction with server */
    while(keep_connection)
    {
        uint16_t rand_srv_port = 0;
        uint16_t rand_clt_port = 0;
        utmp_rqt = NULL;

        /* Pause between 2 tunnels */
        tunnel_state = get_tunnel_state(p);
        if(tunnel_state == OPEN)
        {
            sleep(tunnel_ttl);
        }

        if(!glb_signal_stop)
        {
            /* Socket init */
            if((remoteServer.sock = socket(AF_INET, SOCK_STREAM, 0)) < 0)
            {
                error("client_manager(): socket(): errno %d", errno);
            }

            /* 10s timeout for packets */
            if(set_timeout_socket(remoteServer.sock, 10, 0) == RETURN_ERROR)
            {
                error("client_manager(): set_timeout_socket(): error");
            }

            /* Server connection */
            while(!glb_signal_stop && connect(remoteServer.sock, (struct sockaddr*) &remoteServer.dest, sizeof(remoteServer.dest)) != 0)
            {
                if(debug(2))
                {
                    warning("client_manager(): connect(): error %d", errno);
                }

                sleep(1);
            }

            if(!glb_signal_stop)
            {
                if(!authenticated)
                {
                    if(debug(2))
                        info("client_manager(): Request: authentication...");

                    make_UTMP_auth(&utmp_rqt, &utmp_rqt_size, clt);
                }
                else
                {
                    tunnel_state = get_tunnel_state(p);

                    if(tunnel_state == CLOSE)
                    {
                        if(!glb_signal_stop)
                        {
                            rand_srv_port = get_random_srv_port(clt);
                            rand_clt_port = get_random_clt_port(clt);

                            if(debug(2))
                                info("client_manager(): Request: tunnel creation, srv port:%u, clt port:%u...", rand_srv_port, rand_clt_port);

                            make_UTMP_newTun(&utmp_rqt, &utmp_rqt_size, rand_srv_port, rand_clt_port);
                        }
                        else
                        {
                            keep_connection = false;
                        }
                    }
                    else if(tunnel_state == OPEN)
                    {
                        /* Fermeture tunnel */
                        if(glb_signal_stop)
                        {
                            if(debug(2))
                                info("client_manager(): Request: tunnel close...");

                            make_UTMP_closeTun(&utmp_rqt, &utmp_rqt_size);
                            keep_connection = false;
                        }
                        else
                        {
                            /* Changement des ports */
                            rand_srv_port = get_random_srv_port(clt);
                            rand_clt_port = get_random_clt_port(clt);

                            if(debug(2))
                                info("client_manager(): Request: ports change, srv port:%u, clt port:%u...", rand_srv_port, rand_clt_port);

                            make_UTMP_chgPort(&utmp_rqt, &utmp_rqt_size, rand_srv_port, rand_clt_port);
                        }
                    }
                    else if(tunnel_state == BROKEN)
                    {
                        if(debug(2))
                            warning("client_manager(): tunnel is broken. Stopping it and closing program.");

                        tunnel_stop(p);

                        make_UTMP_closeTun(&utmp_rqt, &utmp_rqt_size);
                        keep_connection = false;
                    }
                }

                if(utmp_rqt != NULL)
                {
                    send_UTMP_msg(remoteServer.sock, utmp_rqt, utmp_rqt_size);

                    if(recv_UTMP_msg(remoteServer.sock, utmp_msg, MANAGER_RCVBUFFLEN) == RETURN_SUCCESS)
                    {
                        switch(get_UTMP_type(utmp_msg))
                        {
                            /* Authentification accepted */
                            case UTMP_MSG_AUTH_OK:
                            {
                                if(debug(2))
                                    info("client_manager(): Reply: authentication OK");

                                uint16_t p_start = 0;
                                uint16_t p_end = 0;
                                uint32_t ip_clt = 0;

                                parse_UTMP_fields(UTMP_MSG_AUTH_OK, SRV_PORT_START, utmp_msg, &p_start);
                                parse_UTMP_fields(UTMP_MSG_AUTH_OK, SRV_PORT_END, utmp_msg, &p_end);
                                parse_UTMP_fields(UTMP_MSG_AUTH_OK, CLT_IP, utmp_msg, &ip_clt);

                                /* Update informations */
                                pthread_mutex_lock(&clt->lock);
                                {
                                    clt->server_listening_port_range[0] = p_start;
                                    clt->server_listening_port_range[1] = p_end;
                                    clt->client_ip = ip_clt;
                                }
                                pthread_mutex_unlock(&clt->lock);

                                authenticated = true;
                            }
                            break;

                            /* Authentification failed */
                            case UTMP_MSG_AUTH_NOK:
                                if(debug(2))
                                    info("client_manager(): Reply: authentication NOK");

                                keep_connection = false;
                            break;

                            case UTMP_MSG_CHG_PORT_OK:
                                if(debug(2))
                                    info("client_manager(): Reply: ports change OK");

                                /* Update informations */
                                pthread_mutex_lock(&clt->lock);
                                {
                                    clt->server_listening_port = rand_srv_port;
                                    clt->client_listening_port = rand_clt_port;
                                }
                                pthread_mutex_unlock(&clt->lock);

                                tunnel_stop(p);
                                tunnel_start(p);
                            break;

                            case UTMP_MSG_CHG_PORT_NOK:
                                if(debug(2))
                                    info("client_manager(): Reply: ports change NOK");
                            break;

                            /* Tunnel creation accepted */
                            case UTMP_MSG_NEW_TUN_OK:
                                if(debug(2))
                                    info("client_manager(): Reply: tunnel creation OK");

                                /* Update informations */
                                pthread_mutex_lock(&clt->lock);
                                {
                                    clt->server_listening_port = rand_srv_port;
                                    clt->client_listening_port = rand_clt_port;
                                }
                                pthread_mutex_unlock(&clt->lock);

                                /* Tunnel creation */
                                tunnel_start(p);
                            break;

                            /* Tunnel creation refused */
                            case UTMP_MSG_NEW_TUN_NOK:
                                if(debug(2))
                                    info("client_manager(): Reply: tunnel creation NOK");

                                keep_connection = false;
                            break;

                            /* Tunnel shutdown acknowledge */
                            case UTMP_MSG_CLOSE_TUN_ACK:
                                if(debug(2))
                                    info("client_manager(): Reply: tunnel close ack");

                                keep_connection = false;
                            break;

                            /* Server is dumb */
                            case UTMP_MSG_UNKNOWN:
                                if(debug(2))
                                    warning("client_manager(): Reply: server didn't understand request :/");
                            break;

                            default:
                                if(debug(2))
                                    warning("client_manager(): unsupported UTMP request");
                            break;
                        }
                    }
                    else
                    {
                        if(debug(2))
                            info("client_manager(): UTMP response missing or malformed. Shutdown connection with server.");

                        keep_connection = false;
                    }
                }
            }
            else
            {
                keep_connection = false;
            }

            if(remoteServer.sock)
                close(remoteServer.sock);
        }
        else
        {
            keep_connection = false;
        }
    }


    tunnel_stop(p);
    free(utmp_rqt);

    return RETURN_SUCCESS;
}

/********************************************************************
 *                                                                  *
 *                                                                  *
 *                            Server part                           *
 *                                                                  *
 *                                                                  *
 ********************************************************************/

void server(Entity* srv)
{
    Param_manager p_m;

    init_manager(&p_m, srv);

    if(debug(1))
        info("============== SERVER SIDE ==============");

    // Réservation du port local TCP
    iptables_block(srv->server_local_target_port, 0);

    server_manager(&p_m);

    iptables_unblock(srv->server_local_target_port, 0);
}

bool server_manager(Param_manager* p)
{
    Entity* srv = p->ent;

    Connection remoteClient;
    Connection local;
    socklen_t slen = sizeof(remoteClient.dest);

    init_connection(&remoteClient);
    init_connection(&local);

    /* Local TCP sock */
    local.dest.saddrin.sin_family = AF_INET;
    local.dest.saddrin.sin_addr.s_addr = htonl(INADDR_ANY);
    local.dest.saddrin.sin_port = htons(srv->server_manager_port);

    if((local.sock = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        error("server_manager(): socket(): errno %d", errno);
    }

    /* 10s timeout for packets */
    if(set_timeout_socket(local.sock, SERVER_NONBLOCKING_SOCKET_MAX_TIME, 0) == RETURN_ERROR)
    {
        error("server_manager(): set_timeout_socket(): error");
    }

    /* Set linger option: give time to non-blocking socket to send last bytes before being closed */
    if(set_linger_socket(local.sock, SERVER_NONBLOCKING_SOCKET_LINGER) == RETURN_ERROR)
    {
        error("server_manager(): set_linger_socket(): error");
    }

    if(bind(local.sock, (struct sockaddr*) &local.dest, sizeof(local.dest)) != 0)
    {
        error("server_manager(): bind(): errno %d", errno);
    }

    if(listen(local.sock, MANAGER_MAXWAITINGCONN) != 0)
    {
        warning("server_manager(): listen(): errno %d", errno);
    }

    /* Waiting/replier for UTMP requests */
    while(!glb_signal_stop)
    {
        remoteClient.sock = accept(local.sock, (struct sockaddr*) &remoteClient.dest, &slen);

        if(remoteClient.sock < 0)
        {
            /* Regular errors if no pending connection because socket has been marked nonblocking */
            if(errno != EAGAIN || errno != EWOULDBLOCK)
            {
                /* Error corresponding to interruption */
                if(errno != EINTR)
                    error("server_manager(): accept(): errno %d", errno);
            }
        }
        else
        {
            uint8_t utmp_msg[MANAGER_RCVBUFFLEN] = {0};

            /* Wait for UTMP mesage */
            if(recv_UTMP_msg(remoteClient.sock, utmp_msg, MANAGER_RCVBUFFLEN) == RETURN_SUCCESS)
            {
                uint8_t* utmp_reply;
                int utmp_reply_size;

                switch(get_UTMP_type(utmp_msg))
                {
                    /* Authentication */
                    case UTMP_MSG_AUTH:
                    if(debug(2))
                        info("server_manager(): Request: authentication");
                    {
                        int password_cmp = 1;

                        /* Test valid password */
                        pthread_mutex_lock(&srv->lock);
                        {
                            password_cmp = u8cmp(utmp_msg+2, srv->server_password);
                        }
                        pthread_mutex_unlock(&srv->lock);

                        if(password_cmp != 0)
                        {
                            if(debug(2))
                                info("server_manager(): Reply: authentication refused");

                            make_UTMP_authNOK(&utmp_reply, &utmp_reply_size);

                            /* Anti bruteforce */
                            sleep(1);
                        }
                        else
                        {
                            if(debug(2))
                                info("server_manager(): Reply: authentication OK");

                            pthread_mutex_lock(&srv->lock);
                            {
                                srv->client_ip = remoteClient.dest.saddrin.sin_addr.s_addr;
                            }
                            pthread_mutex_unlock(&srv->lock);

                            make_UTMP_authOK(&utmp_reply, &utmp_reply_size, srv);
                        }
                    }
                    break;

                    /* UDP ports change */
                    case UTMP_MSG_CHG_PORT:
                    if(debug(2))
                        info("server_manager(): Request: ports change");
                    {
                        uint16_t new_srv_lisn_port;
                        uint16_t new_clt_lisn_port;

                        parse_UTMP_fields(UTMP_MSG_CHG_PORT, SRV_PORT_START, utmp_msg, &new_srv_lisn_port);
                        parse_UTMP_fields(UTMP_MSG_CHG_PORT, SRV_PORT_END, utmp_msg, &new_clt_lisn_port);

                        if(valid_listening_ports(srv, new_srv_lisn_port, new_clt_lisn_port) == RETURN_SUCCESS)
                        {
                            if(debug(2))
                                info("server_manager(): Reply: change port OK");

                            make_UTMP_chgPortOK(&utmp_reply, &utmp_reply_size);

                            pthread_mutex_lock(&srv->lock);
                            {
                                srv->server_listening_port = new_srv_lisn_port;
                                srv->client_listening_port = new_clt_lisn_port;
                            }
                            pthread_mutex_unlock(&srv->lock);

                            tunnel_stop(p);
                            tunnel_start(p);
                        }
                        else
                        {
                            if(debug(2))
                                info("server_manager(): Reply: change port refused");

                            make_UTMP_chgPortNOK(&utmp_reply, &utmp_reply_size);
                        }
                    }
                    break;

                    /* UDP tunnel creation */
                    case UTMP_MSG_NEW_TUN:
                    if(debug(2))
                        info("server_manager(): Request: tunnel creation");
                    {
                        uint16_t new_srv_lisn_port;
                        uint16_t new_clt_lisn_port;

                        parse_UTMP_fields(UTMP_MSG_NEW_TUN, SRV_LISN_PORT, utmp_msg, &new_srv_lisn_port);
                        parse_UTMP_fields(UTMP_MSG_NEW_TUN, CLT_LISN_PORT, utmp_msg, &new_clt_lisn_port);

                        if(valid_listening_ports(srv, new_srv_lisn_port, new_clt_lisn_port) == RETURN_SUCCESS)
                        {
                            make_UTMP_newTunOK(&utmp_reply, &utmp_reply_size);

                            pthread_mutex_lock(&srv->lock);
                            {
                                srv->server_listening_port = new_srv_lisn_port;
                                srv->client_listening_port = new_clt_lisn_port;
                            }
                            pthread_mutex_unlock(&srv->lock);

                            if(debug(2))
                                info("server_manager(): Reply: tunnel creation OK with ports s:%u c:%u", new_srv_lisn_port,new_clt_lisn_port);

                            tunnel_start(p);
                        }
                        else
                        {
                            if(debug(2))
                                info("server_manager(): Reply: tunnel creation refused");

                            make_UTMP_newTunNOK(&utmp_reply, &utmp_reply_size);
                        }
                    }
                    break;

                    /* UDP tunnel close */
                    case UTMP_MSG_CLOSE_TUN:
                    {
                        if(debug(2))
                        {
                            info("server_manager(): Request: tunnel closing");
                            info("server_manager(): Reply: tunnel closing ACK");
                        }

                        tunnel_stop(p);
                        make_UTMP_closeTunACK(&utmp_reply, &utmp_reply_size);
                    }
                    break;

                    /* Unknown request */
                    default:
                        if(debug(2))
                            info("server_manager(): Request: unsupported request");

                        make_UTMP_unknown(&utmp_reply, &utmp_reply_size);
                    break;
                }

                send_UTMP_msg(remoteClient.sock, utmp_reply, utmp_reply_size);
                free(utmp_reply);
            }
            else
            {
                if(debug(2))
                    info("server_manager(): UTMP response missing or malformed. Shutdown connection with client.");
            }

            close(remoteClient.sock);
        }
    }

    tunnel_stop(p);

    close(local.sock);

    return RETURN_SUCCESS;
}
