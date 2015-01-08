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

#include <stdlib.h>
#include <stdio.h>
#include <sys/socket.h>
#include <errno.h>
#include <string.h>

#include "defines.h"
#include "memory.h"
#include "UTMP.h"

extern bool glb_signal_stop;

uint8_t get_UTMP_version(uint8_t* utmp_msg)
{
    return utmp_msg[0];
}

uint8_t get_UTMP_type(uint8_t* utmp_msg)
{
    return utmp_msg[1];
}

int parse_UTMP_fields(int utmp_type, UTMP_field_type field_type, uint8_t* utmp_msg, void* result)
{
    int ret = RETURN_ERROR;

    switch(utmp_type)
    {
        case UTMP_MSG_AUTH_OK:
        {
            switch(field_type)
            {
                case SRV_PORT_START:
                {
                    uint16_t* uint16 = result;
                    *uint16 = (utmp_msg[2] << 8) + utmp_msg[3];
                    ret = RETURN_SUCCESS;
                }
                break;

                case SRV_PORT_END:
                {
                    uint16_t* uint16 = result;
                    *uint16 = (utmp_msg[4] << 8) + utmp_msg[5];
                    ret = RETURN_SUCCESS;
                }
                break;

                case CLT_IP:
                {
                    uint32_t* uint32 = result;
                    *uint32 = (utmp_msg[6] << (8 * 3)) +
                              (utmp_msg[7] << (8 * 2)) +
                              (utmp_msg[8] << (8 * 1)) +
                              (utmp_msg[9] << (8 * 0));
                    ret = RETURN_SUCCESS;
                }
                break;

                default:
                break;
            }
        }
        break;

        case UTMP_MSG_CHG_PORT:
        {
            switch(field_type)
            {
                case SRV_PORT_START:
                {
                    uint16_t* uint16 = result;
                    *uint16 = (utmp_msg[2] << 8) + utmp_msg[3];
                    ret = RETURN_SUCCESS;
                }
                break;

                case SRV_PORT_END:
                {
                    uint16_t* uint16 = result;
                    *uint16 = (utmp_msg[4] << 8) + utmp_msg[5];
                    ret = RETURN_SUCCESS;
                }
                break;

                default:
                break;
            }
        }
        break;

        case UTMP_MSG_NEW_TUN:
        {
            switch(field_type)
            {
                case SRV_LISN_PORT:
                {
                    uint16_t* uint16 = result;
                    *uint16 = (utmp_msg[2] << 8) + utmp_msg[3];
                    ret = RETURN_SUCCESS;
                }
                break;

                case CLT_LISN_PORT:
                {
                    uint16_t* uint16 = result;
                    *uint16 = (utmp_msg[4] << 8) + utmp_msg[5];
                    ret = RETURN_SUCCESS;
                }
                break;

                default:
                break;
            }
        }
        break;
    }

    return ret;
}

void dump_UTMP_packet(uint8_t* buff, int size)
{
    int i = 0;

    info("dump_UTMP_packet()");
    printf("Protocol version: %x\n", buff[0]);
    printf("Type: %x\n", buff[1]);
    printf("Data:\n");

    for(i = 0; i < size-2; i++)
    {
        printf("%02x ", buff[2+i]);
    }
    printf("\n");
}

uint16_t get_random_srv_port(Entity* ent)
{
    uint16_t ret;

    pthread_mutex_lock(&ent->lock);
    {
        ret = rand() % (ent->server_listening_port_range[1] - ent->server_listening_port_range[0]) + ent->server_listening_port_range[0];
    }
    pthread_mutex_unlock(&ent->lock);

    return ret;
}

uint16_t get_random_clt_port(Entity* ent)
{
    uint16_t ret;

    pthread_mutex_lock(&ent->lock);
    {
        ret = rand() % (ent->client_listening_port_range[1] - ent->client_listening_port_range[0]) + ent->client_listening_port_range[0];
    }
    pthread_mutex_unlock(&ent->lock);

    return ret;
}

int valid_listening_ports(Entity* ent, uint16_t new_srv_port, uint16_t new_clt_port)
{
    int ret = RETURN_SUCCESS;

    if(new_clt_port == 0)
        ret = RETURN_ERROR;

    pthread_mutex_lock(&ent->lock);
    {
        if(new_srv_port < ent->server_listening_port_range[0] ||
           new_srv_port > ent->server_listening_port_range[1])
            ret = RETURN_ERROR;
    }
    pthread_mutex_unlock(&ent->lock);

    return ret;
}

int recv_UTMP_msg(int sock, uint8_t* buff_rcv, int buff_rcv_size)
{
    uint8_t rcv_tmp_buff[MANAGER_RCVTMPBUFFLEN] = {0};
    int eot = 0;
    int rcv_ret;
    int rcv_size = 0;
    int decoding_prot = 0;
    int decoding_msg_type = 0;
    int waited_data = 0;
    int ret = RETURN_ERROR;

    while(!glb_signal_stop && !eot)
    {
        rcv_ret = recv(sock, rcv_tmp_buff, MANAGER_RCVTMPBUFFLEN, 0);

        if(rcv_ret == -1)
        {
            /* Too long achievement */
            if(errno == EAGAIN || errno == EWOULDBLOCK)
            {
                if(debug(3))
                    warning("recv_UTMP_msg(): recv(): Too long achievement, errno %d", errno);
            }
            else
            {
                if(debug(3))
                    warning("recv_UTMP_msg(): recv(): errno %d", errno);

                eot = 1;
            }
        }
        else if(rcv_ret == 0)
        {
            if(debug(3))
                warning("recv_UTMP_msg(): recv(): 0 bytes returned, errno %d", errno);

            eot = 1;
        }
        else
        {
            if(rcv_size + rcv_ret > buff_rcv_size)
            {
                if(debug(3))
                    warning("recv_UTMP_msg(): recv(): packet too big");

                eot = 1;
            }
            else
            {
                memcpy( &buff_rcv[rcv_size], rcv_tmp_buff, rcv_ret);
                rcv_size += rcv_ret;

                /* first step: get protocol version */
                if(!decoding_prot && rcv_size >= UTMP_LENGTH_PROTVERSION)
                {
                    decoding_prot = 1;

                    if(get_UTMP_version(buff_rcv) != UTMP_PROTOCOL_VERSION)
                    {
                        if(debug(3))
                            warning("recv_UTMP_msg(): recv(): protocol version unknown");

                        eot = 1;
                    }
                }

                /* second step: get msg type */
                if(!eot && !decoding_msg_type && rcv_size >= (UTMP_LENGTH_PROTVERSION + UTMP_LENGTH_MSGTYPE))
                {
                    decoding_msg_type = 1;

                    switch (get_UTMP_type(buff_rcv))
                    {
                        case UTMP_MSG_AUTH:
                            waited_data = UTMP_LENGTH_MSG_AUTH;
                        break;

                        case UTMP_MSG_CHG_PORT:
                            waited_data = UTMP_LENGTH_MSG_CHG_PORT;
                        break;

                        case UTMP_MSG_AUTH_OK:
                            waited_data = UTMP_LENGTH_MSG_AUTH_OK;
                        break;

                        case UTMP_MSG_AUTH_NOK:
                            waited_data = UTMP_LENGTH_MSG_AUTH_NOK;
                        break;

                        case UTMP_MSG_CHG_PORT_OK:
                            waited_data = UTMP_LENGTH_MSG_CHG_PORT_OK;
                        break;

                        case UTMP_MSG_CHG_PORT_NOK:
                            waited_data = UTMP_LENGTH_MSG_CHG_PORT_NOK;
                        break;

                        case UTMP_MSG_NEW_TUN:
                            waited_data = UTMP_LENGTH_MSG_NEW_TUN;
                        break;

                        case UTMP_MSG_NEW_TUN_OK:
                            waited_data = UTMP_LENGTH_MSG_NEW_TUN_OK;
                        break;

                        case UTMP_MSG_NEW_TUN_NOK:
                            waited_data = UTMP_LENGTH_MSG_NEW_TUN_NOK;
                        break;

                        case UTMP_MSG_CLOSE_TUN:
                            waited_data = UTMP_LENGTH_MSG_CLOSE_TUN;
                        break;

                        case UTMP_MSG_CLOSE_TUN_ACK:
                            waited_data = UTMP_LENGTH_MSG_CLOSE_TUN_ACK;
                        break;

                        case UTMP_MSG_UNKNOWN:
                            waited_data = UTMP_LENGTH_MSG_UNKNOWN;
                        break;

                        default:
                            if(debug(3))
                                warning("recv_UTMP_msg(): message type not recognized");

                            eot = 1;
                        break;
                    }
                }

                /* third step: wait for all datas related to msg type */
                if(!eot && decoding_prot && decoding_msg_type)
                {
                    if(rcv_size >= (waited_data + UTMP_LENGTH_PROTVERSION + UTMP_LENGTH_MSGTYPE))
                    {
                        eot = 1;
                        ret = RETURN_SUCCESS;
                    }
                }
            }
        }
    }

    return ret;
}

int send_UTMP_msg(int sock, uint8_t* buff_snd, int buff_snd_size)
{
    if(send(sock, buff_snd, buff_snd_size, 0) == -1)
    {
        if(debug(3))
            warning("send_UTMP_msg(): send(): error %d\n", errno);

        return RETURN_ERROR;
    }

    return RETURN_SUCCESS;
}

void make_UTMP_auth(uint8_t** buff, int* buff_size, Entity* ent)
{
    *buff_size = UTMP_LENGTH_PROTVERSION + UTMP_LENGTH_MSGTYPE + UTMP_LENGTH_MSG_AUTH;
    *buff = (uint8_t*) s_malloc(sizeof(uint8_t) * *buff_size);

    (*buff)[0] = UTMP_PROTOCOL_VERSION;
    (*buff)[1] = UTMP_MSG_AUTH;

    pthread_mutex_lock(&ent->lock);
    {
        memcpy((*buff)+2, ent->server_password, strlen((const char*) ent->server_password));
    }
    pthread_mutex_unlock(&ent->lock);
}

void make_UTMP_chgPort(uint8_t** buff, int* buff_size, uint16_t srv_port, uint16_t clt_port)
{
    *buff_size = UTMP_LENGTH_PROTVERSION + UTMP_LENGTH_MSGTYPE + UTMP_LENGTH_MSG_CHG_PORT;
    *buff = (uint8_t*) s_malloc(sizeof(uint8_t) * *buff_size);

    (*buff)[0] = UTMP_PROTOCOL_VERSION;
    (*buff)[1] = UTMP_MSG_CHG_PORT;

    (*buff)[2] = srv_port >> 8;
    (*buff)[3] = (srv_port << 8) >> 8;
    (*buff)[4] = clt_port >> 8;
    (*buff)[5] = (clt_port << 8) >> 8;
}

void make_UTMP_authOK(uint8_t** buff, int* buff_size, Entity* ent)
{
    *buff_size = UTMP_LENGTH_PROTVERSION + UTMP_LENGTH_MSGTYPE + UTMP_LENGTH_MSG_AUTH_OK;
    *buff = (uint8_t*) s_malloc(sizeof(uint8_t) * *buff_size);

    (*buff)[0] = UTMP_PROTOCOL_VERSION;
    (*buff)[1] = UTMP_MSG_AUTH_OK;

    pthread_mutex_lock(&ent->lock);
    {
        (*buff)[2] = ent->server_listening_port_range[0] >> 8;
        (*buff)[3] = (ent->server_listening_port_range[0] << 8) >> 8;
        (*buff)[4] = ent->server_listening_port_range[1] >> 8;
        (*buff)[5] = (ent->server_listening_port_range[1] << 8) >> 8;
        (*buff)[6] = (ent->client_ip << 8 * 0) >> (8 * 3);
        (*buff)[7] = (ent->client_ip << 8 * 1) >> (8 * 3);
        (*buff)[8] = (ent->client_ip << 8 * 2) >> (8 * 3);
        (*buff)[9] = (ent->client_ip << 8 * 3) >> (8 * 3);
    }
    pthread_mutex_unlock(&ent->lock);
}

void make_UTMP_authNOK(uint8_t** buff, int* buff_size)
{
    *buff_size = UTMP_LENGTH_PROTVERSION + UTMP_LENGTH_MSGTYPE + UTMP_LENGTH_MSG_AUTH_NOK;
    *buff = (uint8_t*) s_malloc(sizeof(uint8_t) * *buff_size);

    (*buff)[0] = UTMP_PROTOCOL_VERSION;
    (*buff)[1] = UTMP_MSG_AUTH_NOK;
}

void make_UTMP_chgPortOK(uint8_t** buff, int* buff_size)
{
    *buff_size = UTMP_LENGTH_PROTVERSION + UTMP_LENGTH_MSGTYPE + UTMP_LENGTH_MSG_CHG_PORT_OK;
    *buff = (uint8_t*) s_malloc(sizeof(uint8_t) * *buff_size);

    (*buff)[0] = UTMP_PROTOCOL_VERSION;
    (*buff)[1] = UTMP_MSG_CHG_PORT_OK;
}

void make_UTMP_chgPortNOK(uint8_t** buff, int* buff_size)
{
    *buff_size = UTMP_LENGTH_PROTVERSION + UTMP_LENGTH_MSGTYPE + UTMP_LENGTH_MSG_CHG_PORT_NOK;
    *buff = (uint8_t*) s_malloc(sizeof(uint8_t) * *buff_size);

    (*buff)[0] = UTMP_PROTOCOL_VERSION;
    (*buff)[1] = UTMP_MSG_CHG_PORT_NOK;
}

void make_UTMP_newTun(uint8_t** buff, int* buff_size, uint16_t srv_port, uint16_t clt_port)
{
    *buff_size = UTMP_LENGTH_PROTVERSION + UTMP_LENGTH_MSGTYPE + UTMP_LENGTH_MSG_NEW_TUN;
    *buff = (uint8_t*) s_malloc(sizeof(uint8_t) * *buff_size);

    (*buff)[0] = UTMP_PROTOCOL_VERSION;
    (*buff)[1] = UTMP_MSG_NEW_TUN;

    (*buff)[2] = srv_port >> 8;
    (*buff)[3] = (srv_port << 8) >> 8;
    (*buff)[4] = clt_port >> 8;
    (*buff)[5] = (clt_port << 8) >> 8;
}

void make_UTMP_newTunOK(uint8_t** buff, int* buff_size)
{
    *buff_size = UTMP_LENGTH_PROTVERSION + UTMP_LENGTH_MSGTYPE + UTMP_LENGTH_MSG_NEW_TUN_OK;
    *buff = (uint8_t*) s_malloc(sizeof(uint8_t) * *buff_size);

    (*buff)[0] = UTMP_PROTOCOL_VERSION;
    (*buff)[1] = UTMP_MSG_NEW_TUN_OK;
}

void make_UTMP_newTunNOK(uint8_t** buff, int* buff_size)
{
    *buff_size = UTMP_LENGTH_PROTVERSION + UTMP_LENGTH_MSGTYPE + UTMP_LENGTH_MSG_NEW_TUN_NOK;
    *buff = (uint8_t*) s_malloc(sizeof(uint8_t) * *buff_size);

    (*buff)[0] = UTMP_PROTOCOL_VERSION;
    (*buff)[1] = UTMP_MSG_NEW_TUN_NOK;
}

void make_UTMP_closeTun(uint8_t** buff, int* buff_size)
{
    *buff_size = UTMP_LENGTH_PROTVERSION + UTMP_LENGTH_MSGTYPE + UTMP_LENGTH_MSG_CLOSE_TUN;
    *buff = (uint8_t*) s_malloc(sizeof(uint8_t) * *buff_size);

    (*buff)[0] = UTMP_PROTOCOL_VERSION;
    (*buff)[1] = UTMP_MSG_CLOSE_TUN;
}

void make_UTMP_closeTunACK(uint8_t** buff, int* buff_size)
{
    *buff_size = UTMP_LENGTH_PROTVERSION + UTMP_LENGTH_MSGTYPE + UTMP_LENGTH_MSG_CLOSE_TUN_ACK;
    *buff = (uint8_t*) s_malloc(sizeof(uint8_t) * *buff_size);

    (*buff)[0] = UTMP_PROTOCOL_VERSION;
    (*buff)[1] = UTMP_MSG_CLOSE_TUN_ACK;
}

void make_UTMP_unknown(uint8_t** buff, int* buff_size)
{
    *buff_size = UTMP_LENGTH_PROTVERSION + UTMP_LENGTH_MSGTYPE + UTMP_LENGTH_MSG_UNKNOWN;
    *buff = (uint8_t*) s_malloc(sizeof(uint8_t) * *buff_size);

    (*buff)[0] = UTMP_PROTOCOL_VERSION;
    (*buff)[1] = UTMP_MSG_UNKNOWN;
}
