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

#ifndef DEFINES_H
#define DEFINES_H

/*
 *
 *  Server definitions
 *
 */

#define DEFAULT_SERVER_LISTENING_RANGE_START    10200
#define DEFAULT_SERVER_LISTENING_RANGE_END      11200
#define DEFAULT_SERVER_LOCAL_TARGET_PORT        22
#define DEFAULT_SERVER_MANAGER_PORT             2563
#define DEFAULT_SERVER_PASSWORD                 "HELLO123"
#define SERVER_PASSWORD_MAX_LENGTH              UTMP_LENGTH_MSG_AUTH
#define SERVER_NONBLOCKING_SOCKET_MAX_TIME      30
#define SERVER_NONBLOCKING_SOCKET_LINGER        10

/*
 *
 *  Client definitions
 *
 */

#define DEFAULT_CLIENT_LISTENING_RANGE_START    20200
#define DEFAULT_CLIENT_LISTENING_RANGE_END      21200
#define DEFAULT_CLIENT_APPLICATION_DEST_PORT    1234
#define DEFAULT_CLIENT_TUNNEL_TTL               8
#define CLIENT_TUNNEL_TTL_MIN                   2
#define CLIENT_TUNNEL_TTL_MAX                   300

/*
 *
 *  Server and client definitions
 *
 */

#define MANAGER_MAXWAITINGCONN                  10
#define MANAGER_RCVTMPBUFFLEN                   50
#define MANAGER_RCVBUFFLEN                      1000
/* Duration is also used to determine frequency of magic packet */
#define SOCKET_NONBLOCK_DURATION_US             50000

/*
 *
 *  UTMP Protocol specs
 *
 */

#define UTMP_PROTOCOL_VERSION    1

#define UTMP_MSG_AUTH            1
#define UTMP_MSG_CHG_PORT        2
#define UTMP_MSG_AUTH_OK         3
#define UTMP_MSG_AUTH_NOK        4
#define UTMP_MSG_CHG_PORT_OK     5
#define UTMP_MSG_CHG_PORT_NOK    6
#define UTMP_MSG_NEW_TUN         7
#define UTMP_MSG_NEW_TUN_OK      8
#define UTMP_MSG_NEW_TUN_NOK     9
#define UTMP_MSG_CLOSE_TUN      10
#define UTMP_MSG_CLOSE_TUN_ACK  11
#define UTMP_MSG_UNKNOWN        12

#define UTMP_MSG_FIELD_SIZE_SRVLISTENINGPORT    sizeof(uint16_t)
#define UTMP_MSG_FIELD_SIZE_CLTLISTENINGPORT    sizeof(uint16_t)
#define UTMP_MSG_FIELD_SIZE_CLTIP               sizeof(uint32_t)
#define UTMP_MSG_FIELD_SIZE_SRVPORTSTART        sizeof(uint16_t)
#define UTMP_MSG_FIELD_SIZE_SRVPORTEND          sizeof(uint16_t)

#define UTMP_LENGTH_PROTVERSION         1
#define UTMP_LENGTH_MSGTYPE             1
#define UTMP_LENGTH_MSG_AUTH            50
#define UTMP_LENGTH_MSG_CHG_PORT        UTMP_MSG_FIELD_SIZE_SRVLISTENINGPORT + UTMP_MSG_FIELD_SIZE_CLTLISTENINGPORT
#define UTMP_LENGTH_MSG_AUTH_OK         UTMP_MSG_FIELD_SIZE_SRVPORTSTART + UTMP_MSG_FIELD_SIZE_SRVPORTEND + UTMP_MSG_FIELD_SIZE_CLTIP
#define UTMP_LENGTH_MSG_AUTH_NOK        0
#define UTMP_LENGTH_MSG_CHG_PORT_OK     0
#define UTMP_LENGTH_MSG_CHG_PORT_NOK    0
#define UTMP_LENGTH_MSG_NEW_TUN         UTMP_MSG_FIELD_SIZE_SRVLISTENINGPORT + UTMP_MSG_FIELD_SIZE_CLTLISTENINGPORT
#define UTMP_LENGTH_MSG_NEW_TUN_OK      0
#define UTMP_LENGTH_MSG_NEW_TUN_NOK     0
#define UTMP_LENGTH_MSG_CLOSE_TUN       0
#define UTMP_LENGTH_MSG_CLOSE_TUN_ACK   0
#define UTMP_LENGTH_MSG_UNKNOWN         0

/*
 *
 *  Protocol specs
 *
 */

#define IP_HEADER_SIZE_MIN      20
#define TCP_SIZE_MAX            65535
#define TCP_HEADER_SIZE_MIN     20
#define UDP_SIZE_MAX            65535
#define UDP_HEADER_SIZE         8

/*
 *
 *  Program definitions
 *
 */

#define PROGRAM_NAME         "Anguille"
#define VERSION              "0.1"
#define HEXDUMP_COLS         8
#define VERBOSE_LEVEL_MAX    6
#define IPTABLES_RULE_lENGTH 80

#define UNUSED(x)            (void)(x)

#define RETURN_SUCCESS    0
#define RETURN_ERROR      1

#endif
