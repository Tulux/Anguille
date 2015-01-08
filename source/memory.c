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
#include <stdarg.h>
#include <arpa/inet.h>
#include <limits.h>
#include <errno.h>
#include <ctype.h>
#include <inttypes.h>
#include <string.h>
#include <signal.h>

#include "memory.h"

extern bool glb_signal_stop;
extern unsigned int glb_debug_level;

void error(const char* str, ...)
{
    va_list args;

    va_start(args, str);

    fprintf(stderr, "Fatal error:\t");
    vfprintf(stderr, str, args);
    fprintf(stderr, "\n");
    fprintf(stderr, "\t\tProgram is exiting...\n");

    va_end(args);

    exit(EXIT_FAILURE);
}

void warning(const char* str, ...)
{
    va_list args;

    va_start(args, str);

    fprintf(stderr, "Warning:\t");
    vfprintf(stderr, str, args);
    fprintf(stderr, "\n");

    va_end(args);
}

void info(const char* str, ...)
{
    va_list args;

    va_start(args, str);

    printf("Info:\t\t");
    vprintf(str, args);
    printf("\n");

    va_end(args);
}

bool debug(unsigned int level)
{
    if(glb_debug_level >= level)    return true;
    else                            return false;
}

void* s_malloc(size_t size)
{
    void* ptr = NULL;
    ptr = malloc(size);

    if(ptr == NULL)
    {
        error("s_malloc(): Unable to alloc");
    }

    return ptr;
}

void set_rcv_buffer(int32_t* sock)
{
    int32_t rcvbufSize;

    rcvbufSize = -1;
    socklen_t int32_tsizeof = sizeof(rcvbufSize);
    getsockopt(*sock, SOL_SOCKET, SO_RCVBUF, &rcvbufSize, &int32_tsizeof);

    if(debug(6))
        info("set_rcv_buffer(): current receive buffer size: %d", rcvbufSize);

    // Taille maxium pour le buffer
    rcvbufSize = INT_MAX/2;

    if( (setsockopt(*sock, SOL_SOCKET, SO_RCVBUF, &rcvbufSize ,sizeof(int32_t))) < 0 )
    {
        error("set_rcv_buffer(): setsockopt(): errno %d", errno);
    }
    else
    {
        rcvbufSize = -1;

        if(getsockopt(*sock, SOL_SOCKET, SO_RCVBUF, &rcvbufSize, &int32_tsizeof) == 0)
        {
            if(debug(6))
            {
                info("set_rcv_buffer(): new receive buffer size: %d", rcvbufSize);
                info("set_rcv_buffer(): Buffer maximum size value may be improved modifying net.core.rmem_max value!");
            }
        }
        else
        {
            error("set_rcv_buffer(): getsockopt(): error getting receive buffer value, errno %d", errno);
        }
    }
}

void print_hex_dump(void* mem, uint32_t len)
{
    uint32_t i, j;

    info("print_hex_dump()");

    for(i = 0; i < len + ((len % HEXDUMP_COLS) ? (HEXDUMP_COLS - len % HEXDUMP_COLS) : 0); i++)
    {
        /* print32_t offset */
        if(i % HEXDUMP_COLS == 0)
        {
                printf("0x%06x: ", i);
        }

        /* print32_t hex data */
        if(i < len)
        {
                printf("%02x ", 0xFF & ((uint8_t*)mem)[i]);
        }
        else /* end of block, just aligning for ASCII dump */
        {
                printf("   ");
        }

        /* print32_t ASCII dump */
        if(i % HEXDUMP_COLS == (HEXDUMP_COLS - 1))
        {
            for(j = i - (HEXDUMP_COLS - 1); j <= i; j++)
            {
                if(j >= len) /* end of block, not really print32_ting */
                {
                        putchar(' ');
                }
                else if(isprint(((uint8_t*)mem)[j])) /* print32_table char */
                {
                        putchar(0xFF & ((uint8_t*)mem)[j]);
                }
                else /* other char */
                {
                        putchar('.');
                }
            }
            putchar('\n');
        }
    }
}

Connection* new_connection(void)
{
    Connection* c;
    c = s_malloc(sizeof(Connection));
    init_connection(c);

    return c;
}

Sin* new_sin(void)
{
    Sin* s = (Sin*) s_malloc(sizeof(Sin));

    init_sin(s);

    return s;
}

void init_connection(Connection* c)
{
    c->sock = 0;
    init_sin(&c->dest);
}

void init_sin(Sin* s)
{
    memset(&s->saddrin, 0, sizeof(struct sockaddr_in));
    pthread_mutex_init( &(*s).lock , NULL);
}

void copySin(Sin* src, Sin* dst)
{
    pthread_mutex_lock(&dst->lock);
    pthread_mutex_lock(&src->lock);
    {
        memcpy(dst, src, sizeof(Sin));
    }
    pthread_mutex_unlock(&src->lock);
    pthread_mutex_unlock(&dst->lock);
}

bool u8cmp(uint8_t* a, uint8_t* b)
{
    int i;
    bool ret = 0;

    for(i = 0;; i++)
    {
        if(a[i] != b[i])
        {
            ret = 1;
            break;
        }

        if(a[i] == '\0')
            break;
    }

    return ret;
}

void sig_handler(int sign)
{
    if(sign == SIGINT)
    {
        if(debug(1))
            info("SIGINT received, closing program...");

        glb_signal_stop = true;
    }
    else
    {
        if(debug(4))
            warning("Bad signal reveived: %d", sign);
    }
}

void print_usage()
{
    printf("Copyright (C) 2015 Florent DELAHAYE <delahaye.florent@gmail.com>\n");
    printf("Anguille - client/server program establishing dynamic UDP tunnel to carry TCP traffic.\n");
    printf("\n");
    printf("Usage: anguille [-h] [-v level] [-d tunnel duration] [-r port range] [-t application port] [-p password] [-m manager port] [-i server ip] [-s server mode]\n");
    printf("\n");
    printf("Arguments:\n");
    printf("\n");
    printf("\t-h\tDisplay this help.\n");
    printf("\n");
    printf("\t-v\tSay some stuff. Level from 1 to %u.\n", VERBOSE_LEVEL_MAX);
    printf("\n");
    printf("\t-d\tClient side only. Set tunnel duration (second). From %u to %u.\n", CLIENT_TUNNEL_TTL_MIN, CLIENT_TUNNEL_TTL_MAX);
    printf("\n");
    printf("\t-r\tSelect UDP tunnel port-range usable. Syntax is startingport:endingport\n");
    printf("\n");
    printf("\t-t\tServer side: set target application\n");
    printf("\t\tClient side: set local port to listen\n");
    printf("\n");
    printf("\t-p\tServer side: set password protection.\n");
    printf("\t\tClient side: set server password to get access to tunnel.\n");
    printf("\t\t%d characters max length. Authorized characters: A-Za-z0-9_\n", UTMP_LENGTH_MSG_AUTH);
    printf("\n");
    printf("\t-m\tServer side: set TCP manager port.\n");
    printf("\t\tClient side: set remote TCP manager port.\n");
    printf("\n");
    printf("\t-i\tClient side only. Specify program mode as client by setting server IP (v4 only).\n");
    printf("\n");
    printf("\t-s\tServer side only. Specify program mode as server.\n");
    printf("\n");
    printf("Program mode must be specified using either -i or -s option!");
    printf("\n");
    printf("Example:\n");
    printf("Server: anguille -v -r 4500:4600 -p MY_PASS_123 -m 9870 -s\n");
    printf("Client: anguille -v -r 6200:6300 -p MY_PASS_123 -m 9870 -i 10.10.10.10\n");
}

void init_args(Args* args)
{
    args->opt_verbose     = false;
    args->opt_portrange   = false;
    args->opt_localport   = false;
    args->opt_password    = false;
    args->opt_managerport = false;
    args->opt_serverip    = false;

    args->verbose_level = 0;
    args->port_start    = 0;
    args->port_end      = 0;
    args->port_manager  = 0;
    args->port_local    = 0;
    args->password      = NULL;
    args->serverip      = NULL;
}

void print_args(const Args* args)
{
    info("print_args()");

    if(args->opt_verbose)     info("Verbose: %u", args->verbose_level);
    if(args->opt_portrange)   info("UDP port range: %u to %u", args->port_start, args->port_end);
    if(args->opt_localport)   info("Local port: %u", args->port_local);
    if(args->opt_password)    info("Password: %s", args->password);
    if(args->opt_managerport) info("Manager port: %u", args->port_manager);
    if(args->opt_serverip)    info("Server ip: %s", args->serverip);
    if(args->opt_servermode)  info("Server mode");
}

void arg_error(const char* arg)
{
    if(arg == NULL)  warning("Your arguments are invalid. Please refer to usage.");
    else             warning("Argument «%s» is invalid. Please refer to usage.", arg);

    printf("\n");
    print_usage();
    exit(EXIT_FAILURE);
}

void check_arg_verbose(Args* args, char* str)
{
    uint8_t level = (uint8_t) strtoul(str, NULL, 0);

    if(level < 1 || level > VERBOSE_LEVEL_MAX)
    {
        arg_error("verbose level");
    }

    args->opt_verbose   = true;
    args->verbose_level = level;
}

void check_arg_tunnelttl(Args* args, char* str)
{
    uint32_t ttl = (uint32_t) strtoul(str, NULL, 0);

    if(ttl < CLIENT_TUNNEL_TTL_MIN || ttl > CLIENT_TUNNEL_TTL_MAX)
    {
        arg_error("tunnel duration");
    }

    args->opt_tunnelttl = true;
    args->tunnel_ttl    = ttl;
}

void check_arg_portrange(Args* args, char* str)
{
    uint16_t p_start;
    uint16_t p_end;

    if(sscanf(str, "%"SCNu16":%"SCNu16, &p_start, &p_end) != 2 ||
       p_start >= p_end)
    {
        arg_error("port range");
    }

    args->opt_portrange = true;
    args->port_start    = p_start;
    args->port_end      = p_end;
}

void check_arg_localport(Args* args, char* str)
{
    uint16_t port;

    if(sscanf(str, "%"SCNu16, &port) != 1)
    {
        arg_error("local port");
    }

    args->opt_localport = true;
    args->port_local    = port;
}

void check_arg_password(Args* args, char* str)
{
    int i;
    int len = strlen(str);

    if(len > UTMP_LENGTH_MSG_AUTH)
    {
        arg_error("password");
    }

    for(i = 0; i < len; i++)
    {
        if((str[i] < 'a' || str[i] > 'z') &&
           (str[i] < 'A' || str[i] > 'Z') &&
           (str[i] < '0' || str[i] > '9') &&
           str[i] != '_'
           )
        {
            arg_error("password");
        }
    }

    args->opt_password = true;
    args->password     = str;
}

void check_arg_managerport(Args* args, char* str)
{
    uint16_t port;

    if(sscanf(str, "%"SCNu16, &port) != 1)
    {
        arg_error("manager port");
    }

    args->opt_managerport = true;
    args->port_manager    = port;
}

void check_arg_serverip(Args* args, char* str)
{
    int i;
    int len = strlen(str);
    struct sockaddr_in sa_test;

    if(len > 15)
    {
        arg_error("server ip");
    }

    for(i = 0; i < len; i++)
    {
        if((str[i] < '0' || str[i] > '9') &&
           str[i] != '.'
           )
        {
            arg_error("server ip");
        }
    }

    if(inet_pton(AF_INET, str, &(sa_test.sin_addr)) != 1)
    {
        arg_error("server ip");
    }

    args->opt_serverip = true;
    args->serverip     = str;
}

