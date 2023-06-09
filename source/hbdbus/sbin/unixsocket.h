/**
 ** unixsocket.h: Utilities for Unix Domain Socket.
 **
 ** Copyright (c) 2020 FMSoft (http://www.fmsoft.cn)
 **
 ** Author: Vincent Wei (https://github.com/VincentWei)
 **
 ** This file is part of HBDBus.
 **
 ** HBDBus is free software: you can redistribute it and/or modify
 ** it under the terms of the GNU General Public License as published by
 ** the Free Software Foundation, either version 3 of the License, or
 ** (at your option) any later version.
 **
 ** HBDBus is distributed in the hope that it will be useful,
 ** but WITHOUT ANY WARRANTY; without even the implied warranty of
 ** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 ** GNU General Public License for more details.
 ** You should have received a copy of the GNU General Public License
 ** along with this program.  If not, see http://www.gnu.org/licenses/.
 */

#ifndef _HBDBUS_UNIXSOCKET_H
#define _HBDBUS_UNIXSOCKET_H

#include <stdint.h>
#include <time.h>
#include <unistd.h>

#include "internal/list.h"
#include "internal/unixsocket-defs.h"

typedef enum USSTATUS {
    US_OK = 0,
    US_ERR = (1 << 0),
    US_CLOSE = (1 << 1),
    US_READING = (1 << 2),
    US_SENDING = (1 << 3),
    US_THROTTLING = (1 << 4),
    US_WATING_FOR_PAYLOAD = (1 << 5),
} USStatus;

typedef struct USPendingData_ {
    struct list_head list;

    /* the size of data */
    size_t  szdata;
    /* the size of sent */
    size_t  szsent;
    /* pointer to the pending data */
    unsigned char data[0];
} USPendingData;

/* A UnixSocket Client */
typedef struct USClient_
{
    /* the following fields are same as struct SocketClient_ */
    int             ct;         /* the connection type of the client */
    int             fd;         /* UNIX socket FD */
    struct timespec ts;         /* time got the first frame of the current packet */
    UpperEntity    *entity;     /* pointer to the uppper entity */

    unsigned int    status;     /* the status of the client */
    pid_t           pid;        /* client PID */
    uid_t           uid;        /* client UID */

    /* fields for pending data to write */
    size_t              sz_pending;
    struct list_head    pending;

    /* current frame header */
    USFrameHeader   header;

    /* fields for current reading packet */
    int         t_packet;   /* type of packet */
    int         padding_;
    uint32_t    sz_packet;  /* total size of current packet */
    uint32_t    sz_read;    /* read size of current packet */
    char*       packet;     /* packet data */

} USClient;

struct SockClient_;

/* The UnixSocket Server */
typedef struct USServer_
{
    int listener;
    int nr_clients;

    /* Callbacks */
    int (*on_accepted) (void *server, struct SockClient_ *client);
    int (*on_packet) (void *server, struct SockClient_ *client,
            const char* body, unsigned int sz_body, int type);
    int (*on_pending) (void *server, struct SockClient_* client);
    int (*on_close) (void *server, struct SockClient_ *client);
    void (*on_error) (void *server, struct SockClient_ *client, int err_code);

    const ServerConfig* config;
} USServer;

USServer *us_init (const ServerConfig* config);
int us_listen (USServer* server);
void us_stop (USServer *server);

USClient *us_handle_accept (USServer *server);
int us_handle_reads (USServer *server, USClient* usc);
int us_handle_writes (USServer *server, USClient *usc);
int us_remove_dangling_client (USServer * server, USClient *usc);
int us_cleanup_client (USServer* server, USClient* usc);

int us_ping_client (USServer* server, USClient* usc);
int us_close_client (USServer* server, USClient* usc);
int us_send_packet (USServer* server, USClient* usc,
        USOpcode op, const void *data, unsigned int sz);

#endif // for #ifndef _HBDBUS_UNIXSOCKET_H

