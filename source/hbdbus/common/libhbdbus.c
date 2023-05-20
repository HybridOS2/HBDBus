/*
** libhbdbus.c -- The code for HBDBus client.
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

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <assert.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/fcntl.h>
#include <sys/un.h>
#include <sys/time.h>

#include "hbdbus.h"
#include "internal/kvlist.h"
#include "internal/log.h"

struct _hbdbus_conn {
    int type;
    int fd;
    int last_ret_code;
    int padding_;

    char* srv_host_name;
    char* own_host_name;
    char* app_name;
    char* runner_name;

    struct kvlist method_list;
    struct kvlist bubble_list;
    struct kvlist call_list;
    struct kvlist subscribed_list;

    hbdbus_error_handler error_handler;
    hbdbus_event_handler system_event_handler;
    void *user_data;
};

typedef enum  {
    MHT_STRING  = 0,
    MHT_CONST_STRING = 1,
} method_handler_type;

struct method_handler_info {
    method_handler_type type;
    void* handler;
};

static int mhi_get_len (struct kvlist *kv, const void *data)
{
    (void)kv;
    (void)data;
    return sizeof (struct method_handler_info);
}

hbdbus_error_handler hbdbus_conn_get_error_handler (hbdbus_conn *conn)
{
    return conn->error_handler;
}

hbdbus_error_handler hbdbus_conn_set_error_handler (hbdbus_conn *conn,
        hbdbus_error_handler error_handler)
{
    hbdbus_error_handler old = conn->error_handler;
    conn->error_handler = error_handler;

    return old;
}

hbdbus_event_handler hbdbus_conn_get_system_event_handler (hbdbus_conn *conn)
{
    return conn->system_event_handler;
}

hbdbus_event_handler hbdbus_conn_set_system_event_handler (hbdbus_conn *conn,
        hbdbus_event_handler system_event_handler)
{
    hbdbus_event_handler old = conn->system_event_handler;
    conn->system_event_handler = system_event_handler;

    return old;
}

void *hbdbus_conn_get_user_data (hbdbus_conn *conn)
{
    return conn->user_data;
}

void *hbdbus_conn_set_user_data (hbdbus_conn *conn, void *user_data)
{
    void *old = conn->user_data;
    conn->user_data = user_data;

    return old;
}

int hbdbus_conn_get_last_ret_code (hbdbus_conn *conn)
{
    return conn->last_ret_code;
}

int hbdbus_conn_endpoint_name (hbdbus_conn* conn, char *buff)
{
    if (conn->own_host_name && conn->app_name && conn->runner_name) {
        return purc_assemble_endpoint_name (conn->own_host_name,
                conn->app_name, conn->runner_name, buff);
    }

    return 0;
}

char *hbdbus_conn_endpoint_name_alloc (hbdbus_conn* conn)
{
    if (conn->own_host_name && conn->app_name && conn->runner_name) {
        return purc_assemble_endpoint_name_alloc (conn->own_host_name,
                conn->app_name, conn->runner_name);
    }

    return NULL;
}

/* return NULL for error */
static char* read_text_payload_from_us (int fd, int* len)
{
    ssize_t n = 0;
    USFrameHeader header;
    char *payload = NULL;

    n = read (fd, &header, sizeof (USFrameHeader));
    if (n > 0) {
        if (header.op == US_OPCODE_TEXT &&
                header.sz_payload > 0) {
            payload = malloc (header.sz_payload + 1);
        }
        else {
            HLOG_WARN ("Bad payload type (%d) and length (%d)\n",
                    header.op, header.sz_payload);
            return NULL;  /* must not the challenge code */
        }
    }

    if (payload == NULL) {
        HLOG_ERR ("Failed to allocate memory for payload.\n");
        return NULL;
    }
    else {
        n = read (fd, payload, header.sz_payload);
        if (n < header.sz_payload) {
            HLOG_ERR ("Failed to read payload.\n");
            goto failed;
        }

        payload [header.sz_payload] = 0;
        if (len)
            *len = header.sz_payload;
    }

    return payload;

failed:
    free (payload);
    return NULL;
}

static int get_challenge_code (hbdbus_conn *conn, char **challenge)
{
    int err_code = 0;
    char* payload;
    int len;
    purc_variant_t jo = NULL, jo_tmp;
    const char *ch_code = NULL;

    // TODO: handle WebSocket connection
    payload = read_text_payload_from_us (conn->fd, &len);
    if (payload == NULL) {
        err_code = HBDBUS_EC_NOMEM;
        goto failed;
    }

    jo = purc_variant_make_from_json_string(payload, len);
    if (jo == NULL || !purc_variant_is_object(jo)) {
        err_code = HBDBUS_EC_BAD_PACKET;
        goto failed;
    }

    free (payload);
    payload = NULL;

    if ((jo_tmp = purc_variant_object_get_by_ckey(jo, "packetType"))) {
        const char *pack_type;
        pack_type = purc_variant_get_string_const (jo_tmp);

        if (strcasecmp (pack_type, "error") == 0) {
            const char* prot_name = HBDBUS_NOT_AVAILABLE;
            int prot_ver = 0, ret_code = 0;
            const char *ret_msg = HBDBUS_NOT_AVAILABLE, *extra_msg = HBDBUS_NOT_AVAILABLE;

            HLOG_WARN ("Refued by server:\n");
            if ((jo_tmp = purc_variant_object_get_by_ckey(jo, "protocolName"))) {
                prot_name = purc_variant_get_string_const(jo_tmp);
            }

            if ((jo_tmp = purc_variant_object_get_by_ckey(jo, "protocolVersion"))) {
                purc_variant_cast_to_int32(jo_tmp, &prot_ver, true);
            }
            HLOG_WARN ("  Protocol: %s/%d\n", prot_name, prot_ver);

            if ((jo_tmp = purc_variant_object_get_by_ckey(jo, "retCode"))) {
                purc_variant_cast_to_int32(jo_tmp, &ret_code, true);
            }
            if ((jo_tmp = purc_variant_object_get_by_ckey(jo, "retMsg"))) {
                ret_msg = purc_variant_get_string_const(jo_tmp);
            }
            if ((jo_tmp = purc_variant_object_get_by_ckey(jo, "extraMsg"))) {
                extra_msg = purc_variant_get_string_const(jo_tmp);
            }
            HLOG_WARN ("  Error Info: %d (%s): %s\n", ret_code, ret_msg, extra_msg);

            err_code = HBDBUS_EC_SERVER_REFUSED;
            goto failed;
        }
        else if (strcasecmp (pack_type, "auth") == 0) {
            const char *prot_name = HBDBUS_NOT_AVAILABLE;
            int prot_ver = 0;

            if ((jo_tmp = purc_variant_object_get_by_ckey(jo, "challengeCode"))) {
                ch_code = purc_variant_get_string_const(jo_tmp);
            }

            if ((jo_tmp = purc_variant_object_get_by_ckey(jo, "protocolName"))) {
                prot_name = purc_variant_get_string_const (jo_tmp);
            }
            if ((jo_tmp = purc_variant_object_get_by_ckey(jo, "protocolVersion"))) {
                purc_variant_cast_to_int32(jo_tmp, &prot_ver, true);
            }

            if (ch_code == NULL) {
                HLOG_WARN ("Null challenge code\n");
                err_code = HBDBUS_EC_BAD_PACKET;
                goto failed;
            }
            else if (strcasecmp (prot_name, HBDBUS_PROTOCOL_NAME) ||
                    prot_ver < HBDBUS_PROTOCOL_VERSION) {
                HLOG_WARN ("Protocol not matched: %s/%d\n", prot_name, prot_ver);
                err_code = HBDBUS_EC_PROTOCOL;
                goto failed;
            }
        }
    }
    else {
        HLOG_WARN ("No packetType field\n");
        err_code = HBDBUS_EC_BAD_PACKET;
        goto failed;
    }

    assert (ch_code);
    *challenge = strdup (ch_code);
    if (*challenge == NULL)
        err_code = HBDBUS_EC_NOMEM;

failed:
    if (jo)
        purc_variant_unref(jo);
    if (payload)
        free(payload);

    return err_code;
}

static int send_auth_info (hbdbus_conn *conn, const char* ch_code)
{
    int err_code = 0, n;
    unsigned char* sig;
    unsigned int sig_len;
    char* enc_sig = NULL;
    unsigned int enc_sig_len;
    char buff [HBDBUS_DEF_PACKET_BUFF_SIZE];

    err_code = hbdbus_sign_data (conn->app_name,
            (const unsigned char *)ch_code, strlen (ch_code),
            &sig, &sig_len);
    if (err_code) {
        return err_code;
    }

    enc_sig_len = pcutils_b64_encoded_length(sig_len);
    enc_sig = malloc(enc_sig_len);
    if (enc_sig == NULL) {
        err_code = HBDBUS_EC_NOMEM;
        goto failed;
    }

    // When encode the signature in base64 or exadecimal notation,
    // there will be no any '"' and '\' charecters.
    pcutils_b64_encode(sig, sig_len, enc_sig, enc_sig_len);

    free(sig);
    sig = NULL;

    n = snprintf(buff, sizeof (buff), 
            "{"
            "\"packetType\":\"auth\","
            "\"protocolName\":\"%s\","
            "\"protocolVersion\":%d,"
            "\"hostName\":\"%s\","
            "\"appName\":\"%s\","
            "\"runnerName\":\"%s\","
            "\"signature\":\"%s\","
            "\"encodedIn\":\"base64\""
            "}",
            HBDBUS_PROTOCOL_NAME, HBDBUS_PROTOCOL_VERSION,
            conn->own_host_name, conn->app_name, conn->runner_name, enc_sig);

    if (n < 0) {
        err_code = HBDBUS_EC_UNEXPECTED;
        goto failed;
    }
    else if ((size_t)n >= sizeof (buff)) {
        HLOG_ERR ("Too small buffer for signature (%s) in send_auth_info.\n", enc_sig);
        err_code = HBDBUS_EC_TOO_SMALL_BUFF;
        goto failed;
    }

    if (hbdbus_send_text_packet (conn, buff, n)) {
        HLOG_ERR ("Failed to send text packet to HBDBus server in send_auth_info.\n");
        err_code = HBDBUS_EC_IO;
        goto failed;
    }

    free (enc_sig);
    return 0;

failed:
    if (sig)
        free (sig);
    if (enc_sig)
        free (enc_sig);
    return err_code;
}

static void on_lost_event_generator (hbdbus_conn* conn,
        const char* from_endpoint, const char* from_bubble,
        const char* bubble_data)
{
    (void)from_endpoint;
    (void)from_bubble;
    purc_variant_t jo = NULL, jo_tmp;
    const char *endpoint_name = NULL;
    const char* event_name;
    void *next, *data;

    jo = purc_variant_make_from_json_string(bubble_data, strlen(bubble_data));
    if (jo == NULL) {
        HLOG_ERR ("Failed to parse bubble data for bubble `LOSTEVENTGENERATOR`\n");
        return;
    }

    if ((jo_tmp = purc_variant_object_get_by_ckey(jo, "endpointName")) &&
            (endpoint_name = purc_variant_get_string_const(jo_tmp))) {
    }
    else {
        HLOG_ERR ("Fatal error: no endpointName field in the packet!\n");
        return;
    }

    kvlist_for_each_safe(&conn->subscribed_list, event_name, next, data) {
        const char* end_of_endpoint = strrchr(event_name, '/');

        if (strncasecmp(event_name, endpoint_name, end_of_endpoint - event_name) == 0) {
            HLOG_INFO ("Matched an event (%s) in subscribed events for %s\n",
                    event_name, endpoint_name);

            kvlist_delete(&conn->subscribed_list, event_name);
        }
    }
}

static void on_lost_event_bubble (hbdbus_conn* conn,
        const char* from_endpoint, const char* from_bubble,
        const char* bubble_data)
{
    (void)from_endpoint;
    (void)from_bubble;
    int n;
    purc_variant_t jo = NULL, jo_tmp;
    const char *endpoint_name = NULL;
    const char *bubble_name = NULL;
    char event_name [HBDBUS_LEN_ENDPOINT_NAME + HBDBUS_LEN_BUBBLE_NAME + 2];

    jo = purc_variant_make_from_json_string(bubble_data, strlen(bubble_data));
    if (jo == NULL) {
        HLOG_ERR ("Failed to parse bubble data for bubble `LOSTEVENTBUBBLE`\n");
        return;
    }

    if ((jo_tmp = purc_variant_object_get_by_ckey(jo, "endpointName")) &&
            (endpoint_name = purc_variant_get_string_const(jo_tmp))) {
    }
    else {
        HLOG_ERR ("Fatal error: no endpointName in the packet!\n");
        return;
    }

    if ((jo_tmp = purc_variant_object_get_by_ckey(jo, "bubbleName")) &&
            (bubble_name = purc_variant_get_string_const(jo_tmp))) {
    }
    else {
        HLOG_ERR ("Fatal error: no bubbleName in the packet!\n");
        return;
    }

    n = purc_name_tolower_copy(endpoint_name, event_name, HBDBUS_LEN_ENDPOINT_NAME);
    event_name [n++] = '/';
    event_name [n] = '\0';
    strcpy(event_name + n, bubble_name);
    if (!kvlist_get(&conn->subscribed_list, event_name))
        return;

    kvlist_delete(&conn->subscribed_list, event_name);
}

/* add systen event handlers here */
static int on_auth_passed (hbdbus_conn* conn, const purc_variant_t jo)
{
    int n;
    purc_variant_t jo_tmp;
    char event_name [HBDBUS_LEN_ENDPOINT_NAME + HBDBUS_LEN_BUBBLE_NAME + 2];
    const char* srv_host_name;
    const char* own_host_name;
    hbdbus_event_handler event_handler;

    if ((jo_tmp = purc_variant_object_get_by_ckey(jo, "serverHostName")) &&
            (srv_host_name = purc_variant_get_string_const(jo_tmp))) {
        if (conn->srv_host_name)
            free (conn->srv_host_name);

        conn->srv_host_name = strdup (srv_host_name);
    }
    else {
        HLOG_ERR ("Fatal error: no serverHostName in authPassed packet!\n");
        return HBDBUS_EC_PROTOCOL;
    }

    if ((jo_tmp = purc_variant_object_get_by_ckey(jo, "reassignedHostName")) &&
            (own_host_name = purc_variant_get_string_const(jo_tmp))) {
        if (conn->own_host_name)
            free (conn->own_host_name);

        conn->own_host_name = strdup (own_host_name);
    }
    else {
        HLOG_ERR ("Fatal error: no reassignedHostName in authPassed packet!\n");
        return HBDBUS_EC_PROTOCOL;
    }

    n = purc_assemble_endpoint_name (srv_host_name,
            HBDBUS_APP_HBDBUS, HBDBUS_RUNNER_BUILITIN, event_name);
    event_name [n++] = '/';
    event_name [n] = '\0';
    strcat (event_name, "LOSTEVENTGENERATOR");

    event_handler = on_lost_event_generator;
    if (!kvlist_set (&conn->subscribed_list, event_name, &event_handler)) {
        HLOG_ERR ("Failed to register callback for system event `LOSTEVENTGENERATOR`!\n");
        return HBDBUS_EC_UNEXPECTED;
    }

    n = purc_assemble_endpoint_name (srv_host_name,
            HBDBUS_APP_HBDBUS, HBDBUS_RUNNER_BUILITIN, event_name);
    event_name [n++] = '/';
    event_name [n] = '\0';
    strcat (event_name, "LOSTEVENTBUBBLE");

    event_handler = on_lost_event_bubble;
    if (!kvlist_set (&conn->subscribed_list, event_name, &event_handler)) {
        HLOG_ERR ("Failed to register callback for system event `LOSTEVENTBUBBLE`!\n");
        return HBDBUS_EC_UNEXPECTED;
    }

    return 0;
}

static int check_auth_result (hbdbus_conn* conn)
{
    char *packet;
    unsigned int data_len;
    purc_variant_t jo;
    int retval, err_code;

    err_code = hbdbus_read_packet_alloc (conn, &packet, &data_len);
    if (err_code) {
        HLOG_ERR ("Failed to read packet\n");
        return err_code;
    }

    if (data_len == 0) {
        HLOG_ERR ("Unexpected\n");
        return HBDBUS_EC_UNEXPECTED;
    }

    retval = hbdbus_json_packet_to_object (packet, data_len, &jo);
    free (packet);

    if (retval < 0) {
        HLOG_ERR ("Failed to parse JSON packet\n");
        err_code = HBDBUS_EC_BAD_PACKET;
    }
    else if (retval == JPT_AUTH_PASSED) {
        HLOG_WARN ("Passed the authentication\n");
        err_code = on_auth_passed (conn, jo);
        HLOG_INFO ("return value of on_auth_passed: %d\n", retval);
    }
    else if (retval == JPT_AUTH_FAILED) {
        HLOG_WARN ("Failed the authentication\n");
        err_code = HBDBUS_EC_AUTH_FAILED;
    }
    else if (retval == JPT_ERROR) {
        HLOG_WARN ("Got an error\n");
        err_code = HBDBUS_EC_SERVER_REFUSED;
    }
    else {
        HLOG_WARN ("Got an unexpected packet: %d\n", retval);
        err_code = HBDBUS_EC_UNEXPECTED;
    }

    purc_variant_unref(jo);
    return err_code;
}

#define CLI_PATH    "/var/tmp/"
#define CLI_PERM    S_IRWXU

/* returns fd if all OK, -1 on error */
int hbdbus_connect_via_unix_socket (const char* path_to_socket,
        const char* app_name, const char* runner_name, hbdbus_conn** conn)
{
    int fd, len, err_code = HBDBUS_EC_BAD_CONNECTION;
    struct sockaddr_un unix_addr;
    char peer_name [33];
    char *ch_code = NULL;

    if ((*conn = calloc (1, sizeof (hbdbus_conn))) == NULL) {
        HLOG_ERR ("Failed to callocate space for connection: %s\n",
                strerror (errno));
        return HBDBUS_EC_NOMEM;
    }

    /* create a Unix domain stream socket */
    if ((fd = socket (AF_UNIX, SOCK_STREAM, 0)) < 0) {
        HLOG_ERR ("Failed to call `socket` in hbdbus_connect_via_unix_socket: %s\n",
                strerror (errno));
        return HBDBUS_EC_IO;
    }

    {
        pcutils_md5_ctxt ctx;
        unsigned char md5_digest[16];

        pcutils_md5_begin(&ctx);
        pcutils_md5_hash(&ctx, app_name, strlen(app_name));
        pcutils_md5_hash(&ctx, "/", 1);
        pcutils_md5_hash(&ctx, runner_name, strlen(runner_name));
        pcutils_md5_end(&ctx, md5_digest);
        pcutils_bin2hex(md5_digest, 16, peer_name, false);
    }

    /* fill socket address structure w/our address */
    memset(&unix_addr, 0, sizeof(unix_addr));
    unix_addr.sun_family = AF_UNIX;
    /* On Linux sun_path is 108 bytes in size */
    sprintf (unix_addr.sun_path, "%s%s-%05d", CLI_PATH, peer_name, getpid());
    len = sizeof (unix_addr.sun_family) + strlen (unix_addr.sun_path) + 1;

    unlink (unix_addr.sun_path);        /* in case it already exists */
    if (bind (fd, (struct sockaddr *) &unix_addr, len) < 0) {
        HLOG_ERR ("Failed to call `bind` in hbdbus_connect_via_unix_socket: %s\n",
                strerror (errno));
        goto error;
    }
    if (chmod (unix_addr.sun_path, CLI_PERM) < 0) {
        HLOG_ERR ("Failed to call `chmod` in hbdbus_connect_via_unix_socket: %s\n",
                strerror (errno));
        goto error;
    }

    /* fill socket address structure w/server's addr */
    memset (&unix_addr, 0, sizeof(unix_addr));
    unix_addr.sun_family = AF_UNIX;
    strcpy (unix_addr.sun_path, path_to_socket);
    len = sizeof (unix_addr.sun_family) + strlen (unix_addr.sun_path) + 1;

    if (connect (fd, (struct sockaddr *) &unix_addr, len) < 0) {
        HLOG_ERR ("Failed to call `connect` in hbdbus_connect_via_unix_socket: %s\n",
                strerror (errno));
        goto error;
    }

    (*conn)->type = CT_UNIX_SOCKET;
    (*conn)->fd = fd;
    (*conn)->srv_host_name = NULL;
    (*conn)->own_host_name = strdup (HBDBUS_LOCALHOST);
    (*conn)->app_name = strdup (app_name);
    (*conn)->runner_name = strdup (runner_name);

    kvlist_init (&(*conn)->method_list, mhi_get_len, true);
    kvlist_init (&(*conn)->bubble_list, NULL, true);
    kvlist_init (&(*conn)->call_list, NULL, false);
    kvlist_init (&(*conn)->subscribed_list, NULL, false);

    /* try to read challenge code */
    if ((err_code = get_challenge_code (*conn, &ch_code)))
        goto error;

    if ((err_code = send_auth_info (*conn, ch_code))) {
        goto error;
    }

    free (ch_code);
    ch_code = NULL;

    if ((err_code = check_auth_result (*conn))) {
        goto error;
    }

    return fd;

error:
    close (fd);

    if (ch_code)
        free (ch_code);
    if ((*conn)->own_host_name)
       free ((*conn)->own_host_name);
    if ((*conn)->app_name)
       free ((*conn)->app_name);
    if ((*conn)->runner_name)
       free ((*conn)->runner_name);
    free (*conn);
    *conn = NULL;

    return err_code;
}

int hbdbus_connect_via_web_socket (const char* host_name, int port,
        const char* app_name, const char* runner_name, hbdbus_conn** conn)
{
    (void)host_name;
    (void)port;
    (void)app_name;
    (void)runner_name;
    (void)conn;
    return HBDBUS_EC_NOT_IMPLEMENTED;
}

const char* hbdbus_conn_srv_host_name (hbdbus_conn* conn)
{
    (void)conn;
    return conn->srv_host_name;
}

const char* hbdbus_conn_own_host_name (hbdbus_conn* conn)
{
    (void)conn;
    return conn->own_host_name;
}

const char* hbdbus_conn_app_name (hbdbus_conn* conn)
{
    (void)conn;
    return conn->app_name;
}

const char* hbdbus_conn_runner_name (hbdbus_conn* conn)
{
    (void)conn;
    return conn->runner_name;
}

int hbdbus_conn_socket_fd (hbdbus_conn* conn)
{
    return conn->fd;
}

int hbdbus_conn_socket_type (hbdbus_conn* conn)
{
    return conn->type;
}

static inline int conn_read (int fd, void *buff, ssize_t sz)
{
    if (read (fd, buff, sz) == sz) {
        return 0;
    }

    return HBDBUS_EC_IO;
}

static inline int conn_write (int fd, const void *data, ssize_t sz)
{
    if (write (fd, data, sz) == sz) {
        return 0;
    }

    return HBDBUS_EC_IO;
}

int hbdbus_free_connection (hbdbus_conn* conn)
{
    assert (conn);

    if (conn->srv_host_name)
        free (conn->srv_host_name);
    free (conn->own_host_name);
    free (conn->app_name);
    free (conn->runner_name);
    close (conn->fd);

    kvlist_free (&conn->method_list);
    kvlist_free (&conn->bubble_list);
    kvlist_free (&conn->call_list);
    kvlist_free (&conn->subscribed_list);

    free (conn);

    return 0;
}

int hbdbus_disconnect (hbdbus_conn* conn)
{
    int err_code = 0;

    if (conn->type == CT_UNIX_SOCKET) {
        USFrameHeader header;

        header.op = US_OPCODE_CLOSE;
        header.fragmented = 0;
        header.sz_payload = 0;
        if (conn_write (conn->fd, &header, sizeof (USFrameHeader))) {
            HLOG_ERR ("Error when wirting to Unix Socket: %s\n", strerror (errno));
            err_code = HBDBUS_EC_IO;
        }
    }
    else if (conn->type == CT_WEB_SOCKET) {
        /* TODO */
        err_code = HBDBUS_EC_NOT_IMPLEMENTED;
    }
    else {
        err_code = HBDBUS_EC_INVALID_VALUE;
    }

    hbdbus_free_connection (conn);

    return err_code;
}

int hbdbus_read_packet (hbdbus_conn* conn, char *packet_buf, unsigned int *packet_len)
{
    unsigned int offset;
    int err_code = 0;

    if (conn->type == CT_UNIX_SOCKET) {
        USFrameHeader header;

        if (conn_read (conn->fd, &header, sizeof (USFrameHeader))) {
            HLOG_ERR ("Failed to read frame header from Unix socket\n");
            err_code = HBDBUS_EC_IO;
            goto done;
        }

        if (header.op == US_OPCODE_PONG) {
            // TODO
            *packet_len = 0;
            return 0;
        }
        else if (header.op == US_OPCODE_PING) {
            header.op = US_OPCODE_PONG;
            header.sz_payload = 0;
            if (conn_write (conn->fd, &header, sizeof (USFrameHeader))) {
                err_code = HBDBUS_EC_IO;
                goto done;
            }
            *packet_len = 0;
            return 0;
        }
        else if (header.op == US_OPCODE_CLOSE) {
            HLOG_WARN ("Peer closed\n");
            err_code = HBDBUS_EC_CLOSED;
            goto done;
        }
        else if (header.op == US_OPCODE_TEXT ||
                header.op == US_OPCODE_BIN) {
            unsigned int left;

            if (header.fragmented > HBDBUS_MAX_INMEM_PAYLOAD_SIZE) {
                err_code = HBDBUS_EC_TOO_LARGE;
                goto done;
            }

            int is_text;
            if (header.op == US_OPCODE_TEXT) {
                is_text = 1;
            }
            else {
                is_text = 0;
            }

            if (conn_read (conn->fd, packet_buf, header.sz_payload)) {
                HLOG_ERR ("Failed to read packet from Unix socket\n");
                err_code = HBDBUS_EC_IO;
                goto done;
            }

            if (header.fragmented > header.sz_payload) {
                left = header.fragmented - header.sz_payload;
            }
            else
                left = 0;
            offset = header.sz_payload;
            while (left > 0) {
                if (conn_read (conn->fd, &header, sizeof (USFrameHeader))) {
                    HLOG_ERR ("Failed to read frame header from Unix socket\n");
                    err_code = HBDBUS_EC_IO;
                    goto done;
                }

                if (header.op != US_OPCODE_CONTINUATION &&
                        header.op != US_OPCODE_END) {
                    HLOG_ERR ("Not a continuation frame\n");
                    err_code = HBDBUS_EC_PROTOCOL;
                    goto done;
                }

                if (conn_read (conn->fd, packet_buf + offset, header.sz_payload)) {
                    HLOG_ERR ("Failed to read packet from Unix socket\n");
                    err_code = HBDBUS_EC_IO;
                    goto done;
                }

                offset += header.sz_payload;
                left -= header.sz_payload;

                if (header.op == US_OPCODE_END) {
                    break;
                }
            }

            if (is_text) {
                ((char *)packet_buf) [offset] = '\0';
                *packet_len = offset + 1;
            }
            else {
                *packet_len = offset;
            }
        }
        else {
            HLOG_ERR ("Bad packet op code: %d\n", header.op);
            err_code = HBDBUS_EC_PROTOCOL;
        }
    }
    else if (conn->type == CT_WEB_SOCKET) {
        /* TODO */
        err_code = HBDBUS_EC_NOT_IMPLEMENTED;
    }
    else {
        err_code = HBDBUS_EC_INVALID_VALUE;
    }

done:
    return err_code;
}

static inline void my_log (const char* str)
{
    ssize_t n = write (2, str, strlen (str));
    n = n & n;
}

int hbdbus_read_packet_alloc (hbdbus_conn* conn, char **packet, unsigned int *packet_len)
{
    char *packet_buf = NULL;
    int err_code = 0;

    if (conn->type == CT_UNIX_SOCKET) {
        USFrameHeader header;

        if (conn_read (conn->fd, &header, sizeof (USFrameHeader))) {
            HLOG_ERR ("Failed to read frame header from Unix socket\n");
            err_code = HBDBUS_EC_IO;
            goto done;
        }

        if (header.op == US_OPCODE_PONG) {
            // TODO
            *packet = NULL;
            *packet_len = 0;
            return 0;
        }
        else if (header.op == US_OPCODE_PING) {
            header.op = US_OPCODE_PONG;
            header.sz_payload = 0;
            if (conn_write (conn->fd, &header, sizeof (USFrameHeader))) {
                err_code = HBDBUS_EC_IO;
                goto done;
            }

            *packet = NULL;
            *packet_len = 0;
            return 0;
        }
        else if (header.op == US_OPCODE_CLOSE) {
            HLOG_WARN ("Peer closed\n");
            err_code = HBDBUS_EC_CLOSED;
            goto done;
        }
        else if (header.op == US_OPCODE_TEXT ||
                header.op == US_OPCODE_BIN) {
            unsigned int total_len, left;
            unsigned int offset;
            int is_text;

            if (header.fragmented > HBDBUS_MAX_INMEM_PAYLOAD_SIZE) {
                err_code = HBDBUS_EC_TOO_LARGE;
                goto done;
            }

            if (header.op == US_OPCODE_TEXT) {
                is_text = 1;
            }
            else {
                is_text = 0;
            }

            if (header.fragmented > header.sz_payload) {
                total_len = header.fragmented;
                offset = header.sz_payload;
                left = total_len - header.sz_payload;
            }
            else {
                total_len = header.sz_payload;
                offset = header.sz_payload;
                left = 0;
            }

            if ((packet_buf = malloc (total_len + 1)) == NULL) {
                err_code = HBDBUS_EC_NOMEM;
                goto done;
            }

            if (conn_read (conn->fd, packet_buf, header.sz_payload)) {
                HLOG_ERR ("Failed to read packet from Unix socket\n");
                err_code = HBDBUS_EC_IO;
                goto done;
            }

            while (left > 0) {
                if (conn_read (conn->fd, &header, sizeof (USFrameHeader))) {
                    HLOG_ERR ("Failed to read frame header from Unix socket\n");
                    err_code = HBDBUS_EC_IO;
                    goto done;
                }

                if (header.op != US_OPCODE_CONTINUATION &&
                        header.op != US_OPCODE_END) {
                    HLOG_ERR ("Not a continuation frame\n");
                    err_code = HBDBUS_EC_PROTOCOL;
                    goto done;
                }

                if (conn_read (conn->fd, packet_buf + offset, header.sz_payload)) {
                    HLOG_ERR ("Failed to read packet from Unix socket\n");
                    err_code = HBDBUS_EC_IO;
                    goto done;
                }

                left -= header.sz_payload;
                offset += header.sz_payload;
                if (header.op == US_OPCODE_END) {
                    break;
                }
            }

            if (is_text) {
                ((char *)packet_buf) [offset] = '\0';
                *packet_len = offset + 1;
            }
            else {
                *packet_len = offset;
            }

            goto done;
        }
        else {
            HLOG_ERR ("Bad packet op code: %d\n", header.op);
            err_code = HBDBUS_EC_PROTOCOL;
            goto done;
        }
    }
    else if (conn->type == CT_WEB_SOCKET) {
        /* TODO */
        err_code = HBDBUS_EC_NOT_IMPLEMENTED;
        goto done;
    }
    else {
        assert (0);
        err_code = HBDBUS_EC_INVALID_VALUE;
        goto done;
    }

done:
    if (err_code) {
        if (packet_buf)
            free (packet_buf);
        *packet = NULL;
        return err_code;
    }

    *packet = packet_buf;
    return 0;
}

int hbdbus_send_text_packet (hbdbus_conn* conn, const char* text, unsigned int len)
{
    int retv = 0;

    if (conn->type == CT_UNIX_SOCKET) {
        USFrameHeader header;

        if (len > HBDBUS_MAX_FRAME_PAYLOAD_SIZE) {
            unsigned int left = len;

            do {
                if (left == len) {
                    header.op = US_OPCODE_TEXT;
                    header.fragmented = len;
                    header.sz_payload = HBDBUS_MAX_FRAME_PAYLOAD_SIZE;
                    left -= HBDBUS_MAX_FRAME_PAYLOAD_SIZE;
                }
                else if (left > HBDBUS_MAX_FRAME_PAYLOAD_SIZE) {
                    header.op = US_OPCODE_CONTINUATION;
                    header.fragmented = 0;
                    header.sz_payload = HBDBUS_MAX_FRAME_PAYLOAD_SIZE;
                    left -= HBDBUS_MAX_FRAME_PAYLOAD_SIZE;
                }
                else {
                    header.op = US_OPCODE_END;
                    header.fragmented = 0;
                    header.sz_payload = left;
                    left = 0;
                }

                if (conn_write (conn->fd, &header, sizeof (USFrameHeader)) == 0) {
                    retv = conn_write (conn->fd, text, header.sz_payload);
                    text += header.sz_payload;
                }

            } while (left > 0 && retv == 0);
        }
        else {
            header.op = US_OPCODE_TEXT;
            header.fragmented = 0;
            header.sz_payload = len;
            if (conn_write (conn->fd, &header, sizeof (USFrameHeader)) == 0)
                retv = conn_write (conn->fd, text, len);
        }
    }
    else if (conn->type == CT_WEB_SOCKET) {
        /* TODO */
        retv = HBDBUS_EC_NOT_IMPLEMENTED;
    }
    else
        retv = HBDBUS_EC_INVALID_VALUE;

    return retv;
}

int hbdbus_ping_server (hbdbus_conn* conn)
{
    int err_code = 0;

    if (conn->type == CT_UNIX_SOCKET) {
        USFrameHeader header;

        header.op = US_OPCODE_PING;
        header.fragmented = 0;
        header.sz_payload = 0;
        if (conn_write (conn->fd, &header, sizeof (USFrameHeader))) {
            HLOG_ERR ("Error when wirting to Unix Socket: %s\n", strerror (errno));
            err_code = HBDBUS_EC_IO;
        }
    }
    else if (conn->type == CT_WEB_SOCKET) {
        /* TODO */
        err_code = HBDBUS_EC_NOT_IMPLEMENTED;
    }
    else {
        err_code = HBDBUS_EC_INVALID_VALUE;
    }

    return err_code;
}

static int wait_for_specific_call_result_packet (hbdbus_conn* conn, 
        const char* call_id, int time_expected, int *ret_code, char** ret_value);

int hbdbus_call_procedure_and_wait (hbdbus_conn* conn, const char* endpoint,
        const char* method_name, const char* method_param,
        int time_expected, int *ret_code, char** ret_value)
{
    int n;
    char call_id [HBDBUS_LEN_UNIQUE_ID + 1];
    char buff [HBDBUS_DEF_PACKET_BUFF_SIZE];
    char* escaped_param;

    if (!hbdbus_is_valid_method_name (method_name))
        return HBDBUS_EC_INVALID_VALUE;

    escaped_param = pcutils_escape_string_for_json (method_param);
    if (escaped_param == NULL)
        return HBDBUS_EC_NOMEM;

    purc_generate_unique_id (call_id, "call");

    n = snprintf (buff, sizeof (buff), 
            "{"
            "\"packetType\": \"call\","
            "\"callId\": \"%s\","
            "\"toEndpoint\": \"%s\","
            "\"toMethod\": \"%s\","
            "\"expectedTime\": %d,"
            "\"parameter\": \"%s\""
            "}",
            call_id,
            endpoint,
            method_name,
            time_expected,
            escaped_param);
    free (escaped_param);

    if (n < 0) {
        return HBDBUS_EC_UNEXPECTED;
    }
    else if ((size_t)n >= sizeof (buff)) {
        return HBDBUS_EC_TOO_SMALL_BUFF;
    }

    if (hbdbus_send_text_packet (conn, buff, n)) {
        return HBDBUS_EC_IO;
    }

    return wait_for_specific_call_result_packet (conn,
            call_id, time_expected, ret_code, ret_value);
}

static int my_register_procedure (hbdbus_conn* conn, const char* method_name,
        const char* for_host, const char* for_app,
        const struct method_handler_info* mhi)
{
    int n, err_code, ret_code;
    char endpoint_name [HBDBUS_LEN_ENDPOINT_NAME + 1];
    char param_buff [HBDBUS_MIN_PACKET_BUFF_SIZE];
    char* ret_value;

    if (!hbdbus_is_valid_method_name (method_name))
        return HBDBUS_EC_INVALID_VALUE;

    if (for_host == NULL) for_host = "*";
    if (!hbdbus_is_valid_wildcard_pattern_list (for_host)) {
        return HBDBUS_EC_INVALID_VALUE;
    }

    if (for_app == NULL) for_app = "*";
    if (!hbdbus_is_valid_wildcard_pattern_list (for_app)) {
        return HBDBUS_EC_INVALID_VALUE;
    }

    if (kvlist_get (&conn->method_list, method_name))
        return HBDBUS_EC_DUPLICATED;

    n = snprintf (param_buff, sizeof (param_buff), 
            "{"
            "\"methodName\": \"%s\","
            "\"forHost\": \"%s\","
            "\"forApp\": \"%s\""
            "}",
            method_name,
            for_host, for_app);

    if (n < 0) {
        return HBDBUS_EC_UNEXPECTED;
    }
    else if ((size_t)n >= sizeof (param_buff))
        return HBDBUS_EC_TOO_SMALL_BUFF;

    purc_assemble_endpoint_name (conn->srv_host_name,
            HBDBUS_APP_HBDBUS, HBDBUS_RUNNER_BUILITIN, endpoint_name);

    if ((err_code = hbdbus_call_procedure_and_wait (conn, endpoint_name,
                    "registerProcedure", param_buff,
                    HBDBUS_DEF_TIME_EXPECTED, &ret_code, &ret_value))) {
        return err_code;
    }

    if (ret_code == PCRDR_SC_OK) {
        kvlist_set (&conn->method_list, method_name, mhi);
        if (ret_value)
            free (ret_value);
    }

    return 0;
}

int hbdbus_register_procedure (hbdbus_conn* conn, const char* method_name,
        const char* for_host, const char* for_app,
        hbdbus_method_handler method_handler)
{
    struct method_handler_info mhi = { MHT_STRING, method_handler };

    return my_register_procedure (conn, method_name, for_host, for_app, &mhi);
}

int hbdbus_register_procedure_const (hbdbus_conn* conn, const char* method_name,
        const char* for_host, const char* for_app,
        hbdbus_method_handler_const method_handler)
{
    struct method_handler_info mhi = { MHT_CONST_STRING, method_handler };

    return my_register_procedure (conn, method_name, for_host, for_app, &mhi);
}


int hbdbus_revoke_procedure (hbdbus_conn* conn, const char* method_name)
{
    int n, err_code, ret_code;
    char endpoint_name [HBDBUS_LEN_ENDPOINT_NAME + 1];
    char param_buff [HBDBUS_MIN_PACKET_BUFF_SIZE];
    char* ret_value;

    if (!hbdbus_is_valid_method_name (method_name))
        return HBDBUS_EC_INVALID_VALUE;

    if (!kvlist_get (&conn->method_list, method_name))
        return HBDBUS_EC_INVALID_VALUE;

    n = snprintf (param_buff, sizeof (param_buff), 
            "{"
            "\"methodName\": \"%s\""
            "}",
            method_name);

    if (n < 0) {
        return HBDBUS_EC_UNEXPECTED;
    }
    else if ((size_t)n >= sizeof (param_buff))
        return HBDBUS_EC_TOO_SMALL_BUFF;

    purc_assemble_endpoint_name (conn->srv_host_name,
            HBDBUS_APP_HBDBUS, HBDBUS_RUNNER_BUILITIN, endpoint_name);

    if ((err_code = hbdbus_call_procedure_and_wait (conn, endpoint_name,
                    "revokeProcedure", param_buff,
                    HBDBUS_DEF_TIME_EXPECTED, &ret_code, &ret_value))) {
        return err_code;
    }

    if (ret_code == PCRDR_SC_OK) {
        kvlist_delete (&conn->method_list, method_name);

        if (ret_value)
            free (ret_value);
    }

    return 0;
}

int hbdbus_register_event (hbdbus_conn* conn, const char* bubble_name,
        const char* for_host, const char* for_app)
{
    int n, err_code, ret_code;
    char endpoint_name [HBDBUS_LEN_ENDPOINT_NAME + 1];
    char param_buff [HBDBUS_MIN_PACKET_BUFF_SIZE];
    char* ret_value;

    if (!hbdbus_is_valid_bubble_name (bubble_name))
        return HBDBUS_EC_INVALID_VALUE;

    if (for_host == NULL) for_host = "*";
    if (!hbdbus_is_valid_wildcard_pattern_list (for_host)) {
        return HBDBUS_EC_INVALID_VALUE;
    }

    if (for_app == NULL) for_app = "*";
    if (!hbdbus_is_valid_wildcard_pattern_list (for_app)) {
        return HBDBUS_EC_INVALID_VALUE;
    }

    if (kvlist_get (&conn->bubble_list, bubble_name))
        return HBDBUS_EC_DUPLICATED;

    n = snprintf (param_buff, sizeof (param_buff), 
            "{"
            "\"bubbleName\": \"%s\","
            "\"forHost\": \"%s\","
            "\"forApp\": \"%s\""
            "}",
            bubble_name,
            for_host, for_app);

    if (n < 0) {
        return HBDBUS_EC_UNEXPECTED;
    }
    else if ((size_t)n >= sizeof (param_buff))
        return HBDBUS_EC_TOO_SMALL_BUFF;

    purc_assemble_endpoint_name (conn->srv_host_name,
            HBDBUS_APP_HBDBUS, HBDBUS_RUNNER_BUILITIN, endpoint_name);

    if ((err_code = hbdbus_call_procedure_and_wait (conn, endpoint_name,
                    "registerEvent", param_buff,
                    HBDBUS_DEF_TIME_EXPECTED, &ret_code, &ret_value))) {
        return err_code;
    }

    if (ret_code == PCRDR_SC_OK) {
        kvlist_set (&conn->bubble_list, bubble_name, hbdbus_register_event);

        if (ret_value)
            free (ret_value);
    }
    else {
        err_code = HBDBUS_EC_SERVER_ERROR;
    }

    return err_code;
}

int hbdbus_revoke_event (hbdbus_conn* conn, const char* bubble_name)
{
    int n, err_code, ret_code;
    char endpoint_name [HBDBUS_LEN_ENDPOINT_NAME + 1];
    char param_buff [HBDBUS_MIN_PACKET_BUFF_SIZE];
    char* ret_value;

    if (!hbdbus_is_valid_bubble_name (bubble_name))
        return HBDBUS_EC_INVALID_VALUE;

    if (!kvlist_get (&conn->bubble_list, bubble_name))
        return HBDBUS_EC_INVALID_VALUE;

    n = snprintf (param_buff, sizeof (param_buff), 
            "{"
            "\"bubbleName\": \"%s\""
            "}",
            bubble_name);

    if (n < 0) {
        return HBDBUS_EC_UNEXPECTED;
    }
    else if ((size_t)n >= sizeof (param_buff))
        return HBDBUS_EC_TOO_SMALL_BUFF;

    purc_assemble_endpoint_name (conn->srv_host_name,
            HBDBUS_APP_HBDBUS, HBDBUS_RUNNER_BUILITIN, endpoint_name);

    if ((err_code = hbdbus_call_procedure_and_wait (conn, endpoint_name,
                    "revokeEvent", param_buff,
                    HBDBUS_DEF_TIME_EXPECTED, &ret_code, &ret_value))) {
        return err_code;
    }

    if (ret_code == PCRDR_SC_OK) {
        kvlist_delete (&conn->bubble_list, bubble_name);

        if (ret_value)
            free (ret_value);
    }
    else {
        err_code = HBDBUS_EC_SERVER_ERROR;
    }

    return 0;
}

int hbdbus_subscribe_event (hbdbus_conn* conn,
        const char* endpoint, const char* bubble_name,
        hbdbus_event_handler event_handler)
{
    int n, err_code, ret_code;
    char builtin_name [HBDBUS_LEN_ENDPOINT_NAME + 1];
    char param_buff [HBDBUS_MIN_PACKET_BUFF_SIZE];
    char event_name [HBDBUS_LEN_ENDPOINT_NAME + HBDBUS_LEN_BUBBLE_NAME + 2];
    char* ret_value;

    if (!purc_is_valid_endpoint_name (endpoint))
        return HBDBUS_EC_INVALID_VALUE;

    if (!hbdbus_is_valid_bubble_name (bubble_name))
        return HBDBUS_EC_INVALID_VALUE;

    n = purc_name_tolower_copy (endpoint, event_name, HBDBUS_LEN_ENDPOINT_NAME);
    event_name [n++] = '/';
    event_name [n] = '\0';
    strcpy(event_name + n, bubble_name);
    if (kvlist_get (&conn->subscribed_list, event_name))
        return HBDBUS_EC_INVALID_VALUE;

    n = snprintf (param_buff, sizeof (param_buff), 
            "{"
            "\"endpointName\": \"%s\","
            "\"bubbleName\": \"%s\""
            "}",
            endpoint,
            bubble_name);

    if (n < 0) {
        return HBDBUS_EC_UNEXPECTED;
    }
    else if ((size_t)n >= sizeof (param_buff))
        return HBDBUS_EC_TOO_SMALL_BUFF;

    purc_assemble_endpoint_name (conn->srv_host_name,
            HBDBUS_APP_HBDBUS, HBDBUS_RUNNER_BUILITIN, builtin_name);

    if ((err_code = hbdbus_call_procedure_and_wait (conn, builtin_name,
                    "subscribeEvent", param_buff,
                    HBDBUS_DEF_TIME_EXPECTED, &ret_code, &ret_value))) {
        return err_code;
    }

    if (ret_code == PCRDR_SC_OK) {
        kvlist_set (&conn->subscribed_list, event_name, &event_handler);

        if (ret_value)
            free (ret_value);
    }

    return 0;
}

int hbdbus_unsubscribe_event (hbdbus_conn* conn,
        const char* endpoint, const char* bubble_name)
{
    int n, err_code, ret_code;
    char builtin_name [HBDBUS_LEN_ENDPOINT_NAME + 1];
    char param_buff [HBDBUS_MIN_PACKET_BUFF_SIZE];
    char event_name [HBDBUS_LEN_ENDPOINT_NAME + HBDBUS_LEN_BUBBLE_NAME + 2];
    char* ret_value;

    if (!purc_is_valid_endpoint_name (endpoint))
        return HBDBUS_EC_INVALID_VALUE;

    if (!hbdbus_is_valid_bubble_name (bubble_name))
        return HBDBUS_EC_INVALID_VALUE;

    n = purc_name_tolower_copy (endpoint, event_name, HBDBUS_LEN_ENDPOINT_NAME);
    event_name [n++] = '/';
    event_name [n] = '\0';
    strcpy(event_name + n, bubble_name);
    if (!kvlist_get (&conn->subscribed_list, event_name))
        return HBDBUS_EC_INVALID_VALUE;

    n = snprintf (param_buff, sizeof (param_buff), 
            "{"
            "\"endpointName\": \"%s\","
            "\"bubbleName\": \"%s\""
            "}",
            endpoint,
            bubble_name);

    if (n < 0) {
        return HBDBUS_EC_UNEXPECTED;
    }
    else if ((size_t)n >= sizeof (param_buff))
        return HBDBUS_EC_TOO_SMALL_BUFF;

    purc_assemble_endpoint_name (conn->srv_host_name,
            HBDBUS_APP_HBDBUS, HBDBUS_RUNNER_BUILITIN, builtin_name);

    if ((err_code = hbdbus_call_procedure_and_wait (conn, builtin_name,
                    "unsubscribeEvent", param_buff,
                    HBDBUS_DEF_TIME_EXPECTED, &ret_code, &ret_value))) {
        return err_code;
    }

    if (ret_code == PCRDR_SC_OK) {
        kvlist_delete (&conn->subscribed_list, event_name);

        if (ret_value)
            free (ret_value);
    }

    return 0;
}

int hbdbus_call_procedure (hbdbus_conn* conn,
        const char* endpoint,
        const char* method_name, const char* method_param,
        int time_expected, hbdbus_result_handler result_handler,
        const char** call_id)
{
    int n, retv;
    char call_id_buf [HBDBUS_LEN_UNIQUE_ID + 1];
    char buff [HBDBUS_DEF_PACKET_BUFF_SIZE];
    char* escaped_param;

    if (!purc_is_valid_endpoint_name (endpoint))
        return HBDBUS_EC_INVALID_VALUE;

    if (!hbdbus_is_valid_method_name (method_name))
        return HBDBUS_EC_INVALID_VALUE;

    escaped_param = pcutils_escape_string_for_json (method_param);
    if (escaped_param == NULL)
        return HBDBUS_EC_NOMEM;

    purc_generate_unique_id (call_id_buf, "call");

    n = snprintf (buff, sizeof (buff), 
            "{"
            "\"packetType\": \"call\","
            "\"callId\": \"%s\","
            "\"toEndpoint\": \"%s\","
            "\"toMethod\": \"%s\","
            "\"expectedTime\": %d,"
            "\"parameter\": \"%s\""
            "}",
            call_id_buf,
            endpoint,
            method_name,
            time_expected,
            escaped_param);
    free (escaped_param);

    if (n < 0) {
        return HBDBUS_EC_UNEXPECTED;
    }
    else if ((size_t)n >= sizeof (buff)) {
        return HBDBUS_EC_TOO_SMALL_BUFF;
    }

    if ((retv = hbdbus_send_text_packet (conn, buff, n)) == 0) {
        const char* p;
        p = kvlist_set_ex (&conn->call_list, call_id_buf, &result_handler);
        if (p) {
            if (call_id) {
                *call_id = p;
            }
        }
        else
            retv = HBDBUS_EC_NOMEM;
    }

    return retv;
}

int hbdbus_fire_event (hbdbus_conn* conn,
        const char* bubble_name, const char* bubble_data)
{
    int n;
    char event_id [HBDBUS_LEN_UNIQUE_ID + 1];
    char buff_in_stack [HBDBUS_DEF_PACKET_BUFF_SIZE];
    char* packet_buff = buff_in_stack;
    size_t len_data = bubble_data ? (strlen (bubble_data) * 2 + 1) : 0;
    size_t sz_packet_buff = sizeof (buff_in_stack);
    char* escaped_data;
    int err_code = 0;

    if (!hbdbus_is_valid_bubble_name (bubble_name)) {
        err_code = HBDBUS_EC_INVALID_VALUE;
        return HBDBUS_EC_INVALID_VALUE;
    }

    if (!kvlist_get (&conn->bubble_list, bubble_name)) {
        err_code = HBDBUS_EC_INVALID_VALUE;
        return HBDBUS_EC_INVALID_VALUE;
    }

    if (len_data > HBDBUS_MIN_PACKET_BUFF_SIZE) {
        sz_packet_buff = HBDBUS_MIN_PACKET_BUFF_SIZE + len_data;
        packet_buff = malloc (HBDBUS_MIN_PACKET_BUFF_SIZE + len_data);
        if (packet_buff == NULL) {
            err_code = HBDBUS_EC_NOMEM;
            return HBDBUS_EC_NOMEM;
        }
    }

    if (bubble_data) {
        escaped_data = pcutils_escape_string_for_json (bubble_data);
        if (escaped_data == NULL) {
            err_code = HBDBUS_EC_NOMEM;
            return HBDBUS_EC_NOMEM;
        }
    }
    else
        escaped_data = NULL;

    purc_generate_unique_id (event_id, "event");
    n = snprintf (packet_buff, sz_packet_buff, 
            "{"
            "\"packetType\": \"event\","
            "\"eventId\": \"%s\","
            "\"bubbleName\": \"%s\","
            "\"bubbleData\": \"%s\""
            "}",
            event_id,
            bubble_name,
            escaped_data ? escaped_data : "");
    if (escaped_data)
        free (escaped_data);

    if (n < 0) {
        err_code = HBDBUS_EC_UNEXPECTED;
    }
    else if ((size_t)n >= sz_packet_buff) {
        err_code = HBDBUS_EC_TOO_SMALL_BUFF;
    }
    else
        err_code = hbdbus_send_text_packet (conn, packet_buff, n);

    if (packet_buff && packet_buff != buff_in_stack) {
        free (packet_buff);
    }

    return err_code;
}

static int dispatch_call_packet (hbdbus_conn* conn, const purc_variant_t jo)
{
    purc_variant_t jo_tmp;
    const char* from_endpoint = NULL, *call_id=NULL, *result_id = NULL;
    const char* to_method;
    const char* parameter;
    void *data;
    char *ret_value = NULL;
    int err_code = 0;
    char buff_in_stack [HBDBUS_DEF_PACKET_BUFF_SIZE];
    char* packet_buff = buff_in_stack;
    size_t sz_packet_buff = sizeof (buff_in_stack);
    char* escaped_value = NULL;
    int n = 0, ret_code = 0;
    double time_consumed = 0.0f;

    if ((jo_tmp = purc_variant_object_get_by_ckey(jo, "fromEndpoint")) &&
            (from_endpoint = purc_variant_get_string_const(jo_tmp))) {
    }
    else {
        err_code = HBDBUS_EC_PROTOCOL;
        goto done;
    }

    if ((jo_tmp = purc_variant_object_get_by_ckey(jo, "toMethod")) &&
            (to_method = purc_variant_get_string_const(jo_tmp))) {
    }
    else {
        err_code = HBDBUS_EC_PROTOCOL;
        goto done;
    }

    if ((jo_tmp = purc_variant_object_get_by_ckey(jo, "callId")) &&
            (call_id = purc_variant_get_string_const(jo_tmp))) {
    }
    else {
        err_code = HBDBUS_EC_PROTOCOL;
        goto done;
    }

    if ((jo_tmp = purc_variant_object_get_by_ckey(jo, "resultId")) &&
            (result_id = purc_variant_get_string_const(jo_tmp))) {
    }
    else {
        err_code = HBDBUS_EC_PROTOCOL;
        goto done;
    }

    if ((jo_tmp = purc_variant_object_get_by_ckey(jo, "parameter")) &&
            (parameter = purc_variant_get_string_const(jo_tmp))) {
    }
    else {
        parameter = "";
    }

    if ((data = kvlist_get(&conn->method_list, to_method)) == NULL) {
        err_code = HBDBUS_EC_UNKNOWN_METHOD;
        goto done;
    }
    else {
        struct timespec ts;
        struct method_handler_info mhi;
        const char *ret_value_const = NULL;

        mhi = *(struct method_handler_info *)data;

        clock_gettime (CLOCK_MONOTONIC, &ts);
        if (mhi.type == MHT_CONST_STRING) {
            hbdbus_method_handler_const method_handler = mhi.handler;
            ret_value_const = method_handler(conn, from_endpoint,
                    to_method, parameter, &err_code);
        }
        else {
            hbdbus_method_handler method_handler = mhi.handler;
            ret_value = method_handler(conn, from_endpoint,
                    to_method, parameter, &err_code);
            ret_value_const = ret_value;
        }

        time_consumed = purc_get_elapsed_seconds (&ts, NULL);

        if (err_code == 0) {
            size_t len_value;

            if (ret_value_const) {
                escaped_value = pcutils_escape_string_for_json(ret_value_const);
                if (escaped_value == NULL) {
                    err_code = HBDBUS_EC_NOMEM;
                    goto done;
                }
            }
            else
                escaped_value = NULL;

            len_value = escaped_value ? (strlen(escaped_value) + 2) : 2;
            if (len_value > HBDBUS_MIN_PACKET_BUFF_SIZE) {
                sz_packet_buff = HBDBUS_MIN_PACKET_BUFF_SIZE + len_value;
                packet_buff = malloc(HBDBUS_MIN_PACKET_BUFF_SIZE + len_value);
                if (packet_buff == NULL) {
                    packet_buff = buff_in_stack;
                    sz_packet_buff = sizeof(buff_in_stack);

                    err_code = HBDBUS_EC_NOMEM;
                    goto done;
                }
            }
        }
    }

done:
    if (ret_value)
        free(ret_value);

    ret_code = hbdbus_errcode_to_retcode(err_code);
    n = snprintf(packet_buff, sz_packet_buff, 
            "{"
            "\"packetType\": \"result\","
            "\"resultId\": \"%s\","
            "\"callId\": \"%s\","
            "\"fromMethod\": \"%s\","
            "\"timeConsumed\": %.9f,"
            "\"retCode\": %d,"
            "\"retMsg\": \"%s\","
            "\"retValue\": \"%s\""
            "}",
            result_id, call_id,
            to_method,
            time_consumed,
            ret_code,
            pcrdr_get_ret_message (ret_code),
            escaped_value ? escaped_value : "");
    if (escaped_value)
        free(escaped_value);

    if (n < 0) {
        err_code = HBDBUS_EC_UNEXPECTED;
    }
    else if ((size_t)n >= sz_packet_buff) {
        err_code = HBDBUS_EC_TOO_SMALL_BUFF;
    }
    else
        hbdbus_send_text_packet(conn, packet_buff, n);

    if (packet_buff && packet_buff != buff_in_stack) {
        free(packet_buff);
    }

    return err_code;
}

static int dispatch_result_packet(hbdbus_conn* conn, const purc_variant_t jo)
{
    purc_variant_t jo_tmp;
    const char* result_id = NULL, *call_id = NULL;
    const char* from_endpoint = NULL;
    const char* from_method = NULL;
    const char* ret_value;
    void *data;
    hbdbus_result_handler result_handler;
    int ret_code;
    double time_consumed;

    if ((jo_tmp = purc_variant_object_get_by_ckey(jo, "resultId")) &&
            (result_id = purc_variant_get_string_const(jo_tmp))) {
    }
    else {
        HLOG_WARN ("No resultId\n");
    }

    if ((jo_tmp = purc_variant_object_get_by_ckey (jo, "callId")) &&
            (call_id = purc_variant_get_string_const(jo_tmp))) {
    }
    else {
        return HBDBUS_EC_PROTOCOL;
    }

    data = kvlist_get(&conn->call_list, call_id);
    if (data == NULL) {
        HLOG_ERR ("Not found result handler for callId: %s\n", call_id);
        return HBDBUS_EC_INVALID_VALUE;
    }

    result_handler = *(hbdbus_result_handler *)data;
    if (result_handler == NULL) {
        /* ignore the result */
        return 0;
    }

    if ((jo_tmp = purc_variant_object_get_by_ckey(jo, "fromEndpoint")) &&
            (from_endpoint = purc_variant_get_string_const(jo_tmp))) {
    }
    else {
        return HBDBUS_EC_PROTOCOL;
    }

    if ((jo_tmp = purc_variant_object_get_by_ckey(jo, "fromMethod")) &&
            (from_method = purc_variant_get_string_const(jo_tmp))) {
    }
    else {
        return HBDBUS_EC_PROTOCOL;
    }

    if ((jo_tmp = purc_variant_object_get_by_ckey(jo, "timeConsumed")) &&
            (purc_variant_cast_to_number(jo_tmp, &time_consumed, false))) {
    }
    else {
        return HBDBUS_EC_PROTOCOL;
    }

    if ((jo_tmp = purc_variant_object_get_by_ckey (jo, "retCode")) &&
            purc_variant_cast_to_int32(jo_tmp, &ret_code, false)) {
        conn->last_ret_code = ret_code;
    }
    else {
        return HBDBUS_EC_PROTOCOL;
    }

    if ((jo_tmp = purc_variant_object_get_by_ckey (jo, "retValue")) &&
            (ret_value = purc_variant_get_string_const(jo_tmp))) {
    }
    else {
        return HBDBUS_EC_PROTOCOL;
    }

    if (result_handler(conn, from_endpoint, from_method, call_id,
                ret_code, ret_value) == 0)
        kvlist_delete (&conn->call_list, call_id);

    return 0;
}

static int dispatch_event_packet (hbdbus_conn* conn, const purc_variant_t jo)
{
    purc_variant_t jo_tmp;
    const char* from_endpoint = NULL;
    const char* from_bubble = NULL;
    const char* event_id = NULL;
    const char* bubble_data;
    char event_name [HBDBUS_LEN_ENDPOINT_NAME + HBDBUS_LEN_BUBBLE_NAME + 2];
    hbdbus_event_handler event_handler;
    int n;
    void *data;

    if ((jo_tmp = purc_variant_object_get_by_ckey(jo, "fromEndpoint")) &&
            (from_endpoint = purc_variant_get_string_const(jo_tmp))) {
    }
    else {
        return HBDBUS_EC_PROTOCOL;
    }

    if ((jo_tmp = purc_variant_object_get_by_ckey(jo, "fromBubble")) &&
            (from_bubble = purc_variant_get_string_const(jo_tmp))) {
    }
    else {
        return HBDBUS_EC_PROTOCOL;
    }

    if ((jo_tmp = purc_variant_object_get_by_ckey(jo, "eventId")) &&
            (event_id = purc_variant_get_string_const(jo_tmp))) {
    }
    else {
        return HBDBUS_EC_PROTOCOL;
    }

    if ((jo_tmp = purc_variant_object_get_by_ckey(jo, "bubbleData")) &&
            (bubble_data = purc_variant_get_string_const(jo_tmp))) {
    }
    else {
        bubble_data = "";
    }

    n = purc_name_tolower_copy(from_endpoint, event_name, HBDBUS_LEN_ENDPOINT_NAME);
    event_name[n++] = '/';
    event_name[n] = '\0';
    strcpy(event_name + n, from_bubble);
    if ((data = kvlist_get(&conn->subscribed_list, event_name)) == NULL) {
        if (strcmp(event_id, HBDBUS_SYSTEM_EVENT_ID) == 0) {
            if (conn->system_event_handler) {
                conn->system_event_handler(conn, from_endpoint, from_bubble,
                        bubble_data);
            }
            else {
                HLOG_WARN("Got an unhandled system event: %s\n", event_name);
            }
        }
        else {
            HLOG_ERR("Got an unsubscribed event: %s\n", event_name);
        }

        return HBDBUS_EC_UNKNOWN_EVENT;
    }
    else {
        event_handler = *(hbdbus_event_handler *)data;
        event_handler(conn, from_endpoint, from_bubble, bubble_data);
    }

    return 0;
}

static int wait_for_specific_call_result_packet (hbdbus_conn* conn, 
        const char* call_id, int time_expected, int *ret_code, char** ret_value)
{
    fd_set rfds;
    struct timeval tv;
    int retval;
    char *packet;
    unsigned int data_len;
    purc_variant_t jo = NULL;
    time_t time_to_return;
    int err_code = 0;

    *ret_value = NULL;

    if (time_expected <= 0) {
        time_to_return = purc_get_monotoic_time () + HBDBUS_DEF_TIME_EXPECTED;
    }
    else {
        time_to_return = purc_get_monotoic_time () + time_expected;
    }

    while (1 /* purc_get_monotoic_time () < time_to_return */) {
        FD_ZERO (&rfds);
        FD_SET (conn->fd, &rfds);

        tv.tv_sec = time_to_return - purc_get_monotoic_time ();
        tv.tv_usec = 0;
        retval = select (conn->fd + 1, &rfds, NULL, NULL, &tv);

        if (retval == -1) {
            HLOG_ERR ("Failed to call select(): %s\n", strerror (errno));
            err_code = HBDBUS_EC_BAD_SYSTEM_CALL;
        }
        else if (retval) {
            err_code = hbdbus_read_packet_alloc (conn, &packet, &data_len);

            if (err_code) {
                HLOG_ERR ("Failed to read packet\n");
                break;
            }

            if (data_len == 0)
                continue;

            retval = hbdbus_json_packet_to_object (packet, data_len, &jo);
            free (packet);

            if (retval < 0) {
                HLOG_ERR ("Failed to parse JSON packet;\n");
                err_code = HBDBUS_EC_BAD_PACKET;
            }
            else if (retval == JPT_RESULT) {
                purc_variant_t jo_tmp;
                const char* str_tmp;
                if ((jo_tmp = purc_variant_object_get_by_ckey(jo, "callId")) &&
                        (str_tmp = purc_variant_get_string_const(jo_tmp)) &&
                        strcasecmp(str_tmp, call_id) == 0) {

                    if ((jo_tmp = purc_variant_object_get_by_ckey(jo, "retCode"))) {
                        purc_variant_cast_to_int32(jo_tmp, ret_code, true);
                    }
                    else {
                        *ret_code = PCRDR_SC_INTERNAL_SERVER_ERROR;
                    }
                    conn->last_ret_code = *ret_code;

                    if (*ret_code == PCRDR_SC_OK) {
                        if ((jo_tmp = purc_variant_object_get_by_ckey(jo, "retValue"))) {
                            str_tmp = purc_variant_get_string_const(jo_tmp);
                            if (str_tmp) {
                                *ret_value = strdup (str_tmp);
                            }
                            else
                                *ret_value = NULL;
                        }
                        else {
                            *ret_value = NULL;
                        }

                        purc_variant_unref(jo);
                        jo = NULL;
                        err_code = 0;
                        break;
                    }
                    else if (*ret_code == PCRDR_SC_ACCEPTED) {
                        // wait for ok
                        err_code = 0;
                    }
                }
                else {
                    err_code = dispatch_result_packet (conn, jo);
                }
            }
            else if (retval == JPT_ERROR) {
                purc_variant_t jo_tmp;

                if ((jo_tmp = purc_variant_object_get_by_ckey(jo, "retCode"))) {
                    purc_variant_cast_to_int32(jo_tmp, ret_code, true);
                }
                else {
                    *ret_code = PCRDR_SC_INTERNAL_SERVER_ERROR;
                }

                conn->last_ret_code = *ret_code;
                err_code = HBDBUS_EC_SERVER_ERROR;

                if ((jo_tmp = purc_variant_object_get_by_ckey (jo, "causedBy")) &&
                        strcasecmp (purc_variant_get_string_const(jo_tmp), "call") == 0 &&
                        (jo_tmp = purc_variant_object_get_by_ckey(jo, "causedId")) &&
                        strcasecmp (purc_variant_get_string_const(jo_tmp), call_id) == 0) {
                    break;
                }
            }
            else if (retval == JPT_AUTH) {
                HLOG_WARN ("Should not be here for packetType `auth`\n");
                err_code = 0;
            }
            else if (retval == JPT_CALL) {
                err_code = dispatch_call_packet (conn, jo);
            }
            else if (retval == JPT_RESULT_SENT) {
                err_code = 0;
            }
            else if (retval == JPT_EVENT) {
                err_code = dispatch_event_packet (conn, jo);
            }
            else if (retval == JPT_EVENT_SENT) {
                err_code = 0;
            }
            else if (retval == JPT_AUTH_PASSED) {
                HLOG_WARN ("Unexpected authPassed packet\n");
                err_code = HBDBUS_EC_UNEXPECTED;
            }
            else if (retval == JPT_AUTH_FAILED) {
                HLOG_WARN ("Unexpected authFailed packet\n");
                err_code = HBDBUS_EC_UNEXPECTED;
            }
            else {
                HLOG_ERR ("Unknown packet type; quit...\n");
                err_code = HBDBUS_EC_PROTOCOL;
            }

            purc_variant_unref(jo);
            jo = NULL;
        }
        else {
            err_code = HBDBUS_EC_TIMEOUT;
            break;
        }
    }

    if (jo)
        purc_variant_unref(jo);

    return err_code;
}

int hbdbus_read_and_dispatch_packet (hbdbus_conn* conn)
{
    char *packet;
    unsigned int data_len;
    purc_variant_t jo = NULL;
    int err_code, retval;

    err_code = hbdbus_read_packet_alloc (conn, &packet, &data_len);
    if (err_code) {
        HLOG_ERR ("Failed to read packet\n");
        goto done;
    }

    if (data_len == 0) { // no data
        return 0;
    }

    retval = hbdbus_json_packet_to_object (packet, data_len, &jo);
    free (packet);

    if (retval < 0) {
        HLOG_ERR ("Failed to parse JSON packet; quit...\n");
        err_code = HBDBUS_EC_BAD_PACKET;
    }
    else if (retval == JPT_ERROR) {
        HLOG_ERR ("The server gives an error packet\n");
        if (conn->error_handler) {
            conn->error_handler (conn, jo);
        }
        err_code = HBDBUS_EC_SERVER_ERROR;
    }
    else if (retval == JPT_AUTH) {
        HLOG_WARN ("Should not be here for packetType `auth`; quit...\n");
        err_code = HBDBUS_EC_UNEXPECTED;
    }
    else if (retval == JPT_CALL) {
        err_code = dispatch_call_packet (conn, jo);
    }
    else if (retval == JPT_RESULT) {
        err_code = dispatch_result_packet (conn, jo);
    }
    else if (retval == JPT_RESULT_SENT) {
        err_code = 0;
    }
    else if (retval == JPT_EVENT) {
        err_code = dispatch_event_packet (conn, jo);
    }
    else if (retval == JPT_EVENT_SENT) {
        err_code = 0;
    }
    else if (retval == JPT_AUTH_PASSED) {
        HLOG_WARN ("Unexpected authPassed packet\n");
        err_code = HBDBUS_EC_UNEXPECTED;
    }
    else if (retval == JPT_AUTH_FAILED) {
        HLOG_WARN ("Unexpected authFailed packet\n");
        err_code = HBDBUS_EC_UNEXPECTED;
    }
    else {
        HLOG_ERR ("Unknown packet type; quit...\n");
        err_code = HBDBUS_EC_PROTOCOL;
    }

done:
    if (jo)
        purc_variant_unref(jo);

    return err_code;
}

int hbdbus_wait_and_dispatch_packet (hbdbus_conn* conn, int timeout_ms)
{
    fd_set rfds;
    struct timeval tv;
    int err_code = 0;
    int retval;

    FD_ZERO (&rfds);
    FD_SET (conn->fd, &rfds);

    if (timeout_ms >= 0) {
        tv.tv_sec = timeout_ms / 1000;
        tv.tv_usec = (timeout_ms % 1000) * 1000;
        retval = select (conn->fd + 1, &rfds, NULL, NULL, &tv);
    }
    else {
        retval = select (conn->fd + 1, &rfds, NULL, NULL, NULL);
    }

    if (retval == -1) {
        err_code = HBDBUS_EC_BAD_SYSTEM_CALL;
    }
    else if (retval) {
        err_code = hbdbus_read_and_dispatch_packet (conn);
    }
    else {
        err_code = HBDBUS_EC_TIMEOUT;
    }

    return err_code;
}

