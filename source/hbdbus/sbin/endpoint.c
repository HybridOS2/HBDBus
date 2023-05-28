/*
** endpoint.c -- The endpoint (event/procedure/subscriber) management.
**
** Copyright (c) 2020 ~ 2023 FMSoft (http://www.fmsoft.cn)
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

#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <purc/purc.h>

#include "internal/log.h"

#include "hbdbus.h"
#include "endpoint.h"
#include "unixsocket.h"
#include "websocket.h"

BusEndpoint* new_endpoint (BusServer* bus_srv, int type, void* client)
{
    struct timespec ts;
    BusEndpoint* endpoint = NULL;

    endpoint = (BusEndpoint *)calloc (sizeof (BusEndpoint), 1);
    if (endpoint == NULL)
        return NULL;

    clock_gettime (CLOCK_MONOTONIC, &ts);
    endpoint->t_created = ts.tv_sec;
    endpoint->t_living = ts.tv_sec;
    endpoint->avl.key = NULL;

    switch (type) {
        case ET_BUILTIN:
            endpoint->type = ET_BUILTIN;
            endpoint->status = ES_READY;
            endpoint->entity.client = NULL;

            endpoint->host_name = strdup (bus_srv->server_name);
            endpoint->app_name = strdup (HBDBUS_APP_NAME);
            endpoint->runner_name = strdup (HBDBUS_RUN_BUILITIN);
            break;

        case ET_UNIX_SOCKET:
        case ET_WEB_SOCKET:
            endpoint->type = type;
            endpoint->status = ES_AUTHING;
            endpoint->entity.client = client;

            endpoint->host_name = NULL;
            endpoint->app_name = NULL;
            endpoint->runner_name = NULL;
            if (!store_dangling_endpoint (bus_srv, endpoint)) {
                HLOG_ERR ("Failed to store dangling endpoint\n");
                free (endpoint);
                return NULL;
            }
            break;

        default:
            HLOG_ERR ("Bad endpoint type\n");
            free (endpoint);
            return NULL;
    }

    if (type == ET_UNIX_SOCKET) {
        USClient* usc = (USClient*)client;
        usc->entity = &endpoint->entity;
    }
    else if (type == ET_WEB_SOCKET) {
        WSClient* wsc = (WSClient*)client;
        wsc->entity = &endpoint->entity;
    }

    kvlist_init (&endpoint->method_list, NULL, true);
    kvlist_init (&endpoint->bubble_list, NULL, true);
    kvlist_init (&endpoint->subscribed_list, NULL, true);

    return endpoint;
}

int del_endpoint (BusServer* bus_srv, BusEndpoint* endpoint, int cause)
{
    char endpoint_name [HBDBUS_LEN_ENDPOINT_NAME + 1];
    const char *method_name, *bubble_name, *event_name;
    void *next, *data;

    if (assemble_endpoint_name (endpoint, endpoint_name) > 0) {
        HLOG_INFO ("Deleting an endpoint: %s (%p)\n", endpoint_name, endpoint);
        if (cause == CDE_LOST_CONNECTION || cause == CDE_NO_RESPONDING) {
            fire_system_event (bus_srv, SBT_BROKEN_ENDPOINT, endpoint, NULL,
                    (cause == CDE_LOST_CONNECTION) ? "lostConnection" : "noResponding");
        }

        if (endpoint->avl.key)
            avl_delete (&bus_srv->living_avl, &endpoint->avl);
    }
    else {
        strcpy (endpoint_name, "edpt://endpoint/not/authenticated");
    }

    kvlist_for_each (&endpoint->method_list, method_name, data) {
        MethodInfo* method;

        method = *(MethodInfo **)data;
        HLOG_INFO ("Revoke procedure: edpt://%s/%s/%s/method/%s (%p)\n",
                endpoint->host_name, endpoint->app_name, endpoint->runner_name,
                method_name, method);
        cleanup_pattern_list (&method->host_patt_list);
        cleanup_pattern_list (&method->app_patt_list);
        free (method);
    }
    kvlist_free (&endpoint->method_list);

    kvlist_for_each_safe (&endpoint->bubble_list, bubble_name, next, data) {
        const char* sub_name;
        void* sub_data;
        BubbleInfo* bubble;

        bubble = *(BubbleInfo **)data;
        HLOG_INFO ("Revoke event: edpt://%s/%s/%s/bubble/%s (%p)\n",
                endpoint->host_name, endpoint->app_name, endpoint->runner_name,
                bubble_name, bubble);
        cleanup_pattern_list (&bubble->host_patt_list);
        cleanup_pattern_list (&bubble->app_patt_list);

        if (endpoint->type != ET_BUILTIN) {
            kvlist_for_each (&bubble->subscriber_list, sub_name, sub_data) {
                void *sub_sub_data;
                sub_sub_data = kvlist_get (&bus_srv->endpoint_list, sub_name);

                if (sub_sub_data) {
                    BusEndpoint* subscriber;
                    subscriber = *(BusEndpoint **)sub_sub_data;

                    HLOG_INFO ("notify subscirber: %s\n", sub_name);
                    if (subscriber != endpoint) {
                        fire_system_event (bus_srv, SBT_LOST_EVENT_GENERATOR,
                                endpoint, subscriber, bubble_name);
                    }
                }
            }
        }
        kvlist_free (&bubble->subscriber_list);

        free (bubble);
    }
    kvlist_free (&endpoint->bubble_list);

    kvlist_for_each (&endpoint->subscribed_list, event_name, data) {
        char* bubble_name;
        void *sub_data;

        /* here we use a trick to separate the endpoint name and bubble name */
        bubble_name = strrchr (event_name, '/');
        bubble_name [0] = '\0';
        bubble_name++;

        sub_data = kvlist_get (&bus_srv->endpoint_list, event_name);
        if (sub_data) {
            void *sub_sub_data;
            BusEndpoint* event_endpoint;
            BubbleInfo *info;

            event_endpoint = *(BusEndpoint **)sub_data;
            if ((sub_sub_data = kvlist_get (&event_endpoint->bubble_list,
                            bubble_name)) == NULL) {
                continue;
            }

            info = *(BubbleInfo **)sub_sub_data;
            kvlist_delete (&info->subscriber_list, endpoint_name);
        }
    }
    kvlist_free (&endpoint->subscribed_list);

    /* not for builtin endpoint */
    if (endpoint->sta_data)
        free (endpoint->sta_data);

    if (endpoint->host_name) free (endpoint->host_name);
    if (endpoint->app_name) free (endpoint->app_name);
    if (endpoint->runner_name) free (endpoint->runner_name);

    free (endpoint);
    HLOG_WARN ("Endpoint (%s) removed\n", endpoint_name);
    return 0;
}

bool store_dangling_endpoint (BusServer* bus_srv, BusEndpoint* endpoint)
{
    if (bus_srv->dangling_endpoints == NULL)
        bus_srv->dangling_endpoints = gslist_create (endpoint);
    else
        bus_srv->dangling_endpoints =
            gslist_insert_append (bus_srv->dangling_endpoints, endpoint);

    if (bus_srv->dangling_endpoints)
        return true;

    return false;
}

bool remove_dangling_endpoint (BusServer* bus_srv, BusEndpoint* endpoint)
{
    gs_list* node = bus_srv->dangling_endpoints;

    while (node) {
        if (node->data == endpoint) {
            gslist_remove_node (&bus_srv->dangling_endpoints, node);
            return true;
        }

        node = node->next;
    }

    return false;
}

bool make_endpoint_ready (BusServer* bus_srv,
        const char* endpoint_name, BusEndpoint* endpoint)
{
    if (remove_dangling_endpoint (bus_srv, endpoint)) {
        if (!kvlist_set (&bus_srv->endpoint_list, endpoint_name, &endpoint)) {
            HLOG_ERR ("Failed to store the endpoint: %s\n", endpoint_name);
            return false;
        }

        endpoint->t_living = purc_get_monotoic_time ();
        endpoint->avl.key = endpoint;
        if (avl_insert (&bus_srv->living_avl, &endpoint->avl)) {
            HLOG_ERR ("Failed to insert to the living AVL tree: %s\n", endpoint_name);
            assert (0);
            return false;
        }
        bus_srv->nr_endpoints++;
    }
    else {
        HLOG_ERR ("Not found endpoint in dangling list: %s\n", endpoint_name);
        return false;
    }

    return true;
}

static void cleanup_endpoint_client (BusServer *bus_srv, BusEndpoint* endpoint)
{
    if (endpoint->type == ET_UNIX_SOCKET) {
        endpoint->entity.client->entity = NULL;
        us_cleanup_client (bus_srv->us_srv, (USClient*)endpoint->entity.client);
    }
    else if (endpoint->type == ET_WEB_SOCKET) {
        endpoint->entity.client->entity = NULL;
        ws_cleanup_client (bus_srv->ws_srv, (WSClient*)endpoint->entity.client);
    }

    HLOG_WARN ("The endpoint (edpt://%s/%s/%s) client cleaned up\n",
            endpoint->host_name, endpoint->app_name, endpoint->runner_name);
}

int check_no_responding_endpoints (BusServer *bus_srv)
{
    int n = 0;
#if 0
    struct timespec ts;
    const char* name;
    void *next, *data;

    clock_gettime (CLOCK_MONOTONIC, &ts);

    kvlist_for_each_safe (&bus_srv->endpoint_list, name, next, data) {
        BusEndpoint* endpoint = *(BusEndpoint **)data;

        if (endpoint->type != ET_BUILTIN &&
                ts.tv_sec > endpoint->t_living + HBDBUS_MAX_NO_RESPONDING_TIME) {
            kvlist_delete (&bus_srv->endpoint_list, name);
            cleanup_endpoint_client (bus_srv, endpoint);
            del_endpoint (bus_srv, endpoint, CDE_NO_RESPONDING);
            n++;
        }
    }
#endif

    time_t t_curr = purc_get_monotoic_time ();
    BusEndpoint *endpoint, *tmp;

    HLOG_INFO ("Checking no responding endpoints...\n");

    avl_for_each_element_safe (&bus_srv->living_avl, endpoint, avl, tmp) {
        char name [HBDBUS_LEN_ENDPOINT_NAME + 1];

        assert (endpoint->type != ET_BUILTIN);

        assemble_endpoint_name (endpoint, name);
        if (t_curr > endpoint->t_living + HBDBUS_MAX_NO_RESPONDING_TIME) {

            kvlist_delete (&bus_srv->endpoint_list, name);
            cleanup_endpoint_client (bus_srv, endpoint);
            del_endpoint (bus_srv, endpoint, CDE_NO_RESPONDING);
            bus_srv->nr_endpoints--;
            n++;

            HLOG_INFO ("A no-responding client: %s\n", name);
        }
        else if (t_curr > endpoint->t_living + HBDBUS_MAX_PING_TIME) {
            if (endpoint->type == ET_UNIX_SOCKET) {
                us_ping_client (bus_srv->us_srv, (USClient *)endpoint->entity.client);
            }
            else if (endpoint->type == ET_WEB_SOCKET) {
                ws_ping_client (bus_srv->ws_srv, (WSClient *)endpoint->entity.client);
            }

            HLOG_INFO ("Ping client: %s\n", name);
        }
        else {
            HLOG_INFO ("Skip left endpoints since (%s): %ld\n", name, endpoint->t_living);
            break;
        }
    }

    HLOG_INFO ("Total endpoints removed: %d\n", n);
    return n;
}

int check_dangling_endpoints (BusServer *bus_srv)
{
    int n = 0;
    time_t t_curr = purc_get_monotoic_time ();
    gs_list* node = bus_srv->dangling_endpoints;

    while (node) {
        gs_list *next = node->next;
        BusEndpoint* endpoint = (BusEndpoint *)node->data;

        if (t_curr > endpoint->t_created + HBDBUS_MAX_NO_RESPONDING_TIME) {
            gslist_remove_node (&bus_srv->dangling_endpoints, node);
            cleanup_endpoint_client (bus_srv, endpoint);
            del_endpoint (bus_srv, endpoint, CDE_NO_RESPONDING);
            n++;
        }

        node = next;
    }

    return n;
}

#define LEN_BODY_PART       0

int send_packet_to_endpoint (BusServer* bus_srv,
        BusEndpoint* endpoint, const char* body, int len_body)
{
#if LEN_BODY_PART
    char *part;
    if (len_body > LEN_BODY_PART)
        part = strndup(body, LEN_BODY_PART);
    else
        part = strndup(body, len_body);

    HLOG_INFO ("Packet body sending to edpt://%s/%s/%s: %s...\n",
            endpoint->host_name, endpoint->app_name, endpoint->runner_name,
            part);
    free(part);
#endif

    if (endpoint->type == ET_UNIX_SOCKET) {
        return us_send_packet (bus_srv->us_srv, (USClient *)endpoint->entity.client,
                US_OPCODE_TEXT, body, len_body);
    }
    else if (endpoint->type == ET_WEB_SOCKET) {
        return ws_send_packet (bus_srv->ws_srv, (WSClient *)endpoint->entity.client,
                WS_OPCODE_TEXT, body, len_body);
    }

    return -1;
}

int send_challenge_code (BusServer* bus_srv, BusEndpoint* endpoint)
{
    int n, retv;
    char key [32];
    unsigned char ch_code_bin [PCUTILS_SHA256_DIGEST_SIZE];
    char *ch_code;
    char buff [HBDBUS_DEF_PACKET_BUFF_SIZE];

    if ((endpoint->sta_data = malloc (PCUTILS_SHA256_DIGEST_SIZE * 2 + 1)) == NULL) {
        return PCRDR_SC_INSUFFICIENT_STORAGE;
    }
    ch_code = endpoint->sta_data;

    snprintf (key, sizeof (key), "hbdbus-%ld", random ());

    pcutils_hmac_sha256 (ch_code_bin,
            (uint8_t*)HBDBUS_APP_NAME, strlen (HBDBUS_APP_NAME),
            (uint8_t*)key, strlen (key));
    pcutils_bin2hex (ch_code_bin, PCUTILS_SHA256_DIGEST_SIZE, ch_code, false);
    ch_code [PCUTILS_SHA256_DIGEST_SIZE * 2] = 0;

    HLOG_INFO ("Challenge code for new endpoint: %s\n", ch_code);

    n = snprintf (buff, sizeof (buff), 
            "{"
            "\"packetType\":\"auth\","
            "\"protocolName\":\"%s\","
            "\"protocolVersion\":%d,"
            "\"challengeCode\":\"%s\""
            "}",
            HBDBUS_PROTOCOL_NAME, HBDBUS_PROTOCOL_VERSION,
            ch_code);

    if (n < 0 || (size_t)n >= sizeof (buff)) {
        HLOG_ERR ("The size of buffer for packet is too small.\n");
        retv = PCRDR_SC_INTERNAL_SERVER_ERROR;
    }
    else
        retv = send_packet_to_endpoint (bus_srv, endpoint, buff, n);

    if (retv) {
        endpoint->status = ES_CLOSING;
        free (endpoint->sta_data);
        endpoint->sta_data = NULL;
        return PCRDR_SC_IOERR;
    }

    return PCRDR_SC_OK;
}

static int authenticate_endpoint (BusServer* bus_srv, BusEndpoint* endpoint,
        const purc_variant_t jo)
{
    purc_variant_t jo_tmp;
    const char* prot_name = NULL;
    const char *host_name = NULL, *app_name = NULL, *runner_name = NULL;
    const char *encoded_sig = NULL, *encoding = NULL;
    unsigned char *sig;
    size_t sig_len = 0;
    int prot_ver = 0, retv;
    char norm_host_name [HBDBUS_LEN_HOST_NAME + 1];
    char norm_app_name [HBDBUS_LEN_APP_NAME + 1];
    char norm_runner_name [HBDBUS_LEN_RUNNER_NAME + 1];
    char endpoint_name [HBDBUS_LEN_ENDPOINT_NAME + 1];

    if ((jo_tmp = purc_variant_object_get_by_ckey (jo, "protocolName"))) {
        prot_name = purc_variant_get_string_const (jo_tmp);
    }
    if ((jo_tmp = purc_variant_object_get_by_ckey (jo, "protocolVersion"))) {
        purc_variant_cast_to_int32(jo_tmp, &prot_ver, true);
    }
    if ((jo_tmp = purc_variant_object_get_by_ckey (jo, "hostName"))) {
        host_name = purc_variant_get_string_const (jo_tmp);
    }
    if ((jo_tmp = purc_variant_object_get_by_ckey (jo, "appName"))) {
        app_name = purc_variant_get_string_const (jo_tmp);
    }
    if ((jo_tmp = purc_variant_object_get_by_ckey (jo, "runnerName"))) {
        runner_name = purc_variant_get_string_const (jo_tmp);
    }
    if ((jo_tmp = purc_variant_object_get_by_ckey (jo, "signature"))) {
        encoded_sig = purc_variant_get_string_const (jo_tmp);
    }
    if ((jo_tmp = purc_variant_object_get_by_ckey (jo, "encodedIn"))) {
        encoding = purc_variant_get_string_const (jo_tmp);
    }

    if (prot_name == NULL || prot_ver > HBDBUS_PROTOCOL_VERSION ||
            host_name == NULL || app_name == NULL || runner_name == NULL ||
            encoded_sig == NULL || encoding == NULL ||
            strcasecmp (prot_name, HBDBUS_PROTOCOL_NAME)) {
        HLOG_WARN ("Bad packet data for authentication\n");
        return PCRDR_SC_BAD_REQUEST;
    }

    if (prot_ver < HBDBUS_MINIMAL_PROTOCOL_VERSION)
        return PCRDR_SC_UPGRADE_REQUIRED;

    if (!purc_is_valid_host_name (host_name) ||
            !purc_is_valid_app_name (app_name) ||
            !purc_is_valid_token (runner_name, HBDBUS_LEN_RUNNER_NAME)) {
        HLOG_WARN ("Bad endpoint name: edpt://%s/%s/%s\n",
                host_name, app_name, runner_name);
        return PCRDR_SC_NOT_ACCEPTABLE;
    }

    purc_name_tolower_copy (host_name, norm_host_name, HBDBUS_LEN_HOST_NAME);
    purc_name_tolower_copy (app_name, norm_app_name, HBDBUS_LEN_APP_NAME);
    purc_name_tolower_copy (runner_name, norm_runner_name, HBDBUS_LEN_RUNNER_NAME);
    host_name = norm_host_name;
    app_name = norm_app_name;
    runner_name = norm_runner_name;

    assert (endpoint->sta_data);

    if (strcasecmp (encoding, "base64") == 0) {
        sig_len = pcutils_b64_decoded_length(strlen (encoded_sig));
        sig = malloc(sig_len);
        sig_len = pcutils_b64_decode(encoded_sig, sig, sig_len);
    }
    else if (strcasecmp (encoding, "hex") == 0) {
        sig = malloc(strlen (encoded_sig) / 2 + 1);
        pcutils_hex2bin(encoded_sig, sig, &sig_len);
    }
    else {
        return PCRDR_SC_BAD_REQUEST;
    }

    if (sig_len <= 0) {
        free (sig);
        return PCRDR_SC_BAD_REQUEST;
    }

    retv = pcutils_verify_signature (app_name,
            endpoint->sta_data, strlen (endpoint->sta_data),
            sig, sig_len);
    free (sig);

    if (retv < 0) {
        HLOG_WARN ("No such app installed: %s\n", app_name);
        return PCRDR_SC_NOT_FOUND;
    }
    else if (retv == 0) {
        HLOG_WARN ("Failed to authenticate the app (%s) with challenge code: %s\n",
                app_name, (char *)endpoint->sta_data);
        return PCRDR_SC_UNAUTHORIZED;
    }

    /* make endpoint ready here */
    if (endpoint->type == CT_UNIX_SOCKET) {
        /* override the host name */
        host_name = HBDBUS_LOCALHOST;
    }
    else {
        /* TODO: handle hostname for web socket connections here */
        host_name = HBDBUS_LOCALHOST;
    }

    purc_assemble_endpoint_name (host_name,
                    app_name, runner_name, endpoint_name);

    HLOG_INFO ("New endpoint: %s (%p)\n", endpoint_name, endpoint);

    if (kvlist_get (&bus_srv->endpoint_list, endpoint_name)) {
        HLOG_WARN ("Duplicated endpoint: %s\n", endpoint_name);
        return PCRDR_SC_CONFLICT;
    }

    if (!make_endpoint_ready (bus_srv, endpoint_name, endpoint)) {
        HLOG_ERR ("Failed to store the endpoint: %s\n", endpoint_name);
        return PCRDR_SC_INSUFFICIENT_STORAGE;
    }

    HLOG_INFO ("New endpoint stored: %s (%p), %d endpoints totally.\n",
            endpoint_name, endpoint, bus_srv->nr_endpoints);

    endpoint->host_name = strdup (host_name);
    endpoint->app_name = strdup (app_name);
    endpoint->runner_name = strdup (runner_name);
    endpoint->status = ES_READY;

    fire_system_event (bus_srv, SBT_NEW_ENDPOINT, endpoint, NULL, NULL);
    return PCRDR_SC_OK;
}

static int handle_auth_packet (BusServer* bus_srv, BusEndpoint* endpoint,
        const purc_variant_t jo)
{
    if (endpoint->status == ES_AUTHING) {
        char buff [HBDBUS_MIN_PACKET_BUFF_SIZE];
        int retv, n;

        assert (endpoint->sta_data);

        if ((retv = authenticate_endpoint (bus_srv, endpoint, jo)) !=
                PCRDR_SC_OK) {

            free (endpoint->sta_data);
            endpoint->sta_data = NULL;

            /* send authFailed packet */
            n = snprintf (buff, sizeof (buff), 
                    "{"
                    "\"packetType\":\"authFailed\","
                    "\"retCode\":%d,"
                    "\"retMsg\":\"%s\""
                    "}",
                    retv, pcrdr_get_ret_message (retv));

            if (n < 0 || (size_t)n >= sizeof (buff)) {
                HLOG_ERR ("The size of buffer for packet is too small.\n");
                return PCRDR_SC_INTERNAL_SERVER_ERROR;
            }
            else
                send_packet_to_endpoint (bus_srv, endpoint, buff, n);

            return retv;
        }

        free (endpoint->sta_data);
        endpoint->sta_data = NULL;

        /* send authPassed packet */
        n = snprintf (buff, sizeof (buff), 
                "{"
                "\"packetType\":\"authPassed\","
                "\"serverHostName\":\"%s\","
                "\"reassignedHostName\":\"%s\""
                "}",
                bus_srv->server_name, endpoint->host_name);

        if (n < 0 || (size_t)n >= sizeof (buff)) {
            HLOG_ERR ("The size of buffer for packet is too small.\n");
            return PCRDR_SC_INTERNAL_SERVER_ERROR;
        }
        else
            send_packet_to_endpoint (bus_srv, endpoint, buff, n);

        return PCRDR_SC_OK;
    }

    return PCRDR_SC_PRECONDITION_FAILED;
}

static int handle_call_packet (BusServer* bus_srv, BusEndpoint* endpoint,
        const purc_variant_t jo, const struct timespec *ts)
{
    purc_variant_t jo_tmp;
    const char *str_tmp;
    char to_endpoint_name [HBDBUS_LEN_ENDPOINT_NAME + 1];
    const char *to_method_name = NULL;
    BusEndpoint *to_endpoint;
    MethodInfo *to_method;
    const char *call_id = NULL;
    int expected_time;
    struct timespec ts_start;
    double time_diff, time_consumed;
    const char *parameter;
    CallInfo call_info;

    char buff_in_stack [HBDBUS_MAX_FRAME_PAYLOAD_SIZE];
    size_t sz_packet_buff = sizeof (buff_in_stack);
    int ret_code, n = 0;
    char result_id [HBDBUS_LEN_UNIQUE_ID + 1], *result, *escaped_result = NULL;
    char* packet_buff = buff_in_stack;

    if ((jo_tmp = purc_variant_object_get_by_ckey (jo, "callId")) &&
            (call_id = purc_variant_get_string_const(jo_tmp))) {
    }
    else {
        ret_code = PCRDR_SC_BAD_REQUEST;
        goto done;
    }

    if ((jo_tmp = purc_variant_object_get_by_ckey (jo, "toEndpoint"))) {
        if ((str_tmp = purc_variant_get_string_const(jo_tmp))) {
            void *data;
            purc_name_tolower_copy (str_tmp, to_endpoint_name,
                    HBDBUS_LEN_ENDPOINT_NAME);
            if ((data = kvlist_get (&bus_srv->endpoint_list,
                            to_endpoint_name))) {
                to_endpoint = *(BusEndpoint **)data;
            }
            else {
                ret_code = PCRDR_SC_NOT_FOUND;
                goto done;
            }
        }
        else {
            ret_code = PCRDR_SC_BAD_REQUEST;
            goto done;
        }
    }
    else {
        ret_code = PCRDR_SC_BAD_REQUEST;
        goto done;
    }

    if ((jo_tmp = purc_variant_object_get_by_ckey(jo, "toMethod"))) {
        if ((str_tmp = purc_variant_get_string_const(jo_tmp))) {
            void *data;
            to_method_name = str_tmp;
            if ((data = kvlist_get (&to_endpoint->method_list, to_method_name))) {
                to_method = *(MethodInfo **)data;
            }
            else {
                ret_code = PCRDR_SC_NOT_FOUND;
                goto done;
            }
        }
        else {
            ret_code = PCRDR_SC_BAD_REQUEST;
            goto done;
        }
    }
    else {
        ret_code = PCRDR_SC_BAD_REQUEST;
        goto done;
    }

    if (!match_pattern (&to_method->host_patt_list, endpoint->host_name,
                1, HBDBUS_PATTERN_VAR_SELF, to_endpoint->host_name)) {
        ret_code = PCRDR_SC_METHOD_NOT_ALLOWED;
        goto done;
    }

    if (!match_pattern (&to_method->app_patt_list, endpoint->app_name,
                1, HBDBUS_PATTERN_VAR_OWNER, to_endpoint->app_name)) {
        ret_code = PCRDR_SC_METHOD_NOT_ALLOWED;
        goto done;
    }

    if ((jo_tmp = purc_variant_object_get_by_ckey (jo, "expectedTime"))) {
        purc_variant_cast_to_int32(jo_tmp, &expected_time, true);
    }
    else {
        expected_time = -1;
    }

    if ((jo_tmp = purc_variant_object_get_by_ckey (jo, "parameter")) &&
            (parameter = purc_variant_get_string_const(jo_tmp))) {
    }
    else {
        parameter = NULL;
    }

    assert (to_method->handler);

    purc_generate_unique_id (result_id, "result");
    clock_gettime (CLOCK_MONOTONIC, &ts_start);
    time_diff = purc_get_elapsed_seconds (ts, &ts_start);

    call_info.call_id = call_id;
    call_info.result_id = result_id;
    call_info.time_diff = time_diff;
    endpoint->sta_data = &call_info;
    result = to_method->handler (bus_srv, endpoint, to_endpoint, to_method_name,
            parameter, &ret_code);
    endpoint->sta_data = NULL;

    time_consumed = purc_get_elapsed_seconds (&ts_start, NULL);

    if (ret_code == PCRDR_SC_OK && result) {
        escaped_result = pcutils_escape_string_for_json (result);
        free (result);

        if (escaped_result == NULL) {
            ret_code = PCRDR_SC_INSUFFICIENT_STORAGE;
        }
        else {
            sz_packet_buff = strlen (escaped_result) + HBDBUS_MIN_PACKET_BUFF_SIZE;
            if (sz_packet_buff <= sizeof (buff_in_stack)) {
                packet_buff = buff_in_stack;
                sz_packet_buff = sizeof (buff_in_stack);
            }
            else {
                packet_buff = malloc (sz_packet_buff);
                if (packet_buff == NULL) {
                    packet_buff = buff_in_stack;
                    sz_packet_buff = sizeof (buff_in_stack);
                    ret_code = PCRDR_SC_INSUFFICIENT_STORAGE;
                }
            }
        }
    }
    else {
        escaped_result = NULL;
        packet_buff = buff_in_stack;
        sz_packet_buff = sizeof (buff_in_stack);
    }

done:
    if (ret_code == PCRDR_SC_OK) {
        n = snprintf (packet_buff, sz_packet_buff, 
            "{"
            "\"packetType\": \"result\","
            "\"resultId\": \"%s\","
            "\"callId\": \"%s\","
            "\"fromEndpoint\": \"edpt://%s/%s/%s\","
            "\"fromMethod\": \"%s\","           // add ",", modified by gengyue
            "\"timeDiff\": %f,"
            "\"timeConsumed\": %f,"
            "\"retCode\": %d,"
            "\"retMsg\": \"%s\","
            "\"retValue\": \"%s\""
            "}",
            result_id, call_id,
            to_endpoint->host_name, to_endpoint->app_name, to_endpoint->runner_name,
            to_method_name,
            time_diff, time_consumed,
            ret_code,
            pcrdr_get_ret_message (ret_code),
            escaped_result ? escaped_result : "");

    }
    else if (ret_code == PCRDR_SC_ACCEPTED) {
        BusWaitingInfo waiting_info;

        waiting_info.ts = *ts;
        waiting_info.expected_time = expected_time;
        purc_assemble_endpoint_name (endpoint->host_name, endpoint->app_name,
                endpoint->runner_name, waiting_info.endpoint_name);

        if (!kvlist_set (&bus_srv->waiting_endpoints, result_id, &waiting_info)) {
            ret_code = PCRDR_SC_INSUFFICIENT_STORAGE;
        }
        else {
            n = snprintf (packet_buff, sz_packet_buff, 
                "{"
                "\"packetType\": \"result\","
                "\"resultId\": \"%s\","
                "\"callId\": \"%s\","
                "\"timeDiff\": %f,"
                "\"timeConsumed\": %f,"
                "\"retCode\": %d,"
                "\"retMsg\": \"%s\""
                "}",
                result_id, call_id,
                time_diff, time_consumed,
                ret_code,
                pcrdr_get_ret_message (ret_code));
        }
    }

    if (ret_code != PCRDR_SC_OK && ret_code != PCRDR_SC_ACCEPTED) {
        n = snprintf (packet_buff, sz_packet_buff, 
            "{"
            "\"packetType\": \"error\","
            "\"protocolName\":\"%s\","
            "\"protocolVersion\":%d,"
            "\"causedBy\": \"call\","
            "\"causedId\": \"%s\","
            "\"retCode\": %d,"
            "\"retMsg\": \"%s\""
            "}",
            HBDBUS_PROTOCOL_NAME, HBDBUS_PROTOCOL_VERSION,
            call_id ? call_id : "N/A",
            ret_code,
            pcrdr_get_ret_message (ret_code));

    }

    if (n > 0 && (size_t)n < sz_packet_buff) {
        send_packet_to_endpoint (bus_srv, endpoint, packet_buff, n);
    }
    else {
        HLOG_ERR ("The size of buffer for packet is too small.\n");
    }

    if (escaped_result)
        free (escaped_result);
    if (packet_buff && packet_buff != buff_in_stack)
        free (packet_buff);

    return PCRDR_SC_OK;
}

static int handle_result_packet (BusServer* bus_srv, BusEndpoint* endpoint,
        const purc_variant_t jo, const struct timespec *ts)
{
    purc_variant_t jo_tmp;
    int real_ret_code;
    const char *call_id, *result_id = NULL, *from_method_name;
    double time_diff, time_consumed;
    const char* ret_value;
    void* data;
    BusEndpoint *to_endpoint;

    char buff_in_stack [HBDBUS_MAX_FRAME_PAYLOAD_SIZE];
    size_t sz_packet_buff = sizeof (buff_in_stack);
    int ret_code, n;
    char* escaped_ret_value = NULL, *packet_buff = buff_in_stack;

    if ((jo_tmp = purc_variant_object_get_by_ckey (jo, "resultId")) &&
            (result_id = purc_variant_get_string_const(jo_tmp))) {
        if (!purc_is_valid_unique_id (result_id)) {
            ret_code = PCRDR_SC_BAD_REQUEST;
            goto failed;
        }
    }
    else {
        ret_code = PCRDR_SC_BAD_REQUEST;
        goto failed;
    }

    if ((jo_tmp = purc_variant_object_get_by_ckey(jo, "callId")) &&
            (call_id = purc_variant_get_string_const (jo_tmp))) {
        if (!purc_is_valid_unique_id (call_id)) {
            ret_code = PCRDR_SC_BAD_REQUEST;
            goto failed;
        }
    }
    else {
        ret_code = PCRDR_SC_BAD_REQUEST;
        goto failed;
    }

    if ((jo_tmp = purc_variant_object_get_by_ckey(jo, "retCode")) &&
             purc_variant_cast_to_int32(jo_tmp, &real_ret_code, false)) {
    }
    else {
        ret_code = PCRDR_SC_BAD_REQUEST;
        goto failed;
    }

    if ((jo_tmp = purc_variant_object_get_by_ckey(jo, "fromMethod")) &&
            (from_method_name = purc_variant_get_string_const(jo_tmp))) {
        if (!hbdbus_is_valid_method_name (from_method_name)) {
            ret_code = PCRDR_SC_BAD_REQUEST;
            goto failed;
        }
    }
    else {
        ret_code = PCRDR_SC_BAD_REQUEST;
        goto failed;
    }

    data = kvlist_get (&bus_srv->waiting_endpoints, result_id);
    if (data == NULL) {
        ret_code = PCRDR_SC_GONE;
        goto failed;
    }
    else {
        BusWaitingInfo waiting_info;

        memcpy (&waiting_info, data, sizeof (BusWaitingInfo));
        kvlist_delete (&bus_srv->waiting_endpoints, result_id);

        if ((data = kvlist_get (&bus_srv->endpoint_list,
                        waiting_info.endpoint_name)) == NULL) {
            ret_code = PCRDR_SC_NOT_FOUND;
            goto failed;
        }
        else {
            /* NOTE: the endpoint might not the caller */
            to_endpoint = *(BusEndpoint **)data;
        }
    }

    if ((jo_tmp = purc_variant_object_get_by_ckey(jo, "timeConsumed")) &&
            purc_variant_cast_to_number(jo_tmp, &time_consumed, false)) {
    }
    else {
        time_consumed = 0.0f;
    }

    if ((jo_tmp = purc_variant_object_get_by_ckey (jo, "retValue")) &&
            (ret_value = purc_variant_get_string_const (jo_tmp))) {
    }
    else {
        ret_value = NULL;
    }

    packet_buff = buff_in_stack;
    if (ret_value) {
        escaped_ret_value = pcutils_escape_string_for_json (ret_value);

        if (escaped_ret_value == NULL) {
            ret_code = PCRDR_SC_INSUFFICIENT_STORAGE;
            goto failed;
        }
        else {
            sz_packet_buff = strlen (escaped_ret_value) + HBDBUS_MIN_PACKET_BUFF_SIZE;
            if (sz_packet_buff <= sizeof (buff_in_stack)) {
                packet_buff = buff_in_stack;
                sz_packet_buff = sizeof (buff_in_stack);
            }
            else {
                packet_buff = malloc (sz_packet_buff);
                if (packet_buff == NULL) {
                    packet_buff = buff_in_stack;
                    sz_packet_buff = sizeof (buff_in_stack);
                    ret_code = PCRDR_SC_INSUFFICIENT_STORAGE;
                    goto failed;
                }
            }
        }
    }
    else {
        escaped_ret_value = NULL;
    }

    time_diff = purc_get_elapsed_seconds (ts, NULL);
    n = snprintf (packet_buff, sz_packet_buff, 
        "{"
        "\"packetType\":\"result\","
        "\"resultId\":\"%s\","
        "\"callId\":\"%s\","
        "\"fromEndpoint\":\"edpt://%s/%s/%s\","
        "\"fromMethod\":\"%s\","
        "\"timeConsumed\":%f,"
        "\"timeDiff\":%f,"
        "\"retCode\":%d,"
        "\"retMsg\":\"%s\","
        "\"retValue\":\"%s\""
        "}",
        result_id, call_id,
        endpoint->host_name, endpoint->app_name, endpoint->runner_name,
        from_method_name, time_consumed, time_diff,
        real_ret_code, pcrdr_get_ret_message (real_ret_code),
        escaped_ret_value ? escaped_ret_value : "");

    if (n > 0 && (size_t)n < sz_packet_buff) {
        send_packet_to_endpoint (bus_srv, to_endpoint, packet_buff, n);
        ret_code = PCRDR_SC_OK;
    }
    else {
        HLOG_ERR ("The size of buffer for result packet is too small.\n");
        ret_code = PCRDR_SC_INTERNAL_SERVER_ERROR;
    }

failed:
    if (ret_code != PCRDR_SC_OK) {
        n = snprintf (packet_buff, sz_packet_buff, 
            "{"
            "\"packetType\":\"error\","
            "\"protocolName\":\"%s\","
            "\"protocolVersion\":%d,"
            "\"causedBy\":\"result\","
            "\"causedId\":\"%s\","
            "\"retCode\":%d,"
            "\"retMsg\":\"%s\""
            "}",
            HBDBUS_PROTOCOL_NAME, HBDBUS_PROTOCOL_VERSION,
            result_id ? result_id : "N/A",
            ret_code, pcrdr_get_ret_message (ret_code));

        if (n > 0 && (size_t)n < sz_packet_buff) {
            send_packet_to_endpoint (bus_srv, endpoint, packet_buff, n);
        }
        else {
            HLOG_ERR ("The size of buffer for error packet is too small.\n");
        }
    }
    else {
        n = snprintf (packet_buff, sz_packet_buff, 
            "{"
            "\"packetType\":\"resultSent\","
            "\"resultId\":\"%s\","
            "\"timeDiff\":%.9f"
            "}",
            result_id, time_diff);

        if (n > 0 && (size_t)n < sz_packet_buff) {
            send_packet_to_endpoint (bus_srv, endpoint, packet_buff, n);
        }
        else {
            HLOG_ERR ("The size of buffer for resultSent packet is too small.\n");
        }
    }

    if (escaped_ret_value)
        free (escaped_ret_value);
    if (packet_buff && packet_buff != buff_in_stack)
        free (packet_buff);

    return PCRDR_SC_OK;
}

static int handle_event_packet (BusServer* bus_srv, BusEndpoint* endpoint,
        const purc_variant_t jo, const struct timespec *ts)
{
    purc_variant_t jo_tmp;
    const char *str_tmp;
    const char *bubble_name = NULL;
    BubbleInfo *bubble;
    const char *event_id = NULL;
    const char *bubble_data;

    char buff_in_stack [HBDBUS_MAX_FRAME_PAYLOAD_SIZE];
    size_t sz_packet_buff = sizeof (buff_in_stack);
    int ret_code, n;
    char* escaped_data = NULL, *packet_buff = NULL;
    struct timespec ts_start;
    double time_diff, time_consumed;
    unsigned int nr_succeeded = 0, nr_failed = 0;

    if ((jo_tmp = purc_variant_object_get_by_ckey (jo, "bubbleName"))) {
        if ((str_tmp = purc_variant_get_string_const (jo_tmp))) {
            void *data;
            bubble_name = str_tmp;
            if ((data = kvlist_get (&endpoint->bubble_list, bubble_name))) {
                bubble = *(BubbleInfo **)data;
            }
            else {
                ret_code = PCRDR_SC_NOT_FOUND;
                goto failed;
            }
        }
        else {
            ret_code = PCRDR_SC_BAD_REQUEST;
            goto failed;
        }
    }
    else {
        ret_code = PCRDR_SC_BAD_REQUEST;
        goto failed;
    }

    if ((jo_tmp = purc_variant_object_get_by_ckey (jo, "eventId")) &&
            (event_id = purc_variant_get_string_const (jo_tmp))) {
    }
    else {
        ret_code = PCRDR_SC_BAD_REQUEST;
        goto failed;
    }

    if ((jo_tmp = purc_variant_object_get_by_ckey (jo, "bubbleData")) &&
            (bubble_data = purc_variant_get_string_const(jo_tmp))) {
    }
    else {
        bubble_data = NULL;
    }

    packet_buff = buff_in_stack;
    if (bubble_data) {
        escaped_data = pcutils_escape_string_for_json (bubble_data);

        if (escaped_data == NULL) {
            ret_code = PCRDR_SC_INSUFFICIENT_STORAGE;
            goto failed;
        }
        else {
            sz_packet_buff = strlen (escaped_data) + HBDBUS_MIN_PACKET_BUFF_SIZE;
            if (sz_packet_buff <= sizeof (buff_in_stack)) {
                packet_buff = buff_in_stack;
                sz_packet_buff = sizeof (buff_in_stack);
            }
            else {
                packet_buff = malloc (sz_packet_buff);
                if (packet_buff == NULL) {
                    packet_buff = buff_in_stack;
                    sz_packet_buff = sizeof (buff_in_stack);
                    ret_code = PCRDR_SC_INSUFFICIENT_STORAGE;
                    goto failed;
                }
            }
        }
    }
    else {
        escaped_data = NULL;
    }

    clock_gettime (CLOCK_MONOTONIC, &ts_start);
    time_diff = purc_get_elapsed_seconds (ts, &ts_start);

    n = snprintf (packet_buff, sz_packet_buff, 
        "{"
        "\"packetType\": \"event\","
        "\"eventId\": \"%s\","
        "\"fromEndpoint\": \"edpt://%s/%s/%s\","
        "\"fromBubble\": \"%s\","
        "\"bubbleData\": \"%s\","
        "\"timeDiff\":",
        event_id,
        endpoint->host_name, endpoint->app_name, endpoint->runner_name,
        bubble_name,
        escaped_data ? escaped_data : "");

    if (n > 0 && (size_t)n < sz_packet_buff) {
        const char* name;
        void *next, *data;
        size_t org_len = strlen (packet_buff);

        kvlist_for_each_safe (&bubble->subscriber_list, name, next, data) {
            void *sub_data;

            sub_data = kvlist_get (&bus_srv->endpoint_list, name);

            // forward event to subscriber.
            if (sub_data) {
                double my_time_diff;
                char str_time_diff [64];
                BusEndpoint* subscriber;

                subscriber = *(BusEndpoint **)sub_data;

                my_time_diff = purc_get_elapsed_seconds (ts, NULL);
                snprintf (str_time_diff, sizeof (str_time_diff), "%.9f}", my_time_diff);
                packet_buff [org_len] = '\0';
                n = org_len + strlen (str_time_diff);
                if (sz_packet_buff > (size_t)n) {
                    strcat (packet_buff, str_time_diff);
                    send_packet_to_endpoint (bus_srv, subscriber, packet_buff, n);
                    HLOG_INFO ("Send event packet to endpoint (edpt://%s/%s/%s): \n%s\n",
                            subscriber->host_name,
                            subscriber->app_name,
                            subscriber->runner_name,
                            packet_buff);
                }
                else {
                    HLOG_ERR ("The size of buffer for event packet is too small.\n");
                    ret_code = PCRDR_SC_INTERNAL_SERVER_ERROR;
                    break;
                }
                nr_succeeded++;
            }
            else {
                kvlist_delete (&bubble->subscriber_list, name);
                nr_failed++;
            }
        }

        ret_code = PCRDR_SC_OK;
    }
    else {
        HLOG_ERR ("The size of buffer for event packet is too small.\n");
        ret_code = PCRDR_SC_INTERNAL_SERVER_ERROR;
    }

failed:
    if (ret_code != PCRDR_SC_OK) {
        n = snprintf (packet_buff, sz_packet_buff, 
            "{"
            "\"packetType\": \"error\","
            "\"protocolName\":\"%s\","
            "\"protocolVersion\":%d,"
            "\"causedBy\": \"event\","
            "\"causedId\": \"%s\","
            "\"retCode\": %d,"
            "\"retMsg\": \"%s\""
            "}",
            HBDBUS_PROTOCOL_NAME, HBDBUS_PROTOCOL_VERSION,
            event_id ? event_id : "N/A",
            ret_code,
            pcrdr_get_ret_message (ret_code));

        if (n > 0 && (size_t)n < sz_packet_buff) {
            send_packet_to_endpoint (bus_srv, endpoint, packet_buff, n);
        }
        else {
            HLOG_ERR ("The size of buffer for error packet is too small.\n");
        }
    }
    else {
        time_consumed = purc_get_elapsed_seconds (&ts_start, NULL);

        n = snprintf (packet_buff, sz_packet_buff, 
            "{"
            "\"packetType\":\"eventSent\","
            "\"eventId\":\"%s\","
            "\"nrSucceeded\":%u,"
            "\"nrFailed\":%u,"
            "\"timeDiff\":%.9f,"
            "\"timeConsumed\":%.9f"
            "}",
            event_id,
            nr_succeeded, nr_failed,
            time_diff, time_consumed);

        if (n > 0 && (size_t)n < sz_packet_buff) {
            send_packet_to_endpoint (bus_srv, endpoint, packet_buff, n);
        }
        else {
            HLOG_ERR ("The size of buffer for eventSent packet is too small.\n");
        }
    }

    if (escaped_data)
        free (escaped_data);
    if (packet_buff && packet_buff != buff_in_stack)
        free (packet_buff);

    return PCRDR_SC_OK;
}

int handle_json_packet (BusServer* bus_srv, BusEndpoint* endpoint,
        const struct timespec *ts, const char* json, unsigned int len)
{
    int retv = PCRDR_SC_OK;
    purc_variant_t jo = NULL, jo_tmp;

    HLOG_INFO ("Handling packet: \n%s\n", json);

    jo = purc_variant_make_from_json_string(json, len);
    if (jo == NULL || !purc_variant_is_object(jo)) {
        retv = PCRDR_SC_UNPROCESSABLE_PACKET;
        goto done;
    }

    if ((jo_tmp = purc_variant_object_get_by_ckey(jo, "packetType"))) {
        const char *pack_type;
        pack_type = purc_variant_get_string_const(jo_tmp);
        if (pack_type == NULL) {
            retv = PCRDR_SC_BAD_REQUEST;
            goto done;
        }

        if (strcasecmp (pack_type, "auth") == 0) {
            retv = handle_auth_packet (bus_srv, endpoint, jo);
        }
        else if (strcasecmp (pack_type, "call") == 0) {
            retv = handle_call_packet (bus_srv, endpoint, jo, ts);
        }
        else if (strcasecmp (pack_type, "result") == 0) {
            retv = handle_result_packet (bus_srv, endpoint, jo, ts);
        }
        else if (strcasecmp (pack_type, "event") == 0) {
            retv = handle_event_packet (bus_srv, endpoint, jo, ts);
        }
        else {
            retv = PCRDR_SC_BAD_REQUEST;
        }
    }
    else {
        retv = PCRDR_SC_BAD_REQUEST;
    }

done:
    if (jo)
        purc_variant_unref(jo);

    return retv;
}

int register_procedure (BusServer *bus_srv, BusEndpoint* endpoint,
        const char* method_name,
        const char* for_host, const char* for_app, method_handler handler)
{
    (void)bus_srv;
    int retv = PCRDR_SC_OK;
    MethodInfo *info;

    if (!hbdbus_is_valid_method_name (method_name))
        return PCRDR_SC_BAD_REQUEST;

    if (kvlist_get (&endpoint->method_list, method_name)) {
        return PCRDR_SC_CONFLICT;
    }

    if ((info = calloc (1, sizeof (MethodInfo))) == NULL)
        return PCRDR_SC_INSUFFICIENT_STORAGE;

    if (!init_pattern_list (&info->host_patt_list, for_host)) {
        retv = PCRDR_SC_INSUFFICIENT_STORAGE;
        goto failed;
    }

    if (info->host_patt_list.nr_patterns == 0) {
        retv = PCRDR_SC_NOT_ACCEPTABLE;
        goto failed;
    }

    if (!init_pattern_list (&info->app_patt_list, for_app)) {
        retv = PCRDR_SC_INSUFFICIENT_STORAGE;
        goto failed;
    }

    if (info->app_patt_list.nr_patterns == 0) {
        retv = PCRDR_SC_NOT_ACCEPTABLE;
        goto failed;
    }

    info->handler = handler;

    if (!kvlist_set (&endpoint->method_list, method_name, &info)) {
        retv = PCRDR_SC_INSUFFICIENT_STORAGE;
        goto failed;
    }

    HLOG_INFO ("New procedure registered: edpt://%s/%s/%s/method/%s (%p)\n",
            endpoint->host_name, endpoint->app_name, endpoint->runner_name,
            method_name, info);
    return PCRDR_SC_OK;

failed:
    cleanup_pattern_list (&info->host_patt_list);
    cleanup_pattern_list (&info->app_patt_list);
    free (info);
    return retv;
}

int revoke_procedure (BusServer *bus_srv, BusEndpoint* endpoint, const char* method_name)
{
    (void)bus_srv;
    void *data;
    MethodInfo *info;

    if (!hbdbus_is_valid_method_name (method_name))
        return PCRDR_SC_BAD_REQUEST;

    if ((data = kvlist_get (&endpoint->method_list, method_name)) == NULL) {
        return PCRDR_SC_NOT_FOUND;
    }

    info = *(MethodInfo **)data;
    cleanup_pattern_list (&info->host_patt_list);
    cleanup_pattern_list (&info->app_patt_list);
    /* TODO: cancel pending calls */
    free (info);

    kvlist_delete (&endpoint->method_list, method_name);
    return PCRDR_SC_OK;
}

int register_event (BusServer *bus_srv, BusEndpoint* endpoint,
        const char* bubble_name,
        const char* for_host, const char* for_app)
{
    (void)bus_srv;
    int retv = PCRDR_SC_OK;
    BubbleInfo *info;

    HLOG_INFO ("register_event: %s (%s, %s)\n", bubble_name, for_host, for_app);

    if (!hbdbus_is_valid_bubble_name (bubble_name))
        return PCRDR_SC_BAD_REQUEST;

    if (kvlist_get (&endpoint->bubble_list, bubble_name)) {
        return PCRDR_SC_CONFLICT;
    }

    if ((info = calloc (1, sizeof (BubbleInfo))) == NULL)
        return PCRDR_SC_INSUFFICIENT_STORAGE;

    if (!init_pattern_list (&info->host_patt_list, for_host)) {
        retv = PCRDR_SC_INSUFFICIENT_STORAGE;
        goto failed;
    }

    if (info->host_patt_list.nr_patterns == 0) {
        retv = PCRDR_SC_NOT_ACCEPTABLE;
        goto failed;
    }

    if (!init_pattern_list (&info->app_patt_list, for_app)) {
        retv = PCRDR_SC_INSUFFICIENT_STORAGE;
        goto failed;
    }

    if (info->app_patt_list.nr_patterns == 0) {
        retv = PCRDR_SC_NOT_ACCEPTABLE;
        goto failed;
    }

    kvlist_init (&info->subscriber_list, NULL, true);

    if (!kvlist_set (&endpoint->bubble_list, bubble_name, &info)) {
        retv = PCRDR_SC_INSUFFICIENT_STORAGE;
        goto failed;
    }

    HLOG_INFO ("New event registered: edpt://%s/%s/%s/bubble/%s (%p)\n",
            endpoint->host_name, endpoint->app_name, endpoint->runner_name,
            bubble_name, info);
    return PCRDR_SC_OK;

failed:
    cleanup_pattern_list (&info->host_patt_list);
    cleanup_pattern_list (&info->app_patt_list);
    free (info);
    return retv;
}

int revoke_event (BusServer *bus_srv, BusEndpoint *endpoint, const char* bubble_name)
{
    (void)bus_srv;
    const char* name;
    void *data;
    BubbleInfo *bubble;

    if (!hbdbus_is_valid_bubble_name (bubble_name))
        return PCRDR_SC_BAD_REQUEST;

    if ((data = kvlist_get (&endpoint->bubble_list, bubble_name)) == NULL) {
        return PCRDR_SC_NOT_FOUND;
    }

    bubble = *(BubbleInfo **)data;
    cleanup_pattern_list (&bubble->host_patt_list);
    cleanup_pattern_list (&bubble->app_patt_list);

    /* notify subscribers */
    kvlist_for_each (&bubble->subscriber_list, name, data) {
        void *sub_data;
        BusEndpoint* subscriber;
        sub_data = kvlist_get (&bus_srv->endpoint_list, name);

        if (sub_data) {
            subscriber = *(BusEndpoint **)sub_data;
            fire_system_event (bus_srv, SBT_LOST_EVENT_BUBBLE,
                    endpoint, subscriber, bubble_name);
        }
    }

    kvlist_free (&bubble->subscriber_list);
    free (bubble);

    kvlist_delete (&endpoint->bubble_list, bubble_name);
    return PCRDR_SC_OK;
}

int subscribe_event (BusServer *bus_srv, BusEndpoint* endpoint,
        const char* bubble_name, BusEndpoint* subscriber)
{
    (void)bus_srv;
    void *data;
    BubbleInfo *info;
    char subscriber_name [HBDBUS_LEN_ENDPOINT_NAME + 1];
    char event_name [HBDBUS_LEN_ENDPOINT_NAME + HBDBUS_LEN_BUBBLE_NAME + 2];

    if (!hbdbus_is_valid_bubble_name (bubble_name))
        return PCRDR_SC_BAD_REQUEST;

    if ((data = kvlist_get (&endpoint->bubble_list, bubble_name)) == NULL) {
        return PCRDR_SC_NOT_FOUND;
    }

    assemble_endpoint_name (subscriber, subscriber_name);

    assemble_endpoint_name (endpoint, event_name);
    strcat (event_name, "/");
    strcat (event_name, bubble_name);

    info = *(BubbleInfo **)data;
    if (kvlist_get (&info->subscriber_list, subscriber_name)) {
        HLOG_ERR ("Duplicated subscriber (%s) for bubble: %s\n",
                subscriber_name, bubble_name);
        return PCRDR_SC_CONFLICT;
    }

    if (!match_pattern (&info->host_patt_list, subscriber->host_name,
                1, HBDBUS_PATTERN_VAR_SELF, endpoint->host_name)) {
        return PCRDR_SC_FORBIDDEN;
    }

    if (!match_pattern (&info->app_patt_list, subscriber->app_name,
                1, HBDBUS_PATTERN_VAR_OWNER, endpoint->app_name)) {
        return PCRDR_SC_FORBIDDEN;
    }

    if (!kvlist_set (&subscriber->subscribed_list, event_name, &endpoint))
        return PCRDR_SC_INSUFFICIENT_STORAGE;

    if (!kvlist_set (&info->subscriber_list, subscriber_name, &subscriber)) {
        kvlist_delete (&subscriber->subscribed_list, event_name);
        return PCRDR_SC_INSUFFICIENT_STORAGE;
    }

    return PCRDR_SC_OK;
}

int unsubscribe_event (BusServer *bus_srv, BusEndpoint* endpoint,
        const char* bubble_name, BusEndpoint* subscriber)
{
    (void)bus_srv;
    void *data;
    BubbleInfo *info;
    char subscriber_name [HBDBUS_LEN_ENDPOINT_NAME + 1];
    char event_name [HBDBUS_LEN_ENDPOINT_NAME + HBDBUS_LEN_BUBBLE_NAME + 2];

    if (!hbdbus_is_valid_bubble_name (bubble_name)) {
        HLOG_ERR ("Invalid bubble name: %s\n", bubble_name);
        return PCRDR_SC_BAD_REQUEST;
    }

    if ((data = kvlist_get (&endpoint->bubble_list, bubble_name)) == NULL) {
        HLOG_ERR ("No such bubble: %s\n", bubble_name);
        return PCRDR_SC_NOT_FOUND;
    }

    assemble_endpoint_name (subscriber, subscriber_name);
    assemble_endpoint_name (endpoint, event_name);
    strcat (event_name, "/");
    strcat (event_name, bubble_name);

    info = *(BubbleInfo **)data;
    if (kvlist_get (&info->subscriber_list, subscriber_name) == NULL) {
        HLOG_ERR ("No such subscriber: %s\n", subscriber_name);
        return PCRDR_SC_NOT_FOUND;
    }

    kvlist_delete (&info->subscriber_list, subscriber_name);
    kvlist_delete (&subscriber->subscribed_list, event_name);
    return PCRDR_SC_OK;
}

size_t fire_system_event (BusServer* bus_srv, int bubble_type,
        BusEndpoint* cause, BusEndpoint* to, const char* add_msg)
{
    const char* bubble_name;
    int n = 0;
    size_t nr_fired = 0;
    char packet_buff [HBDBUS_DEF_PACKET_BUFF_SIZE];
    char bubble_data [HBDBUS_MIN_PACKET_BUFF_SIZE];
    char* escaped_bubble_data = NULL;
    bool to_all = false;

    if (bubble_type == SBT_NEW_ENDPOINT) {
        char peer_info [INET6_ADDRSTRLEN] = "";

        if (cause->type == ET_UNIX_SOCKET) {
            USClient* usc = (USClient *)cause->entity.client;
            snprintf (peer_info, sizeof (peer_info), "%d", usc->pid);
        }
        else {
            WSClient* wsc = (WSClient *)cause->entity.client;
            strncpy (peer_info, wsc->remote_ip, /*sizeof (wsc->remote_ip)*/INET6_ADDRSTRLEN);
        }

        n = snprintf (bubble_data, sizeof (bubble_data),
                "{"
                "\"endpointType\":\"%s\","
                "\"endpointName\":\"edpt://%s/%s/%s\","
                "\"peerInfo\":\"%s\","
                "\"totalEndpoints\":%d"
                "}",
                (cause->type == ET_UNIX_SOCKET) ? "unix" : "web",
                cause->host_name, cause->app_name, cause->runner_name,
                peer_info,
                bus_srv->nr_endpoints);
        bubble_name = HBDBUS_BUBBLE_NEWENDPOINT;
    }
    else if (bubble_type == SBT_BROKEN_ENDPOINT) {
#if 0
        char peer_info [INET6_ADDRSTRLEN] = "";

        if (cause->type == ET_UNIX_SOCKET) {
            USClient* usc = (USClient *)cause->entity.client;
            snprintf (peer_info, sizeof (peer_info), "%d", usc->pid);
        }
        else {
            WSClient* wsc = (WSClient *)cause->entity.client;
            strncpy (peer_info, wsc->remote_ip, sizeof (wsc->remote_ip));
        }
#else
        const char *peer_info  = "N/A";
#endif

        n = snprintf (bubble_data, sizeof (bubble_data),
                "{"
                "\"endpointType\":\"%s\","
                "\"endpointName\":\"edpt://%s/%s/%s\","
                "\"peerInfo\":\"%s\","
                "\"brokenReason\":\"%s\","
                "\"totalEndpoints\":%d"
                "}",
                (cause->type == ET_UNIX_SOCKET) ? "unix" : "web",
                cause->host_name, cause->app_name, cause->runner_name,
                peer_info, add_msg,
                bus_srv->nr_endpoints);
        bubble_name = HBDBUS_BUBBLE_BROKENENDPOINT;
    }
    else if (bubble_type == SBT_LOST_EVENT_GENERATOR) {
        n = snprintf (bubble_data, sizeof (bubble_data),
                "{"
                "\"endpointName\":\"edpt://%s/%s/%s\","
                "}",
                cause->host_name, cause->app_name, cause->runner_name);
        bubble_name = HBDBUS_BUBBLE_LOSTEVENTGENERATOR;
    }
    else if (bubble_type == SBT_LOST_EVENT_BUBBLE) {
        n = snprintf (bubble_data, sizeof (bubble_data),
                "{"
                "\"endpointName\":\"edpt://%s/%s/%s\","
                "\"bubbleName\":\"%s\""
                "}",
                cause->host_name, cause->app_name, cause->runner_name,
                add_msg);
        bubble_name = HBDBUS_BUBBLE_LOSTEVENTBUBBLE;
    }
    else if (bubble_type == SBT_SYSTEM_SHUTTING_DOWN) {
        n = snprintf (bubble_data, sizeof (bubble_data),
                "{"
                "\"endpointName\":\"edpt://%s/%s/%s\","
                "\"shutdownTime\":\"%s\""
                "}",
                cause->host_name, cause->app_name, cause->runner_name,
                add_msg);
        bubble_name = HBDBUS_BUBBLE_SYSTEMSHUTTINGDOWN;
        to_all = true;
    }
    else {
        return 0;
    }

    if (n > 0 && (size_t)n < sizeof (bubble_data)) {
        escaped_bubble_data = pcutils_escape_string_for_json (bubble_data);
        if (escaped_bubble_data == NULL)
            return 0;
    }
    else {
        return 0;
    }

    n = snprintf (packet_buff, sizeof (packet_buff),
        "{"
        "\"packetType\": \"event\","
        "\"eventId\": \"NOTIFICATION\","
        "\"fromEndpoint\": \"edpt://%s/%s/%s\","
        "\"fromBubble\": \"%s\","
        "\"bubbleData\": \"%s\","
        "\"timeDiff\":0.0"
        "}",
        bus_srv->endpoint_builtin->host_name,
        bus_srv->endpoint_builtin->app_name,
        bus_srv->endpoint_builtin->runner_name,
        bubble_name,
        escaped_bubble_data);

    if (n > 0 && (size_t)n < sizeof (packet_buff)) {
        if (to) {
            send_packet_to_endpoint (bus_srv, to, packet_buff, n);
            nr_fired++;
        }
        else if (to_all) {
            const char* name;
            void *data;
            kvlist_for_each (&bus_srv->endpoint_list, name, data) {
                BusEndpoint* edpt = *(BusEndpoint **)data;

                if (edpt != bus_srv->endpoint_builtin) {
                    send_packet_to_endpoint (bus_srv, edpt, packet_buff, n);
                    nr_fired++;
                }
            }
        }
        else {
            BubbleInfo *bubble;
            const char* name;
            void *next, *data;

            data = kvlist_get (&bus_srv->endpoint_builtin->bubble_list, bubble_name);
            if (data) {
                bubble = *(BubbleInfo **)data;
            }
            else {
                goto failed;
            }

            kvlist_for_each_safe (&bubble->subscriber_list, name, next, data) {
                void *sub_data;

                sub_data = kvlist_get (&bus_srv->endpoint_list, name);

                // forward event to subscriber.
                if (sub_data) {
                    BusEndpoint* subscriber;

                    subscriber = *(BusEndpoint **)sub_data;
                    send_packet_to_endpoint (bus_srv, subscriber, packet_buff, n);
                    nr_fired++;
                }
                else {
                    kvlist_delete (&bubble->subscriber_list, name);
                }
            }
        }
    }
    else {
        HLOG_ERR ("The size of buffer for system event packet is too small.\n");
    }

failed:
    if (escaped_bubble_data)
        free (escaped_bubble_data);

    return nr_fired;
}

