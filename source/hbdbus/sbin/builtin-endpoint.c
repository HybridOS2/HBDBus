/*
** builtin-endpoint.c -- The implemetation of the builtin endpoint.
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

#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <purc/purc-helpers.h>

#include "internal/log.h"

#include "hbdbus.h"
#include "endpoint.h"
#include "unixsocket.h"
#include "websocket.h"

static char *
default_method_handler (BusServer *bus_srv,
        BusEndpoint* from, BusEndpoint* to,
        const char* method_name, const char* method_param, int* ret_code)
{
    char buff_in_stack [HBDBUS_DEF_PACKET_BUFF_SIZE];
    int n = 0;
    char* packet_buff = buff_in_stack;
    const CallInfo *call_info = from->sta_data;
    size_t len_param = strlen (method_param) * 2 + 1;
    size_t sz_packet_buff = sizeof (buff_in_stack);
    char* escaped_param;

    if (len_param > HBDBUS_MIN_PACKET_BUFF_SIZE) {
        sz_packet_buff = HBDBUS_MIN_PACKET_BUFF_SIZE + len_param;
        packet_buff = malloc (HBDBUS_MIN_PACKET_BUFF_SIZE + len_param);
        if (packet_buff == NULL) {
            *ret_code = PCRDR_SC_INSUFFICIENT_STORAGE;
            return NULL;
        }
    }

    if (method_param)
        escaped_param = pcutils_escape_string_for_json (method_param);
    else
        escaped_param = NULL;

    n = snprintf (packet_buff, sz_packet_buff, 
            "{"
            "\"packetType\":\"call\","
            "\"callId\":\"%s\","
            "\"resultId\":\"%s\","
            "\"fromEndpoint\":\"edpt://%s/%s/%s\","
            "\"toMethod\":\"%s\","
            "\"timeDiff\":%.9f,"
            "\"parameter\":\"%s\""
            "}",
            call_info->call_id, call_info->result_id,
            from->host_name, from->app_name, from->runner_name,
            method_name,
            call_info->time_diff,
            escaped_param ? escaped_param : "");

    if (escaped_param)
        free (escaped_param);

    if (n < 0 || (size_t)n >= sz_packet_buff) {
        HLOG_ERR ("The size of buffer for call packet is too small.\n");
        *ret_code = PCRDR_SC_INTERNAL_SERVER_ERROR;
    }
    else {
        if (send_packet_to_endpoint (bus_srv, to, packet_buff, n)) {
            *ret_code = PCRDR_SC_BAD_CALLEE;
        }
        else {
            *ret_code = PCRDR_SC_ACCEPTED;
        }
    }

    if (packet_buff != NULL && packet_buff != buff_in_stack) {
        free (packet_buff);
    }

    return NULL;
}

static char *
builtin_method_echo (BusServer *bus_srv,
        BusEndpoint* from, BusEndpoint* to,
        const char* method_name, const char* method_param, int* ret_code)
{
    (void)bus_srv;
    (void)from;
    (void)to;
    (void)method_name;
    assert (from->type != ET_BUILTIN);
    assert (to->type == ET_BUILTIN);
    assert (strcasecmp (method_name, HBDBUS_METHOD_ECHO) == 0);

    *ret_code = PCRDR_SC_OK;

    if (method_param) {
        return strdup (method_param);
    }

    return strdup ("ARE YOU JOKING ME?");
}

static char *
builtin_method_terminate (BusServer *bus_srv,
        BusEndpoint* from, BusEndpoint* to,
        const char* method_name, const char* method_param, int* ret_code)
{
    (void)bus_srv;
    (void)from;
    (void)to;
    (void)method_name;
    assert (from->type != ET_BUILTIN);
    assert (to->type == ET_BUILTIN);
    assert (strcasecmp (method_name, HBDBUS_METHOD_TERMINATE) == 0);

    purc_variant_t jo, jo_tmp;
    jo = purc_variant_make_from_json_string(method_param, strlen(method_param));
    if (jo == NULL || !purc_variant_is_object(jo)) {
        goto failed;
    }

    uint32_t seconds;
    if ((jo_tmp = purc_variant_object_get_by_ckey(jo, "afterSeconds")) &&
        (purc_variant_cast_to_uint32(jo_tmp, &seconds, false))) {
        bus_srv->shutdown_time = time(NULL) + seconds;
        HLOG_INFO("System will shut down in %u seconds\n", seconds);
    }
    else {
        goto failed;
    }

    purc_variant_unref(jo);

    char buf[128];
    sprintf(buf, "%lu", (unsigned long)bus_srv->shutdown_time);
    size_t nr_fired = fire_system_event(bus_srv, SBT_SYSTEM_SHUTTING_DOWN,
        from, NULL, buf);

    *ret_code = PCRDR_SC_OK;
    sprintf(buf, "%lu", (unsigned long)nr_fired);
    return strdup(buf);

failed:
    if (jo)
        purc_variant_unref(jo);

    *ret_code = PCRDR_SC_BAD_REQUEST;
    return NULL;
}

static char *
builtin_method_register_procedure (BusServer *bus_srv,
        BusEndpoint* from, BusEndpoint* to,
        const char* method_name, const char* method_param, int* ret_code)
{
    (void)bus_srv;
    (void)from;
    (void)to;
    (void)method_name;
    purc_variant_t jo = NULL, jo_tmp;
    const char *param_method_name, *param_for_host, *param_for_app;

    assert (from->type != ET_BUILTIN);
    assert (to->type == ET_BUILTIN);
    assert (strcasecmp (method_name, HBDBUS_METHOD_REGISTERPROCEDURE) == 0);

    jo = purc_variant_make_from_json_string(method_param, strlen(method_param));
    if (jo == NULL || !purc_variant_is_object(jo)) {
        goto failed;
    }

    if ((jo_tmp = purc_variant_object_get_by_ckey (jo, "methodName")) &&
        (param_method_name = purc_variant_get_string_const (jo_tmp))) {
    }
    else {
        goto failed;
    }

    if ((jo_tmp = purc_variant_object_get_by_ckey (jo, "forHost")) &&
        (param_for_host = purc_variant_get_string_const (jo_tmp))) {
    }
    else {
        goto failed;
    }

    if ((jo_tmp = purc_variant_object_get_by_ckey (jo, "forApp")) &&
        (param_for_app = purc_variant_get_string_const (jo_tmp))) {
    }
    else {
        goto failed;
    }

    *ret_code = register_procedure (bus_srv, from,
            param_method_name, param_for_host, param_for_app,
            default_method_handler);
    purc_variant_unref(jo);

    return NULL;

failed:
    if (jo)
        purc_variant_unref (jo);

    *ret_code = PCRDR_SC_BAD_REQUEST;
    return NULL;
}

static char *
builtin_method_revoke_procedure (BusServer *bus_srv,
        BusEndpoint* from, BusEndpoint* to,
        const char* method_name, const char* method_param, int* ret_code)
{
    (void)bus_srv;
    (void)from;
    (void)to;
    (void)method_name;
    purc_variant_t jo = NULL, jo_tmp;
    const char *param_method_name;

    assert (from->type != ET_BUILTIN);
    assert (to->type == ET_BUILTIN);
    assert (strcasecmp (method_name, HBDBUS_METHOD_REVOKEPROCEDURE) == 0);

    jo = purc_variant_make_from_json_string(method_param, strlen (method_param));
    if (jo == NULL || !purc_variant_is_object(jo)) {
        goto failed;
    }

    if ((jo_tmp = purc_variant_object_get_by_ckey (jo, "methodName")) &&
        (param_method_name = purc_variant_get_string_const (jo_tmp))) {
    }
    else {
        goto failed;
    }

    *ret_code = revoke_procedure (bus_srv, from, param_method_name);
    purc_variant_unref (jo);
    return NULL;

failed:
    if (jo)
        purc_variant_unref (jo);
    *ret_code = PCRDR_SC_BAD_REQUEST;
    return NULL;
}

static char *
builtin_method_register_event (BusServer *bus_srv,
        BusEndpoint* from, BusEndpoint* to,
        const char* method_name, const char* method_param, int* ret_code)
{
    (void)bus_srv;
    (void)from;
    (void)to;
    (void)method_name;
    purc_variant_t jo = NULL, jo_tmp;
    const char *param_bubble_name, *param_for_host, *param_for_app;

    assert (from->type != ET_BUILTIN);
    assert (to->type == ET_BUILTIN);
    assert (strcasecmp (method_name, HBDBUS_METHOD_REGISTEREVENT) == 0);

    HLOG_INFO ("parameter: %s\n", method_param);

    jo = purc_variant_make_from_json_string(method_param, strlen(method_param));
    if (jo == NULL || !purc_variant_is_object(jo)) {
        goto failed;
    }

    if ((jo_tmp = purc_variant_object_get_by_ckey (jo, "bubbleName")) &&
        (param_bubble_name = purc_variant_get_string_const (jo_tmp))) {
    }
    else {
        goto failed;
    }

    if ((jo_tmp = purc_variant_object_get_by_ckey (jo, "forHost")) &&
        (param_for_host = purc_variant_get_string_const (jo_tmp))) {
    }
    else {
        goto failed;
    }

    if ((jo_tmp = purc_variant_object_get_by_ckey (jo, "forApp")) &&
        (param_for_app = purc_variant_get_string_const (jo_tmp))) {
    }
    else {
        goto failed;
    }

    *ret_code = register_event (bus_srv, from,
            param_bubble_name, param_for_host, param_for_app);
    purc_variant_unref (jo);
    return NULL;

failed:
    if (jo)
        purc_variant_unref (jo);

    *ret_code = PCRDR_SC_BAD_REQUEST;
    return NULL;
}

static char *
builtin_method_revoke_event (BusServer *bus_srv,
        BusEndpoint* from, BusEndpoint* to,
        const char* method_name, const char* method_param, int* ret_code)
{
    (void)bus_srv;
    (void)from;
    (void)to;
    (void)method_name;
    purc_variant_t jo = NULL, jo_tmp;
    const char *param_bubble_name;

    assert (from->type != ET_BUILTIN);
    assert (to->type == ET_BUILTIN);
    assert (strcasecmp (method_name, HBDBUS_METHOD_REVOKEEVENT) == 0);

    jo = purc_variant_make_from_json_string(method_param, strlen(method_param));
    if (jo == NULL || !purc_variant_is_object(jo)) {
        goto failed;
    }

    if ((jo_tmp = purc_variant_object_get_by_ckey (jo, "bubbleName")) &&
        (param_bubble_name = purc_variant_get_string_const (jo_tmp))) {
    }
    else {
        goto failed;
    }

    *ret_code = revoke_event (bus_srv, from, param_bubble_name);
    purc_variant_unref (jo);
    return NULL;

failed:
    if (jo)
        purc_variant_unref (jo);

    *ret_code = PCRDR_SC_BAD_REQUEST;
    return NULL;
}

static char *
builtin_method_subscribe_event (BusServer *bus_srv,
        BusEndpoint* from, BusEndpoint* to,
        const char* method_name, const char* method_param, int* ret_code)
{
    (void)bus_srv;
    (void)from;
    (void)to;
    (void)method_name;
    purc_variant_t jo = NULL, jo_tmp;
    const char *param_endpoint_name, *param_bubble_name;
    BusEndpoint* target_endpoint = NULL;

    assert (from->type != ET_BUILTIN);
    assert (to->type == ET_BUILTIN);
    assert (strcasecmp (method_name, HBDBUS_METHOD_SUBSCRIBEEVENT) == 0);

    *ret_code = PCRDR_SC_BAD_REQUEST;

    jo = purc_variant_make_from_json_string(method_param, strlen(method_param));
    if (jo == NULL || !purc_variant_is_object(jo)) {
        goto failed;
    }

    if ((jo_tmp = purc_variant_object_get_by_ckey (jo, "endpointName")) &&
        (param_endpoint_name = purc_variant_get_string_const (jo_tmp))) {
        void *data;
        char normalized_name [HBDBUS_LEN_ENDPOINT_NAME + 1];

        purc_name_tolower_copy (param_endpoint_name, normalized_name,
                HBDBUS_LEN_ENDPOINT_NAME);
        if ((data = kvlist_get (&bus_srv->endpoint_list, normalized_name))) {
            target_endpoint = *(BusEndpoint **)data;
        }
        else {
            *ret_code = PCRDR_SC_NOT_FOUND;
            goto failed;
        }
    }
    else {
        goto failed;
    }

    if ((jo_tmp = purc_variant_object_get_by_ckey (jo, "bubbleName")) &&
        (param_bubble_name = purc_variant_get_string_const (jo_tmp))) {
    }
    else {
        goto failed;
    }

    *ret_code = subscribe_event (bus_srv, target_endpoint, param_bubble_name, from);
    purc_variant_unref (jo);
    return NULL;

failed:
    if (jo)
        purc_variant_unref (jo);

    return NULL;
}

static char *
builtin_method_unsubscribe_event (BusServer *bus_srv,
        BusEndpoint* from, BusEndpoint* to,
        const char* method_name, const char* method_param, int* ret_code)
{
    (void)bus_srv;
    (void)from;
    (void)to;
    (void)method_name;
    purc_variant_t jo = NULL, jo_tmp;
    const char *param_endpoint_name, *param_bubble_name;
    BusEndpoint* target_endpoint = NULL;

    assert (from->type != ET_BUILTIN);
    assert (to->type == ET_BUILTIN);
    assert (strcasecmp (method_name, HBDBUS_METHOD_UNSUBSCRIBEEVENT) == 0);

    *ret_code = PCRDR_SC_BAD_REQUEST;

    jo = purc_variant_make_from_json_string(method_param, strlen(method_param));
    if (jo == NULL || !purc_variant_is_object(jo)) {
        goto failed;
    }

    if ((jo_tmp = purc_variant_object_get_by_ckey (jo, "endpointName")) &&
            (param_endpoint_name = purc_variant_get_string_const (jo_tmp))) {
        void *data;
        char normalized_name [HBDBUS_LEN_ENDPOINT_NAME + 1];

        purc_name_tolower_copy (param_endpoint_name, normalized_name,
                HBDBUS_LEN_ENDPOINT_NAME);
        if ((data = kvlist_get (&bus_srv->endpoint_list, normalized_name))) {
            target_endpoint = *(BusEndpoint **)data;
        }
        else {
            HLOG_ERR ("No such endpoint: %s\n", normalized_name);
            *ret_code = PCRDR_SC_NOT_FOUND;
            goto failed;
        }
    }
    else {
        goto failed;
    }

    if ((jo_tmp = purc_variant_object_get_by_ckey (jo, "bubbleName")) &&
            (param_bubble_name = purc_variant_get_string_const (jo_tmp))) {
    }
    else {
        *ret_code = PCRDR_SC_BAD_REQUEST;
        goto failed;
    }

    *ret_code = unsubscribe_event (bus_srv, target_endpoint,
            param_bubble_name, from);
    purc_variant_unref (jo);
    return NULL;

failed:
    if (jo)
        purc_variant_unref (jo);

    return NULL;
}

static char *
builtin_method_list_endpoints (BusServer *bus_srv,
        BusEndpoint* from, BusEndpoint* to,
        const char* method_name, const char* method_param, int* ret_code)
{
    (void)bus_srv;
    (void)from;
    (void)to;
    (void)method_name;
    (void)method_param;
    struct pcutils_printbuf my_buff, *pb = &my_buff;
    const char *endpoint_name;
    void *data;
    int nr_endpoints;

    assert (from->type != ET_BUILTIN);
    assert (to->type == ET_BUILTIN);
    assert (strcasecmp (method_name, HBDBUS_METHOD_LISTENDPOINTS) == 0);

    HLOG_INFO("called\n");

    if (pcutils_printbuf_init (pb)) {
        HLOG_ERR("Failed to initialize printbuf.\n");
        *ret_code = PCRDR_SC_INSUFFICIENT_STORAGE;
        return NULL;
    }

    pcutils_printbuf_strappend (pb, "[");

    nr_endpoints = 0;
    kvlist_for_each (&bus_srv->endpoint_list, endpoint_name, data) {
        const char *sub_name;
        void *sub_data;
        BusEndpoint* endpoint = *(BusEndpoint **)data;
        int n;

        pcutils_printbuf_strappend (pb, "{\"endpointName\":");
        pcutils_printbuf_format (pb, "\"%s\",", endpoint_name);
        pcutils_printbuf_format (pb, "\"livingSeconds\":%lu,",
                purc_get_monotoic_time () - endpoint->t_created);

        n = 0;
        pcutils_printbuf_strappend (pb, "\"methods\":[");
        kvlist_for_each (&endpoint->method_list, sub_name, sub_data) {
            pcutils_printbuf_format (pb, "\"%s\",", sub_name);
            n++;
        }
        if (n > 0)
            pcutils_printbuf_shrink (pb, 1);
        pcutils_printbuf_strappend (pb, "],");

        n = 0;
        pcutils_printbuf_strappend (pb, "\"bubbles\":[");
        kvlist_for_each (&endpoint->bubble_list, sub_name, sub_data) {
            pcutils_printbuf_format (pb, "\"%s\",", sub_name);
            n++;
        }
        if (n > 0)
            pcutils_printbuf_shrink (pb, 1);
        pcutils_printbuf_strappend (pb, "],");

        pcutils_printbuf_format (pb, "\"memUsed\":%lu,", endpoint->entity.sz_sock_mem);
        pcutils_printbuf_format (pb, "\"peakMemUsed\":%lu", endpoint->entity.peak_sz_sock_mem);
        pcutils_printbuf_strappend (pb, "},");
        nr_endpoints++;
    }
    if (nr_endpoints)
        pcutils_printbuf_shrink (pb, 1);

    pcutils_printbuf_strappend (pb, "]");

    *ret_code = PCRDR_SC_OK;
    return pb->buf;
}

static char *
builtin_method_list_procedures (BusServer *bus_srv,
        BusEndpoint* from, BusEndpoint* to,
        const char* method_name, const char* method_param, int* ret_code)
{
    (void)bus_srv;
    (void)from;
    (void)to;
    (void)method_name;
    (void)method_param;
    struct pcutils_printbuf my_buff, *pb = &my_buff;
    const char *endpoint_name;
    void *data;
    int n;

    assert (from->type != ET_BUILTIN);
    assert (to->type == ET_BUILTIN);
    assert (strcasecmp (method_name, HBDBUS_METHOD_LISTPROCEDURES) == 0);

    if (pcutils_printbuf_init (pb)) {
        *ret_code = PCRDR_SC_INSUFFICIENT_STORAGE;
        return NULL;
    }

    n = 0;
    pcutils_printbuf_strappend (pb, "[");
    if (purc_is_valid_endpoint_name (method_param)) {
        char normalized_name [HBDBUS_LEN_ENDPOINT_NAME + 1];

        purc_name_tolower_copy (method_param, normalized_name,
                HBDBUS_LEN_ENDPOINT_NAME);

        if ((data = kvlist_get (&bus_srv->endpoint_list, normalized_name))) {
            const char *method_name;
            void *sub_data;
            BusEndpoint* endpoint = *(BusEndpoint **)data;
            int nr_methods = 0;

            pcutils_printbuf_strappend (pb, "{\"endpointName\":");
            pcutils_printbuf_format (pb, "\"%s\",", normalized_name);

            pcutils_printbuf_strappend (pb, "\"methods\": [");
            kvlist_for_each (&endpoint->method_list, method_name, sub_data) {
                MethodInfo *method_info = *(MethodInfo **)sub_data;

                if (match_pattern (&method_info->host_patt_list, from->host_name,
                            1, HBDBUS_PATTERN_VAR_SELF, endpoint->host_name) &&
                        match_pattern (&method_info->app_patt_list, from->app_name,
                            1, HBDBUS_PATTERN_VAR_OWNER, endpoint->app_name)) {

                    pcutils_printbuf_strappend (pb, "\"");
                    pcutils_printbuf_memappend (pb, method_name, 0);
                    pcutils_printbuf_strappend (pb, "\",");

                    nr_methods++;
                }
            }

            if (nr_methods > 0) {
                pcutils_printbuf_shrink (pb, 1);
            }
            pcutils_printbuf_strappend (pb, "]}");
        }
    }
    else {
        kvlist_for_each (&bus_srv->endpoint_list, endpoint_name, data) {
            const char *method_name;
            void *sub_data;
            BusEndpoint* endpoint = *(BusEndpoint **)data;
            int nr_methods = 0;

            pcutils_printbuf_strappend (pb, "{\"endpointName\":");
            pcutils_printbuf_format (pb, "\"%s\",", endpoint_name);

            pcutils_printbuf_strappend (pb, "\"methods\": [");
            kvlist_for_each (&endpoint->method_list, method_name, sub_data) {
                MethodInfo *method_info = *(MethodInfo **)sub_data;

                if (match_pattern (&method_info->host_patt_list, from->host_name,
                            1, HBDBUS_PATTERN_VAR_SELF, endpoint->host_name) &&
                        match_pattern (&method_info->app_patt_list, from->app_name,
                            1, HBDBUS_PATTERN_VAR_OWNER, endpoint->app_name)) {

                    pcutils_printbuf_strappend (pb, "\"");
                    pcutils_printbuf_memappend (pb, method_name, 0);
                    pcutils_printbuf_strappend (pb, "\",");

                    nr_methods++;
                }
            }

            if (nr_methods > 0) {
                pcutils_printbuf_shrink (pb, 1);
            }
            pcutils_printbuf_strappend (pb, "]},");

            n++;
        }
    }

    if (n > 0) {
        pcutils_printbuf_shrink (pb, 1);
    }
    pcutils_printbuf_strappend (pb, "]");

    *ret_code = PCRDR_SC_OK;
    return pb->buf;
}

static char *
builtin_method_list_events (BusServer *bus_srv,
        BusEndpoint* from, BusEndpoint* to,
        const char* method_name, const char* method_param, int* ret_code)
{
    (void)bus_srv;
    (void)from;
    (void)to;
    (void)method_name;
    (void)method_param;
    struct pcutils_printbuf my_buff, *pb = &my_buff;
    const char *endpoint_name;
    void *data;
    int n;

    assert (from->type != ET_BUILTIN);
    assert (to->type == ET_BUILTIN);
    assert (strcasecmp (method_name, HBDBUS_METHOD_LISTEVENTS) == 0);

    if (pcutils_printbuf_init (pb)) {
        *ret_code = PCRDR_SC_INSUFFICIENT_STORAGE;
        return NULL;
    }

    n = 0;
    pcutils_printbuf_strappend (pb, "[");
    if (purc_is_valid_endpoint_name (method_param)) {
        char normalized_name [HBDBUS_LEN_ENDPOINT_NAME + 1];

        purc_name_tolower_copy (method_param, normalized_name,
                HBDBUS_LEN_ENDPOINT_NAME);

        if ((data = kvlist_get (&bus_srv->endpoint_list, normalized_name))) {
            const char *bubble_name;
            void *sub_data;
            BusEndpoint* endpoint = *(BusEndpoint **)data;
            int nr_methods = 0;

            pcutils_printbuf_strappend (pb, "{\"endpointName\":");
            pcutils_printbuf_format (pb, "\"%s\",", normalized_name);

            pcutils_printbuf_strappend (pb, "\"bubbles\": [");
            kvlist_for_each (&endpoint->bubble_list, bubble_name, sub_data) {
                BubbleInfo *bubble_info = *(BubbleInfo **)sub_data;

                if (match_pattern (&bubble_info->host_patt_list, from->host_name,
                            1, HBDBUS_PATTERN_VAR_SELF, endpoint->host_name) &&
                        match_pattern (&bubble_info->app_patt_list, from->app_name,
                            1, HBDBUS_PATTERN_VAR_OWNER, endpoint->app_name)) {

                    pcutils_printbuf_strappend (pb, "\"");
                    pcutils_printbuf_memappend (pb, bubble_name, 0);
                    pcutils_printbuf_strappend (pb, "\",");

                    nr_methods++;
                }
            }

            if (nr_methods > 0) {
                pcutils_printbuf_shrink (pb, 1);
            }
            pcutils_printbuf_strappend (pb, "]}");
        }
    }
    else {
        kvlist_for_each (&bus_srv->endpoint_list, endpoint_name, data) {
            const char *bubble_name;
            void *sub_data;
            BusEndpoint* endpoint = *(BusEndpoint **)data;
            int nr_methods = 0;

            pcutils_printbuf_strappend (pb, "{\"endpointName\":");
            pcutils_printbuf_format (pb, "\"%s\",", endpoint_name);

            pcutils_printbuf_strappend (pb, "\"bubbles\": [");
            kvlist_for_each (&endpoint->bubble_list, bubble_name, sub_data) {
                BubbleInfo *bubble_info = *(BubbleInfo **)sub_data;

                if (match_pattern (&bubble_info->host_patt_list, from->host_name,
                            1, HBDBUS_PATTERN_VAR_SELF, endpoint->host_name) &&
                        match_pattern (&bubble_info->app_patt_list, from->app_name,
                            1, HBDBUS_PATTERN_VAR_OWNER, endpoint->app_name)) {

                    pcutils_printbuf_strappend (pb, "\"");
                    pcutils_printbuf_memappend (pb, bubble_name, 0);
                    pcutils_printbuf_strappend (pb, "\",");

                    nr_methods++;
                }
            }

            if (nr_methods > 0) {
                pcutils_printbuf_shrink (pb, 1);
            }
            pcutils_printbuf_strappend (pb, "]},");

            n++;
        }
    }

    if (n > 0) {
        pcutils_printbuf_shrink (pb, 1);
    }
    pcutils_printbuf_strappend (pb, "]");

    *ret_code = PCRDR_SC_OK;
    return pb->buf;
}

static char *
builtin_method_list_event_subscribers (BusServer *bus_srv,
        BusEndpoint* from, BusEndpoint* to,
        const char* method_name, const char* method_param, int* ret_code)
{
    (void)bus_srv;
    (void)from;
    (void)to;
    (void)method_name;
    (void)method_param;
    purc_variant_t jo = NULL, jo_tmp;
    const char *param_endpoint_name, *param_bubble_name;
    BusEndpoint *target_endpoint = NULL;
    BubbleInfo *bubble = NULL;

    assert (from->type != ET_BUILTIN);
    assert (to->type == ET_BUILTIN);
    assert (strcasecmp (method_name, HBDBUS_METHOD_LISTEVENTSUBSCRIBERS) == 0);

    struct pcutils_printbuf my_buff, *pb = &my_buff;

    if (pcutils_printbuf_init (pb)) {
        *ret_code = PCRDR_SC_INSUFFICIENT_STORAGE;
        return NULL;
    }

    *ret_code = PCRDR_SC_BAD_REQUEST;
    jo = purc_variant_make_from_json_string(method_param, strlen(method_param));
    if (jo == NULL || !purc_variant_is_object(jo)) {
        goto failed;
    }

    if ((jo_tmp = purc_variant_object_get_by_ckey (jo, "endpointName")) &&
        (param_endpoint_name = purc_variant_get_string_const (jo_tmp))) {
        void *data;
        char normalized_name [HBDBUS_LEN_ENDPOINT_NAME + 1];

        purc_name_tolower_copy (param_endpoint_name, normalized_name,
                HBDBUS_LEN_ENDPOINT_NAME);
        if ((data = kvlist_get (&bus_srv->endpoint_list, normalized_name))) {
            target_endpoint = *(BusEndpoint **)data;
        }
        else {
            *ret_code = PCRDR_SC_NOT_FOUND;
            goto failed;
        }
    }
    else {
        goto failed;
    }

    if ((jo_tmp = purc_variant_object_get_by_ckey (jo, "bubbleName")) &&
            (param_bubble_name = purc_variant_get_string_const (jo_tmp))) {
        void *data;
        if ((data = kvlist_get (&target_endpoint->bubble_list, param_bubble_name))) {
            bubble = *(BubbleInfo **)data;
        }
    }

    if (jo)
        purc_variant_unref (jo);

    if (bubble) {
        const char* name;
        void* data;
        int n;

        pcutils_printbuf_strappend (pb, "[");

        n = 0;
        kvlist_for_each (&bubble->subscriber_list, name, data) {
            void *sub_data = kvlist_get (&bus_srv->endpoint_list, name);

            if (sub_data) {
                pcutils_printbuf_strappend (pb, "\"");
                pcutils_printbuf_memappend (pb, name, 0);
                pcutils_printbuf_strappend (pb, "\",");
            }

            n++;
        }
        if (n > 0) {
            pcutils_printbuf_shrink (pb, 1);
        }

        pcutils_printbuf_strappend (pb, "]");

        *ret_code = PCRDR_SC_OK;
        return pb->buf;
    }
    else {
        *ret_code = PCRDR_SC_NOT_FOUND;
    }

    return NULL;

failed:
    if (jo)
        purc_variant_unref (jo);

    return NULL;
}

bool init_builtin_endpoint (BusServer *bus_srv, BusEndpoint* builtin)
{
    if (register_procedure (bus_srv, builtin, HBDBUS_METHOD_TERMINATE,
            HBDBUS_LOCALHOST, HBDBUS_SYSAPP_ANY,
            builtin_method_terminate) != PCRDR_SC_OK) {
        return false;
    }

    if (register_procedure (bus_srv, builtin, HBDBUS_METHOD_ECHO,
            HBDBUS_PATTERN_ANY, HBDBUS_PATTERN_ANY,
            builtin_method_echo) != PCRDR_SC_OK) {
        return false;
    }

    if (register_procedure (bus_srv, builtin, HBDBUS_METHOD_REGISTERPROCEDURE,
            HBDBUS_PATTERN_ANY, HBDBUS_PATTERN_ANY,
            builtin_method_register_procedure) != PCRDR_SC_OK) {
        return false;
    }

    if (register_procedure (bus_srv, builtin, HBDBUS_METHOD_REVOKEPROCEDURE,
            HBDBUS_PATTERN_ANY, HBDBUS_PATTERN_ANY,
            builtin_method_revoke_procedure) != PCRDR_SC_OK) {
        return false;
    }

    if (register_procedure (bus_srv, builtin, HBDBUS_METHOD_REGISTEREVENT,
            HBDBUS_PATTERN_ANY, HBDBUS_PATTERN_ANY,
            builtin_method_register_event) != PCRDR_SC_OK) {
        return false;
    }

    if (register_procedure (bus_srv, builtin, HBDBUS_METHOD_REVOKEEVENT,
            HBDBUS_PATTERN_ANY, HBDBUS_PATTERN_ANY,
            builtin_method_revoke_event) != PCRDR_SC_OK) {
        return false;
    }

    if (register_procedure (bus_srv, builtin, HBDBUS_METHOD_SUBSCRIBEEVENT,
            HBDBUS_PATTERN_ANY, HBDBUS_PATTERN_ANY,
            builtin_method_subscribe_event) != PCRDR_SC_OK) {
        return false;
    }

    if (register_procedure (bus_srv, builtin, HBDBUS_METHOD_UNSUBSCRIBEEVENT,
            HBDBUS_PATTERN_ANY, HBDBUS_PATTERN_ANY,
            builtin_method_unsubscribe_event) != PCRDR_SC_OK) {
        return false;
    }

    if (register_procedure (bus_srv, builtin, HBDBUS_METHOD_LISTENDPOINTS,
            HBDBUS_PATTERN_ANY, HBDBUS_SYSAPP_ANY,
            builtin_method_list_endpoints) != PCRDR_SC_OK) {
        return false;
    }

    if (register_procedure (bus_srv, builtin, HBDBUS_METHOD_LISTPROCEDURES,
            HBDBUS_PATTERN_ANY, HBDBUS_PATTERN_ANY,
            builtin_method_list_procedures) != PCRDR_SC_OK) {
        return false;
    }

    if (register_procedure (bus_srv, builtin, HBDBUS_METHOD_LISTEVENTS,
            HBDBUS_PATTERN_ANY, HBDBUS_PATTERN_ANY,
            builtin_method_list_events) != PCRDR_SC_OK) {
        return false;
    }

    if (register_procedure (bus_srv, builtin, HBDBUS_METHOD_LISTEVENTSUBSCRIBERS,
            HBDBUS_PATTERN_ANY, HBDBUS_PATTERN_ANY,
            builtin_method_list_event_subscribers) != PCRDR_SC_OK) {
        return false;
    }

    if (register_event (bus_srv, builtin, HBDBUS_BUBBLE_NEWENDPOINT,
            HBDBUS_PATTERN_ANY, HBDBUS_SYSAPP_ANY) != PCRDR_SC_OK) {
        return false;
    }

    if (register_event (bus_srv, builtin, HBDBUS_BUBBLE_BROKENENDPOINT,
            HBDBUS_PATTERN_ANY, HBDBUS_SYSAPP_ANY) != PCRDR_SC_OK) {
        return false;
    }

    HLOG_INFO ("The builtin procedures and events have been registered.\n");

    return true;
}

