/*
** helpers.c -- The helpers for both HBDBus server and clients.
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

#include <string.h>
#include <ctype.h>
#include <time.h>
#include <assert.h>

#include "hbdbus.h"

/* Error Codes and Messages */
#define UNKNOWN_ERR_CODE    "Unknown Error Code"

static const char* err_messages [] = {
    /* 0 */
    "Everything Ok",
    /* HBDBUS_EC_IO (-1) */
    "IO Error",
    /* HBDBUS_EC_CLOSED (-2) */
    "Peer Closed",
    /* HBDBUS_EC_NOMEM (-3) */
    "No Enough Memory",
    /* HBDBUS_EC_TOO_LARGE (-4) */
    "Too Large",
    /* HBDBUS_EC_PROTOCOL (-5) */
    "Protocol",
    /* HBDBUS_EC_UPPER (-6) */
    "Upper",
    /* HBDBUS_EC_NOT_IMPLEMENTED (-7) */
    "Not Implemented",
    /* HBDBUS_EC_INVALID_VALUE (-8) */
    "Invalid Value",
    /* HBDBUS_EC_DUPLICATED (-9) */
    "Duplicated",
    /* HBDBUS_EC_TOO_SMALL_BUFF (-10) */
    "Too Small Buffer",
    /* HBDBUS_EC_BAD_SYSTEM_CALL (-11) */
    "Bad System Call",
    /* HBDBUS_EC_AUTH_FAILED (-12) */
    "Authentication Failed",
    /* HBDBUS_EC_SERVER_ERROR (-13) */
    "Server Error",
    /* HBDBUS_EC_TIMEOUT (-14) */
    "Timeout",
    /* HBDBUS_EC_UNKNOWN_EVENT (-15) */
    "Unknown Event",
    /* HBDBUS_EC_UNKNOWN_RESULT (-16) */
    "Unknown Result",
    /* HBDBUS_EC_UNKNOWN_METHOD (-17) */
    "Unknown Method",
    /* HBDBUS_EC_UNEXPECTED (-18) */
    "Unexpected",
    /* HBDBUS_EC_SERVER_REFUSED (-19) */
    "Server Refused",
    /* HBDBUS_EC_BAD_PACKET (-20) */
    "Bad Packet",
    /* HBDBUS_EC_BAD_CONNECTION (-21) */
    "Bad Connection",
    /* HBDBUS_EC_CANT_LOAD (-22) */
    "Cannot Load Resource",
    /* HBDBUS_EC_BAD_KEY (-23) */
    "Bad Key",
};

const char* hbdbus_get_err_message (int err_code)
{
    if (err_code > 0)
        return UNKNOWN_ERR_CODE;

    err_code = -err_code;
    if (err_code > (int)PCA_TABLESIZE (err_messages))
        return UNKNOWN_ERR_CODE;

    return err_messages [err_code];
}

int hbdbus_errcode_to_retcode (int err_code)
{
    switch (err_code) {
        case 0:
            return PCRDR_SC_OK;
        case HBDBUS_EC_IO:
            return PCRDR_SC_IOERR;
        case HBDBUS_EC_CLOSED:
            return PCRDR_SC_SERVICE_UNAVAILABLE;
        case HBDBUS_EC_NOMEM:
            return PCRDR_SC_INSUFFICIENT_STORAGE;
        case HBDBUS_EC_TOO_LARGE:
            return PCRDR_SC_PACKET_TOO_LARGE;
        case HBDBUS_EC_PROTOCOL:
            return PCRDR_SC_UNPROCESSABLE_PACKET;
        case HBDBUS_EC_UPPER:
            return PCRDR_SC_INTERNAL_SERVER_ERROR;
        case HBDBUS_EC_NOT_IMPLEMENTED:
            return PCRDR_SC_NOT_IMPLEMENTED;
        case HBDBUS_EC_INVALID_VALUE:
            return PCRDR_SC_BAD_REQUEST;
        case HBDBUS_EC_DUPLICATED:
            return PCRDR_SC_CONFLICT;
        case HBDBUS_EC_TOO_SMALL_BUFF:
            return PCRDR_SC_INSUFFICIENT_STORAGE;
        case HBDBUS_EC_BAD_SYSTEM_CALL:
            return PCRDR_SC_INTERNAL_SERVER_ERROR;
        case HBDBUS_EC_AUTH_FAILED:
            return PCRDR_SC_UNAUTHORIZED;
        case HBDBUS_EC_SERVER_ERROR:
            return PCRDR_SC_INTERNAL_SERVER_ERROR;
        case HBDBUS_EC_TIMEOUT:
            return PCRDR_SC_CALLEE_TIMEOUT;
        case HBDBUS_EC_UNKNOWN_EVENT:
            return PCRDR_SC_NOT_FOUND;
        case HBDBUS_EC_UNKNOWN_RESULT:
            return PCRDR_SC_NOT_FOUND;
        case HBDBUS_EC_UNKNOWN_METHOD:
            return PCRDR_SC_NOT_FOUND;
        default:
            break;
    }

    return PCRDR_SC_INTERNAL_SERVER_ERROR;
}

bool hbdbus_is_valid_wildcard_pattern_list (const char* pattern)
{
    if (*pattern == '!')
        pattern++;
    else if (*pattern == '$')
        return purc_is_valid_token (++pattern, 0);

    while (*pattern) {

        if (!isalnum (*pattern) && *pattern != '_'
                && *pattern != '*' && *pattern != '?' && *pattern != '.'
                && *pattern != ',' && *pattern != ';' && *pattern != ' ')
            return false;

        pattern++;
    }

    return true;
}

int hbdbus_json_packet_to_object(const char* json, unsigned int json_len,
        purc_variant_t *jo)
{
    int jpt = JPT_BAD_JSON;
    purc_variant_t jo_tmp;

    *jo = purc_variant_make_from_json_string(json, json_len);
    if (*jo == NULL || !purc_variant_is_object(*jo)) {
        goto failed;
    }

    if ((jo_tmp = purc_variant_object_get_by_ckey(*jo, "packetType"))) {
        const char *pack_type;
        pack_type = purc_variant_get_string_const(jo_tmp);

        if (pack_type == NULL)
            goto failed;

        if (strcasecmp(pack_type, "error") == 0) {
            jpt = JPT_ERROR;
        }
        else if (strcasecmp(pack_type, "auth") == 0) {
            jpt = JPT_AUTH;
        }
        else if (strcasecmp(pack_type, "authPassed") == 0) {
            jpt = JPT_AUTH_PASSED;
        }
        else if (strcasecmp(pack_type, "authFailed") == 0) {
            jpt = JPT_AUTH_FAILED;
        }
        else if (strcasecmp(pack_type, "call") == 0) {
            jpt = JPT_CALL;
        }
        else if (strcasecmp(pack_type, "result") == 0) {
            jpt = JPT_RESULT;
        }
        else if (strcasecmp(pack_type, "resultSent") == 0) {
            jpt = JPT_RESULT_SENT;
        }
        else if (strcasecmp(pack_type, "event") == 0) {
            jpt = JPT_EVENT;
        }
        else if (strcasecmp(pack_type, "eventSent") == 0) {
            jpt = JPT_EVENT_SENT;
        }
        else {
            jpt = JPT_UNKNOWN;
        }
    }

    return jpt;

failed:
    if (*jo)
        purc_variant_unref(*jo);

    return jpt;
}

