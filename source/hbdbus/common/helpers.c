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

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>
#include <assert.h>

#include <hibox/ulog.h>
#include <hibox/json.h>
#include <hibox/list.h>
#include <hibox/md5.h>
#include <hibox/utils.h>

#include "hbdbus.h"

/* Return Codes and Messages */
#define UNKNOWN_RET_CODE    "Unknown Return Code"

static struct  {
    int ret_code;
    const char* ret_msg;
} ret_code_2_messages[] = {
    { HBDBUS_SC_IOERR,               /* 1 */
        "I/O Error" },
    { HBDBUS_SC_OK,                  /* 200 */
        "Ok" },
    { HBDBUS_SC_CREATED,             /* 201 */
        "Created" },
    { HBDBUS_SC_ACCEPTED,            /* 202 */
        "Accepted" },
    { HBDBUS_SC_NO_CONTENT,          /* 204 */
        "No Content" },
    { HBDBUS_SC_RESET_CONTENT,       /* 205 */
        "Reset Content" },
    { HBDBUS_SC_PARTIAL_CONTENT,     /* 206 */
        "Partial Content" },
    { HBDBUS_SC_BAD_REQUEST,         /* 400 */
        "Bad Request" },
    { HBDBUS_SC_UNAUTHORIZED,        /* 401 */
        "Unauthorized" },
    { HBDBUS_SC_FORBIDDEN,           /* 403 */
        "Forbidden" },
    { HBDBUS_SC_NOT_FOUND,           /* 404 */
        "Not Found" },
    { HBDBUS_SC_METHOD_NOT_ALLOWED,  /* 405 */
        "Method Not Allowed" },
    { HBDBUS_SC_NOT_ACCEPTABLE,      /* 406 */
        "Not Acceptable" },
    { HBDBUS_SC_CONFLICT,            /* 409 */
        "Conflict" },
    { HBDBUS_SC_GONE,                /* 410 */
        "Gone" },
    { HBDBUS_SC_PRECONDITION_FAILED, /* 412 */
        "Precondition Failed" },
    { HBDBUS_SC_PACKET_TOO_LARGE,    /* 413 */
        "Packet Too Large" },
    { HBDBUS_SC_EXPECTATION_FAILED,  /* 417 */
        "Expectation Failed" },
    { HBDBUS_SC_IM_A_TEAPOT,         /* 418 */
        "I'm a teapot" },
    { HBDBUS_SC_UNPROCESSABLE_PACKET,    /* 422 */
        "Unprocessable Packet" },
    { HBDBUS_SC_LOCKED,              /* 423 */
        "Locked" },
    { HBDBUS_SC_FAILED_DEPENDENCY,   /* 424 */
        "Failed Dependency" },
    { HBDBUS_SC_FAILED_DEPENDENCY,   /* 425 */
        "Failed Dependency" },
    { HBDBUS_SC_UPGRADE_REQUIRED,    /* 426 */
        "Upgrade Required" },
    { HBDBUS_SC_RETRY_WITH,          /* 449 */
        "Retry With" },
    { HBDBUS_SC_UNAVAILABLE_FOR_LEGAL_REASONS,   /* 451 */
        "Unavailable For Legal Reasons" },
    { HBDBUS_SC_INTERNAL_SERVER_ERROR,   /* 500 */
        "Internal Server Error" },
    { HBDBUS_SC_NOT_IMPLEMENTED,     /* 501 */
        "Not Implemented" },
    { HBDBUS_SC_BAD_CALLEE,          /* 502 */
        "Bad Callee" },
    { HBDBUS_SC_SERVICE_UNAVAILABLE, /* 503 */
        "Service Unavailable" },
    { HBDBUS_SC_CALLEE_TIMEOUT,      /* 504 */
        "Callee Timeout" },
    { HBDBUS_SC_INSUFFICIENT_STORAGE,    /* 507 */
        "Insufficient Storage" },
};

#define TABLESIZE(table)    (sizeof(table)/sizeof(table[0]))

const char* hbdbus_get_ret_message (int ret_code)
{
    unsigned int lower = 0;
    unsigned int upper = TABLESIZE (ret_code_2_messages) - 1;
    int mid = TABLESIZE (ret_code_2_messages) / 2;

    if (ret_code < ret_code_2_messages[lower].ret_code ||
            ret_code > ret_code_2_messages[upper].ret_code)
        return UNKNOWN_RET_CODE;

    do {
        if (ret_code < ret_code_2_messages[mid].ret_code)
            upper = mid - 1;
        else if (ret_code > ret_code_2_messages[mid].ret_code)
            lower = mid + 1;
        else
            return ret_code_2_messages [mid].ret_msg;

        mid = (lower + upper) / 2;

    } while (lower <= upper);

    return UNKNOWN_RET_CODE;
}

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
    if (err_code > (int)TABLESIZE (err_messages))
        return UNKNOWN_ERR_CODE;

    return err_messages [err_code];
}

int hbdbus_errcode_to_retcode (int err_code)
{
    switch (err_code) {
        case 0:
            return HBDBUS_SC_OK;
        case HBDBUS_EC_IO:
            return HBDBUS_SC_IOERR;
        case HBDBUS_EC_CLOSED:
            return HBDBUS_SC_SERVICE_UNAVAILABLE;
        case HBDBUS_EC_NOMEM:
            return HBDBUS_SC_INSUFFICIENT_STORAGE;
        case HBDBUS_EC_TOO_LARGE:
            return HBDBUS_SC_PACKET_TOO_LARGE;
        case HBDBUS_EC_PROTOCOL:
            return HBDBUS_SC_UNPROCESSABLE_PACKET;
        case HBDBUS_EC_UPPER:
            return HBDBUS_SC_INTERNAL_SERVER_ERROR;
        case HBDBUS_EC_NOT_IMPLEMENTED:
            return HBDBUS_SC_NOT_IMPLEMENTED;
        case HBDBUS_EC_INVALID_VALUE:
            return HBDBUS_SC_BAD_REQUEST;
        case HBDBUS_EC_DUPLICATED:
            return HBDBUS_SC_CONFLICT;
        case HBDBUS_EC_TOO_SMALL_BUFF:
            return HBDBUS_SC_INSUFFICIENT_STORAGE;
        case HBDBUS_EC_BAD_SYSTEM_CALL:
            return HBDBUS_SC_INTERNAL_SERVER_ERROR;
        case HBDBUS_EC_AUTH_FAILED:
            return HBDBUS_SC_UNAUTHORIZED;
        case HBDBUS_EC_SERVER_ERROR:
            return HBDBUS_SC_INTERNAL_SERVER_ERROR;
        case HBDBUS_EC_TIMEOUT:
            return HBDBUS_SC_CALLEE_TIMEOUT;
        case HBDBUS_EC_UNKNOWN_EVENT:
            return HBDBUS_SC_NOT_FOUND;
        case HBDBUS_EC_UNKNOWN_RESULT:
            return HBDBUS_SC_NOT_FOUND;
        case HBDBUS_EC_UNKNOWN_METHOD:
            return HBDBUS_SC_NOT_FOUND;
        default:
            break;
    }

    return HBDBUS_SC_INTERNAL_SERVER_ERROR;
}

// VW: donot use printbuf.
hbdbus_json *hbdbus_json_object_from_string (const char* json, int len, int in_depth)
{
    // struct printbuf *pb;
    struct json_object *obj = NULL;
    json_tokener *tok;

#if 0
    if (!(pb = printbuf_new())) {
        ULOG_ERR ("Failed to allocate buffer for parse JSON.\n");
        return NULL;
    }
#endif

    if (in_depth < 0)
        in_depth = JSON_TOKENER_DEFAULT_DEPTH;

    tok = json_tokener_new_ex (in_depth);
    if (!tok) {
        ULOG_ERR ("Failed to create a new JSON tokener.\n");
        // printbuf_free (pb);
        goto error;
    }

    // printbuf_memappend (pb, json, len);
    // obj = json_tokener_parse_ex (tok, pb->buf, printbuf_length (pb));
    obj = json_tokener_parse_ex (tok, json, len);
    if (obj == NULL) {
        ULOG_ERR ("Failed to parse JSON: %s\n",
                json_tokener_error_desc (json_tokener_get_error (tok)));
    }

    json_tokener_free(tok);

error:
    //printbuf_free(pb);
    return obj;
}

bool hbdbus_is_valid_token (const char* token, int max_len)
{
    int i;

    if (!isalpha (token [0]))
        return false;

    i = 1;
    while (token [i]) {

        if (max_len > 0 && i > max_len)
            return false;

        if (!isalnum (token [i]) && token [i] != '_')
            return false;

        i++;
    }

    return true;
}

bool hbdbus_is_valid_wildcard_pattern_list (const char* pattern)
{
    if (*pattern == '!')
        pattern++;
    else if (*pattern == '$')
        return hbdbus_is_valid_token (++pattern, 0);

    while (*pattern) {

        if (!isalnum (*pattern) && *pattern != '_'
                && *pattern != '*' && *pattern != '?' && *pattern != '.'
                && *pattern != ',' && *pattern != ';' && *pattern != ' ')
            return false;

        pattern++;
    }

    return true;
}

bool hbdbus_is_valid_endpoint_name (const char* endpoint_name)
{
    char host_name [HBDBUS_LEN_HOST_NAME + 1];
    char app_name [HBDBUS_LEN_APP_NAME + 1];
    char runner_name [HBDBUS_LEN_RUNNER_NAME + 1];

    if (hbdbus_extract_host_name (endpoint_name, host_name) <= 0)
        return false;

    if (hbdbus_extract_app_name (endpoint_name, app_name) <= 0)
        return false;

    if (hbdbus_extract_runner_name (endpoint_name, runner_name) <= 0)
        return false;

    return hbdbus_is_valid_host_name (host_name) &&
        hbdbus_is_valid_app_name (app_name) &&
        hbdbus_is_valid_runner_name (runner_name);
}

/* @<host_name>/<app_name>/<runner_name> */
int hbdbus_extract_host_name (const char* endpoint, char* host_name)
{
    int len;
    char* slash;

    if (endpoint [0] != '@' || (slash = strchr (endpoint, '/')) == NULL)
        return 0;

    endpoint++;
    len = (uintptr_t)slash - (uintptr_t)endpoint;
    if (len <= 0 || len > HBDBUS_LEN_APP_NAME)
        return 0;

    strncpy (host_name, endpoint, len);
    host_name [len] = '\0';

    return len;
}

char* hbdbus_extract_host_name_alloc (const char* endpoint)
{
    char* host_name;
    if ((host_name = malloc (HBDBUS_LEN_HOST_NAME + 1)) == NULL)
        return NULL;

    if (hbdbus_extract_host_name (endpoint, host_name) > 0)
        return host_name;

    free (host_name);
    return NULL;
}

/* @<host_name>/<app_name>/<runner_name> */
int hbdbus_extract_app_name (const char* endpoint, char* app_name)
{
    int len;
    char *first_slash, *second_slash;

    if (endpoint [0] != '@' || (first_slash = strchr (endpoint, '/')) == 0 ||
            (second_slash = strrchr (endpoint, '/')) == 0 ||
            first_slash == second_slash)
        return 0;

    first_slash++;
    len = (uintptr_t)second_slash - (uintptr_t)first_slash;
    if (len <= 0 || len > HBDBUS_LEN_APP_NAME)
        return 0;

    strncpy (app_name, first_slash, len);
    app_name [len] = '\0';

    return len;
}

char* hbdbus_extract_app_name_alloc (const char* endpoint)
{
    char* app_name;

    if ((app_name = malloc (HBDBUS_LEN_APP_NAME + 1)) == NULL)
        return NULL;

    if (hbdbus_extract_app_name (endpoint, app_name) > 0)
        return app_name;

    free (app_name);
    return NULL;
}

int hbdbus_extract_runner_name (const char* endpoint, char* runner_name)
{
    int len;
    char *second_slash;

    if (endpoint [0] != '@' ||
            (second_slash = strrchr (endpoint, '/')) == 0)
        return 0;

    second_slash++;
    len = strlen (second_slash);
    if (len > HBDBUS_LEN_RUNNER_NAME)
        return 0;

    strcpy (runner_name, second_slash);

    return len;
}

char* hbdbus_extract_runner_name_alloc (const char* endpoint)
{
    char* runner_name;

    if ((runner_name = malloc (HBDBUS_LEN_RUNNER_NAME + 1)) == NULL)
        return NULL;

    if (hbdbus_extract_runner_name (endpoint, runner_name) > 0)
        return runner_name;

    free (runner_name);
    return NULL;
}

int hbdbus_assemble_endpoint_name (const char* host_name, const char* app_name,
        const char* runner_name, char* buff)
{
    int host_len, app_len, runner_len;

    if ((host_len = strlen (host_name)) > HBDBUS_LEN_HOST_NAME)
        return 0;

    if ((app_len = strlen (app_name)) > HBDBUS_LEN_APP_NAME)
        return 0;

    if ((runner_len = strlen (runner_name)) > HBDBUS_LEN_RUNNER_NAME)
        return 0;

    buff [0] = '@';
    buff [1] = '\0';
    strcat (buff, host_name);
    buff [host_len + 1] = '/';
    buff [host_len + 2] = '\0';

    strcat (buff, app_name);
    buff [host_len + app_len + 2] = '/';
    buff [host_len + app_len + 3] = '\0';

    strcat (buff, runner_name);

    return host_len + app_len + runner_len + 3;
}

char* hbdbus_assemble_endpoint_name_alloc (const char* host_name, const char* app_name,
        const char* runner_name)
{
    char* endpoint;
    int host_len, app_len, runner_len;

    if ((host_len = strlen (host_name)) > HBDBUS_LEN_HOST_NAME)
        return NULL;

    if ((app_len = strlen (app_name)) > HBDBUS_LEN_APP_NAME)
        return NULL;

    if ((runner_len = strlen (runner_name)) > HBDBUS_LEN_RUNNER_NAME)
        return NULL;

    if ((endpoint = malloc (host_len + app_len + runner_len + 4)) == NULL)
        return NULL;

    endpoint [0] = '@';
    endpoint [1] = '\0';
    strcat (endpoint, host_name);
    endpoint [host_len + 1] = '/';
    endpoint [host_len + 2] = '\0';

    strcat (endpoint, app_name);
    endpoint [host_len + app_len + 2] = '/';
    endpoint [host_len + app_len + 3] = '\0';

    strcat (endpoint, runner_name);

    return endpoint;
}

bool hbdbus_is_valid_host_name (const char* host_name)
{
    (void)host_name;
    return true;
}

/* cn.fmsoft.hybridos.aaa */
bool hbdbus_is_valid_app_name (const char* app_name)
{
    int len, max_len = HBDBUS_LEN_APP_NAME;
    const char *start;
    char *end;

    start = app_name;
    while (*start) {
        char saved;
        end = strchr (start, '.');
        if (end == NULL) {
            saved = 0;
            end += strlen (start);
        }
        else {
            saved = '.';
            *end = 0;
        }

        if (end == start)
            return false;

        if ((len = hbdbus_is_valid_token (start, max_len)) <= 0)
            return false;

        max_len -= len;
        if (saved) {
            start = end + 1;
            *end = saved;
            max_len--;
        }
        else {
            break;
        }
    }

    return true;
}

int hbdbus_json_packet_to_object (const char* json, unsigned int json_len,
        hbdbus_json **jo)
{
    int jpt = JPT_BAD_JSON;
    hbdbus_json *jo_tmp;

    *jo = hbdbus_json_object_from_string (json, json_len, 2);
    if (*jo == NULL) {
        goto failed;
    }

    if (json_object_object_get_ex (*jo, "packetType", &jo_tmp)) {
        const char *pack_type;
        pack_type = json_object_get_string (jo_tmp);

        if (strcasecmp (pack_type, "error") == 0) {
            jpt = JPT_ERROR;
        }
        else if (strcasecmp (pack_type, "auth") == 0) {
            jpt = JPT_AUTH;
        }
        else if (strcasecmp (pack_type, "authPassed") == 0) {
            jpt = JPT_AUTH_PASSED;
        }
        else if (strcasecmp (pack_type, "authFailed") == 0) {
            jpt = JPT_AUTH_FAILED;
        }
        else if (strcasecmp (pack_type, "call") == 0) {
            jpt = JPT_CALL;
        }
        else if (strcasecmp (pack_type, "result") == 0) {
            jpt = JPT_RESULT;
        }
        else if (strcasecmp (pack_type, "resultSent") == 0) {
            jpt = JPT_RESULT_SENT;
        }
        else if (strcasecmp (pack_type, "event") == 0) {
            jpt = JPT_EVENT;
        }
        else if (strcasecmp (pack_type, "eventSent") == 0) {
            jpt = JPT_EVENT_SENT;
        }
        else {
            jpt = JPT_UNKNOWN;
        }
    }

    return jpt;

failed:
    if (*jo)
        json_object_put (*jo);

    return jpt;
}

void hbdbus_generate_unique_id (char* id_buff, const char* prefix)
{
    static unsigned long accumulator;
    struct timespec tp;
    int i, n = strlen (prefix);
    char my_prefix [9];

    for (i = 0; i < 8; i++) {
        if (i < n) {
            my_prefix [i] = toupper (prefix [i]);
        }
        else
            my_prefix [i] = 'X';
    }
    my_prefix [8] = '\0';

    clock_gettime (CLOCK_REALTIME, &tp);
    snprintf (id_buff, HBDBUS_LEN_UNIQUE_ID + 1,
            "%s-%016lX-%016lX-%016lX",
            my_prefix, tp.tv_sec, tp.tv_nsec, accumulator);
    accumulator++;
}

void hbdbus_generate_md5_id (char* id_buff, const char* prefix)
{
    int n;
    char key [256];
    unsigned char md5_digest [MD5_DIGEST_SIZE];
    struct timespec tp;

    clock_gettime (CLOCK_REALTIME, &tp);
    n = snprintf (key, sizeof (key), "%s-%ld-%ld-%ld", prefix,
            tp.tv_sec, tp.tv_nsec, random ());

    if (n < 0) {
        ULOG_WARN ("Unexpected call to snprintf.\n");
    }
    else if ((size_t)n >= sizeof (key))
        ULOG_WARN ("The buffer is too small for resultId.\n");

    md5digest (key, md5_digest);
    bin2hex (md5_digest, MD5_DIGEST_SIZE, id_buff);
}

bool hbdbus_is_valid_unique_id (const char* id)
{
    int n = 0;

    while (id [n]) {
        if (n > HBDBUS_LEN_UNIQUE_ID)
            return false;

        if (!isalnum (id [n]) && id [n] != '-')
            return false;

        n++;
    }

    return true;
}

bool hbdbus_is_valid_md5_id (const char* id)
{
    int n = 0;

    while (id [n]) {
        if (n > (MD5_DIGEST_SIZE << 1))
            return false;

        if (!isalnum (id [n]))
            return false;

        n++;
    }

    return true;
}

double hbdbus_get_elapsed_seconds (const struct timespec *ts1, const struct timespec *ts2)
{
    struct timespec ts_curr;
    time_t ds;
    long dns;

    if (ts2 == NULL) {
        clock_gettime (CLOCK_MONOTONIC, &ts_curr);
        ts2 = &ts_curr;
    }

    ds = ts2->tv_sec - ts1->tv_sec;
    dns = ts2->tv_nsec - ts1->tv_nsec;
    return ds + dns * 1.0E-9;
}

static const char *json_hex_chars = "0123456789abcdefABCDEF";

char* hbdbus_escape_string_for_json (const char* str)
{
    struct printbuf my_buff, *pb = &my_buff;
    size_t pos = 0, start_offset = 0;
    unsigned char c;

    if (printbuf_init (pb)) {
        ULOG_ERR ("Failed to initialize buffer for escape string for JSON.\n");
        return NULL;
    }

    while (str [pos]) {
        const char* escaped;

        c = str[pos];
        switch (c) {
        case '\b':
            escaped = "\\b";
            break;
        case '\n':
            escaped = "\\n";
            break;
        case '\r':
            escaped = "\\n";
            break;
        case '\t':
            escaped = "\\t";
            break;
        case '\f':
            escaped = "\\f";
            break;
        case '"':
            escaped = "\\\"";
            break;
        case '\\':
            escaped = "\\\\";
            break;
        default:
            escaped = NULL;
            if (c < ' ') {
                char sbuf[7];
                if (pos - start_offset > 0)
                    printbuf_memappend (pb,
                            str + start_offset, pos - start_offset);
                snprintf (sbuf, sizeof (sbuf), "\\u00%c%c",
                        json_hex_chars[c >> 4], json_hex_chars[c & 0xf]);
                printbuf_memappend_fast (pb, sbuf, (int)(sizeof(sbuf) - 1));
                start_offset = ++pos;
            }
            else
                pos++;
            break;
        }

        if (escaped) {
            if (pos - start_offset > 0)
                printbuf_memappend (pb, str + start_offset, pos - start_offset);

            printbuf_memappend (pb, escaped, strlen (escaped));
            start_offset = ++pos;
        }
    }

    if (pos - start_offset > 0)
        printbuf_memappend (pb, str + start_offset, pos - start_offset);

    return pb->buf;
}

