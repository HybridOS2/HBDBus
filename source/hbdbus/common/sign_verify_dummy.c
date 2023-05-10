/*
** sign_verify_hmac_sha256.c -- The utilitis for sign the challenge code
**  and verify the signature with HMAC SHA256 algorithms.
**  This file will be used when OpenSSL is not available.
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
#include <errno.h>
#include <assert.h>

#ifndef BUILD_APP_AUTH

#include "hbdbus.h"

#define DUMMY_SIGNATURE     "DUMB"
#define LEN_DUMMY_SIGNATURE 4

int hbdbus_sign_data (const char *app_name,
        const unsigned char* data, unsigned int data_len,
        unsigned char **sig, unsigned int *sig_len)
{
    (void)app_name;
    (void)data;
    (void)data_len;
    *sig = NULL;
    *sig_len = 0;

    if ((*sig = calloc (1, LEN_DUMMY_SIGNATURE)) == NULL) {
        return HBDBUS_EC_NOMEM;
    }

    *sig_len = LEN_DUMMY_SIGNATURE;
    memcpy (*sig, DUMMY_SIGNATURE, LEN_DUMMY_SIGNATURE);
    return 0;
}

int hbdbus_verify_signature (const char* app_name,
        const unsigned char* data, unsigned int data_len,
        const unsigned char* sig, unsigned int sig_len)
{
    (void)app_name;
    (void)data;
    (void)data_len;
    if (memcmp (sig, DUMMY_SIGNATURE, sig_len) == 0)
        return 1;

    return 0;
}

#endif /* !BUILD_APP_AUTH */

