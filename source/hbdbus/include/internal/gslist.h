/**
 * The MIT License (MIT)
 * Copyright (c) 2009-2016 Gerardo Orellana <hello @ goaccess.io>
 * Copyright (c) 2020 FMSoft <https://www.fmsoft.cn>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef _HBDBUS_INTERNAL_GSLIST_H_
#define _HBDBUS_INTERNAL_GSLIST_H_

#include "config.h"

/* Generic Single linked-list */
typedef struct gs_list_
{
  void *data;
  struct gs_list_ *next;
} gs_list;

#ifdef __cplusplus
extern "C" {
#endif

/* single linked-list */
gs_list *gslist_create (void *data) WTF_INTERNAL;
gs_list *gslist_find (gs_list * node, int (*func) (void *, void *),
        void *data) WTF_INTERNAL;
gs_list *gslist_insert_append (gs_list * node, void *data) WTF_INTERNAL;
gs_list *gslist_insert_prepend (gs_list * list, void *data) WTF_INTERNAL;
int gslist_count (gs_list * list) WTF_INTERNAL;
int gslist_foreach (gs_list * node, int (*func) (void *, void *),
        void *user_data) WTF_INTERNAL;
int gslist_remove_node (gs_list ** list, gs_list * node) WTF_INTERNAL;
int gslist_remove_nodes (gs_list * list) WTF_INTERNAL;

#ifdef __cplusplus
}
#endif

#endif // _HBDBUS_INTERNAL_GSLIST_H_
