/*
 * safe-list.h - linked list protected against recursive iteration with deletes
 *
 * Copyright (C) 2013 Felix Fietkau <nbd@openwrt.org>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/*
 * Use this linked list implementation as a replacement for list.h if you
 * want to allow deleting arbitrary list entries from within one or more
 * recursive iterator calling context
 */

#ifndef _HBDBUS_INTERNAL_SAFE_LIST_H_
#define _HBDBUS_INTERNAL_SAFE_LIST_H_

#include "config.h"

#include <stdbool.h>

#include "list.h"

struct safe_list;
struct safe_list_iterator;

struct safe_list {
    struct list_head list;
    struct safe_list_iterator *i;
};

#ifdef __cplusplus
extern "C" {
#endif

int safe_list_for_each(struct safe_list *list,
               int (*cb)(void *ctx, struct safe_list *list),
               void *ctx) WTF_INTERNAL;

void safe_list_add(struct safe_list *list,
        struct safe_list *head) WTF_INTERNAL;
void safe_list_add_first(struct safe_list *list,
        struct safe_list *head) WTF_INTERNAL;
void safe_list_del(struct safe_list *list) WTF_INTERNAL;

#ifdef __cplusplus
}
#endif

#define INIT_SAFE_LIST(_head) \
    do { \
        INIT_LIST_HEAD(_head.list); \
        (_head)->i = NULL; \
    } while (0)

#define SAFE_LIST_INIT(_name) { LIST_HEAD_INIT(_name.list), NULL }
#define SAFE_LIST(_name)    struct safe_list _name = SAFE_LIST_INIT(_name)

static inline bool safe_list_empty(struct safe_list *head)
{
    return list_empty(&head->list);
}

#endif  /* _HBDBUS_INTERNAL_SAFE_LIST_H_ */
