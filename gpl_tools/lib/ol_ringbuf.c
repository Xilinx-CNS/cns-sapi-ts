/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * @author Sergey Nikitin <Sergey.Nikitin@oktetlabs.ru>
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "ol_ringbuf.h"

#define CHECK_PTHREAD_CALL(_call)                                             \
    do {                                                                      \
        int rc = (_call);                                                     \
        if (rc != 0)                                                          \
        {                                                                     \
            printf("%s failed with rc=%d (%s)\n", #_call, rc, strerror(-rc)); \
            return -1;                                                        \
        }                                                                     \
    } while (0);

#define CRITICAL(_code)                                             \
    do {                                                            \
        CHECK_PTHREAD_CALL(pthread_mutex_lock(&buf->lock));         \
        _code;                                                      \
        CHECK_PTHREAD_CALL(pthread_mutex_unlock(&buf->lock));       \
    } while (0);

static inline void *
get_last_ptr(ol_ringbuffer *buf)
{
    return buf->entries + buf->tail * buf->entry_size;
}

static inline void *
get_first_ptr(ol_ringbuffer *buf)
{
    return buf->entries + buf->head * buf->entry_size;
}

int
ol_ringbuf_push(ol_ringbuffer *buf, const void *e)
{
    if (buf->length == buf->capacity)
    {
        printf("%s(): buffer is full\n", __FUNCTION__);
        return -1;
    }

    CRITICAL(
        memcpy(get_last_ptr(buf), e, buf->entry_size);
        ++buf->tail;
        buf->tail %= buf->capacity;
        ++buf->length;
    );

    return 0;
}

int
ol_ringbuf_pop(ol_ringbuffer *buf, void *e)
{
    if (buf->length == 0)
    {
        printf("%s(): buffer is empty\n", __FUNCTION__);
        return -1;
    }

    CRITICAL(
        memcpy(e, get_first_ptr(buf), buf->entry_size);
        ++buf->head;
        buf->head %= buf->capacity;
        --buf->length;
    );

    return 0;
}

ol_ringbuffer *
ol_ringbuf_new(size_t entry_size, size_t capacity)
{
    ol_ringbuffer *buf = malloc(sizeof(*buf));
    if (buf == NULL)
        return buf;

    buf->head = 0;
    buf->tail = 0;
    buf->length = 0;
    buf->capacity = capacity;
    buf->entries = calloc(capacity, entry_size);
    buf->entry_size = entry_size;

    pthread_mutex_init(&buf->lock, NULL);

    if (buf->entries == NULL)
    {
        free(buf);
        return NULL;
    }

    return buf;
}

void
ol_ringbuf_free(ol_ringbuffer *buf)
{
    int rc = 0;

    rc = pthread_mutex_destroy(&buf->lock);
    if (rc != 0)
        printf("mutex destroy failed (rc=%d (%s))\n", rc, strerror(-rc));

    free(buf->entries);
    free(buf);
}
