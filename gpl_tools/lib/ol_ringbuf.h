/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * @author Sergey Nikitin <Sergey.Nikitin@oktetlabs.ru>
 */

#ifndef __OL_RINGBUF_H__
#define __OL_RINGBUF_H__

#include <stdbool.h>
#include <pthread.h>

/** A ring buffer handle. */
typedef struct ol_ringbuffer
{
    size_t head;        /**< Index of the first entry in the queue. */
    size_t tail;        /**< Index of the last entry in the queue. */
    size_t length;      /**< Current length of the queue. */
    size_t capacity;    /**< Maximum length of the queue. */
    void  *entries;     /**< Buffer for storing entries. */
    size_t entry_size;  /**< An entry size. */
    pthread_mutex_t lock; /**< A mutex to protect @c head, @c tail and @c length
                               members of this structure. */
} ol_ringbuffer;

/**
 * Determines whether the specified buffer is empty.
 *
 * @param buf   The buffer handle.
 *
 * @return @b true if the specified buffer is empty, @b false otherwise.
 */
static inline bool is_empty(ol_ringbuffer *buf)
{
    return buf->length == 0;
}

/**
 * Create new ring buffer queue.
 *
 * @param entry_size    Size of an element to store.
 * @param capacity      The capacity of buffer.
 *
 * @return Pointer to a buffer handle, or @c NULL in case of error.
 */
ol_ringbuffer *
ol_ringbuf_new(size_t entry_size, size_t capacity);

/**
 * Write an entry pointed by @p e, to the end of buffer @p buff.
 *
 * @param buf   The buffer handle
 * @param e     Pointer to an entry data
 *
 * @return Status code
 * @retval 0  Success
 * @retval -1 Error (the buffer is full)
 */
int
ol_ringbuf_push(ol_ringbuffer *buf, const void *e);

/**
 * Get an entry from the head of buffer @p buff and write it to @p e.
 *
 * @param buf   The buffer handle
 * @param e     Pointer where to write the entry data.
 *
 * @return Status code
 * @retval 0  Success
 * @retval -1 Error (the buffer is empty)
 */
int
ol_ringbuf_pop(ol_ringbuffer *buf, void *e);

/**
 * Release the buffer internal data.
 *
 * @param buf   The buffer handle
 */
void
ol_ringbuf_free(ol_ringbuffer *buf);

#endif /* __OL_RINGBUF_H__ */
