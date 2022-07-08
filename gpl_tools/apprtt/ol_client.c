/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * @author Sergey Nikitin <Sergey.Nikitin@oktetlabs.ru>
 */

/* for pthread_tryjoin_np() */
#define _GNU_SOURCE

#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <assert.h>
#include <errno.h>
#include <netdb.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "ol_time.h"
#include "ol_poll.h"
#include "ol_apprtt.h"
#include "ol_client.h"
#include "ol_ringbuf.h"
#include "ol_helpers.h"
#include "ol_pattern.h"

/** Size of a ring buffer for RTT samples - see @ref ol_sample_entry. */
#define RTT_BUF_SIZE 256

/**
 * Data structure containing information to count and print RTT values.
 * The structure is filled on every received answer from server and is
 * stored in the ring buffer to be processed by @ref ol_client_print_rtt_th().
 */
typedef struct ol_sample_entry
{
    unsigned char   id;     /**< Index number of a server answer. */
    uint64_t        ts;     /**< Timestamp of a server answer. */
} ol_sample_entry;

/**
 * Client internal data structure.
 */
typedef struct ol_client_data
{
    int             sent;               /**< Total amount of sent data */
    pthread_t       thread_id;          /**< ID of RTT printing thread */
    int             bytes_to_send;      /**< How much data the client has to
                                             send */
    int             time_to_run;        /**< How much time the client has to
                                             run, in seconds */
    time_t          client_start_time;  /**< Client execution start time */
    int             chunk_size;         /**< Size of sent data for RTT
                                             measuring */
    ol_ringbuffer  *rx_ts_buf;          /**< Ring buffer for storing Rx
                                             timestamps */
    ol_ringbuffer  *tx_ts_buf;          /**< Ring buffer for storing Tx
                                             timestamps */
    unsigned char   n_sent;             /**< Number of sent data chunks */
    bool            use_pattern;        /**< Send data according to the pattern */
    bool            poll_rx_only;       /**< Flag telling to stop sending data,
                                             and receive only */
} ol_client_data;

static void *
ol_client_print_rtt_th(void *arg)
{
    ol_client_data *state = arg;
    ol_sample_entry e_rx;
    ol_sample_entry e_tx;

    assert(arg != NULL);

    while (true)
    {
        while (!is_empty(state->rx_ts_buf) &&
               !is_empty(state->tx_ts_buf))
        {
            if (ol_ringbuf_pop(state->rx_ts_buf, &e_rx) == 0 &&
                ol_ringbuf_pop(state->tx_ts_buf, &e_tx) == 0)
            {
                if (e_rx.id != e_tx.id)
                {
                    printf("client: invalid answer from server "
                           "(id=%u, sent_id=%u)\n", e_rx.id, e_tx.id);
                    pthread_exit(NULL);
                }
                printf("%lu\n", e_rx.ts - e_tx.ts);
            }
            else
            {
                printf("client: getting sample failed\n");
                pthread_exit(NULL);
            }
        }
        pthread_testcancel();
    }

    return NULL;
}

static int
ol_client_pollin_func(int s, void *user_data)
{
    unsigned char           id;
    ol_client_data         *state;
    ol_sample_entry         sample;
    ssize_t                 rc = 0;

    assert(user_data != NULL);

    state = ((ol_app_state *)user_data)->internal_data;

    rc = recv(s, &id, sizeof(id), 0);
    if (rc < 0)
    {
        printf("client: recv(): %s\n", strerror(errno));
        return OL_POLL_RC_FAIL;
    }
    else if (rc == 0)
    {
        printf("client: peer closed connection\n");
        return OL_POLL_RC_STOP;
    }

    sample.id = id;
    sample.ts = ol_time_get_usec();

    if (ol_ringbuf_push(state->rx_ts_buf, &sample) != 0)
    {
        printf("client: failed to print rtt value\n");
        return OL_POLL_RC_FAIL;
    }

    return OL_POLL_RC_OK;
}

static bool
ol_client_must_stop(ol_client_data *state)
{
    if (state->bytes_to_send != OL_CLIENT_LIM_UNSPEC &&
        state->sent >= state->bytes_to_send)
    {
        return true;
    }
    else if (state->time_to_run != OL_CLIENT_LIM_UNSPEC &&
             time(NULL) >= state->client_start_time + state->time_to_run)
    {
        return true;
    }
    else
    {
        return false;
    }
}

static int
ol_client_send(ol_app_state *state, int s)
{
    ol_client_data *client_state;
    size_t          data_len = 0;
    int             rc = 0;
    unsigned int    chunk_sent = 0;
    ol_sample_entry sample;

    assert(state != NULL);
    client_state = state->internal_data;

    chunk_sent = client_state->sent % client_state->chunk_size;
    data_len = client_state->chunk_size - chunk_sent;
    if (chunk_sent == 0)
    {
        sample.id = client_state->n_sent;
        sample.ts = ol_time_get_usec();

        if (ol_ringbuf_push(client_state->tx_ts_buf, &sample) != 0)
        {
            printf("client: failed to print rtt value\n");
            return -1;
        }
        client_state->n_sent++;
    }

    if (client_state->bytes_to_send != OL_CLIENT_LIM_UNSPEC &&
        data_len > client_state->bytes_to_send - client_state->sent)
    {
        data_len = client_state->bytes_to_send - client_state->sent;
    }

    if (data_len > state->bufsize)
        data_len = state->bufsize;

    if (client_state->use_pattern)
    {
        ol_pattern_fill_buff_with_sequence(state->buf, data_len,
                                           client_state->sent);
    }

    rc = send(s, state->buf, data_len, MSG_DONTWAIT);

    if (rc > 0)
        client_state->sent += rc;

    return rc;
}

static int
ol_client_pollout_func(int s, void *user_data)
{
    int             rc;
    ol_client_data *state;

    assert(user_data != NULL);

    state = ((ol_app_state *)user_data)->internal_data;

    if (state->poll_rx_only)
        return OL_POLL_RC_OK;

    rc = ol_client_send(user_data, s);
    if (rc < 0)
    {
        printf("client: send(): %s\n", strerror(errno));
        return OL_POLL_RC_FAIL;
    }

    return OL_POLL_RC_OK;
}

int
ol_rtt_client(ol_app_state *state, const char *host, int time_to_run,
              int bytes_to_send, int chunk_size, bool use_pattern)
{
    int             s = -1;
    int             rc = 0;
    pthread_attr_t  tattr;
    ol_client_data *client_state;

    printf("Client is running\n");
    assert(host != NULL);
    assert(state != NULL);

    client_state = malloc(sizeof(ol_client_data));
    if (client_state == NULL)
    {
        printf("client: malloc: %s\n", strerror(errno));
        return -1;
    }
    state->internal_data = client_state;

    client_state->sent = 0;
    client_state->n_sent = 0;
    client_state->bytes_to_send = bytes_to_send;
    client_state->time_to_run = time_to_run;
    client_state->chunk_size = chunk_size;
    client_state->use_pattern = use_pattern;
    client_state->poll_rx_only = false;
    client_state->rx_ts_buf = ol_ringbuf_new(sizeof(ol_sample_entry),
                                             RTT_BUF_SIZE);
    if (client_state->rx_ts_buf == NULL)
    {
        printf("client: Rx timestamps queue init failed\n");
        return -1;
    }
    client_state->tx_ts_buf = ol_ringbuf_new(sizeof(ol_sample_entry),
                                             RTT_BUF_SIZE);
    if (client_state->tx_ts_buf == NULL)
    {
        printf("client: Tx timestamps queue init failed\n");
        return -1;
    }

    if (client_state->bytes_to_send != OL_CLIENT_LIM_UNSPEC &&
        client_state->time_to_run != OL_CLIENT_LIM_UNSPEC)
    {
        printf("client: incompatible parameters: both --bytes-to-send and "
               "--time-to-run are specified\n");
        return -1;
    }

    s = ol_create_and_connect_socket(OL_CONNECT_ACTIVE, SOCK_STREAM,
                                     SERVER_PORT, host, "client");
    if (s < 0)
    {
        printf("client: connection to the server failed\n");
        return -1;
    }

    rc = pthread_attr_init(&tattr);
    if (rc != 0)
    {
        printf("client: pthread_attr_init error %s\n", strerror(rc));
        return -1;
    }

    rc = pthread_create(&client_state->thread_id, &tattr,
                        ol_client_print_rtt_th, client_state);
    if (rc != 0)
    {
        printf("client: pthread_create error %s\n", strerror(rc));
        return -1;
    }

    ol_poll_addfd(s, ol_client_pollin_func, ol_client_pollout_func);

    ol_time_init();

    client_state->client_start_time = time(NULL);

    do {
        rc = ol_poll_process(state);

        /*
         * Check that printing thread is still alive. If it terminates,
         * then some error occured.
         */
        if (pthread_tryjoin_np(client_state->thread_id, NULL) != EBUSY)
        {
            printf("client: thread error\n");
            rc = OL_POLL_RC_FAIL;
            break;
        }

        if (ol_client_must_stop(client_state))
        {
            /* Make sure we handled all the timestamps. */
            if (is_empty(client_state->rx_ts_buf) &&
                is_empty(client_state->tx_ts_buf))
            {
                break;
            }

            /* If current chunk is sent fully, stop sending and wait for
               server response. */
            if ((client_state->sent % client_state->chunk_size) == 0)
                client_state->poll_rx_only = true;
        }

    } while (rc == OL_POLL_RC_OK);

    pthread_cancel(client_state->thread_id);

    printf("client: total sent - %d(bytes)\n", client_state->sent);
    printf("client: total time elapsed - %ld(s)\n",
           time(NULL) - client_state->client_start_time);

    close(s);
    ol_ringbuf_free(client_state->rx_ts_buf);
    ol_ringbuf_free(client_state->tx_ts_buf);
    free(client_state);

    return rc == OL_POLL_RC_FAIL ? -1 : 0;
}
