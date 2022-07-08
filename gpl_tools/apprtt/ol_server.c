/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * @author Sergey Nikitin <Sergey.Nikitin@oktetlabs.ru>
 */

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#include "ol_apprtt.h"
#include "ol_server.h"
#include "ol_poll.h"
#include "ol_helpers.h"
#include "ol_pattern.h"

/**
 * Server internal data structure.
 */
typedef struct ol_server_data
{
    int             chunk_size;     /**< Size of data after which the server
                                         sends back "ack" byte. */
    size_t          received;       /**< Total amount of received data. */
    unsigned char   n_ack;          /**< The "ack" byte number. */
    bool            data_check;     /**< Check received data with pattern. */
} ol_server_data;

static char         compare_buf[APP_BUF_SIZE];
static size_t       total_received = 0;

static int
ol_server_pollin_func(int s, void *user_data)
{
    ol_app_state           *app_state = user_data;
    ol_server_data         *server_state = NULL;
    int                     rc;

    assert(app_state != NULL);
    server_state = app_state->internal_data;

    rc = recv(s, app_state->buf, app_state->bufsize, MSG_DONTWAIT);
    if (rc < 0)
    {
        printf("server: recv(): %s\n", strerror(errno));
        return OL_POLL_RC_FAIL;
    }

    if (rc == 0)
    {
        printf("server: peer closed the connection\n");
        return OL_POLL_RC_STOP;
    }

    if (server_state->data_check)
    {
        ol_pattern_fill_buff_with_sequence(compare_buf, rc, total_received);

        if (memcmp(app_state->buf, compare_buf, rc) != 0)
        {
            printf("server: received data doesn't correspond to the pattern\n");
            return OL_POLL_RC_FAIL;
        }
    }

    server_state->received += rc;
    total_received += rc;

    while (server_state->received >= server_state->chunk_size)
    {
        if (send(s, &server_state->n_ack, sizeof(server_state->n_ack), 0) < 0)
        {
            printf("server: send(): %s\n", strerror(errno));
            return OL_POLL_RC_FAIL;
        }

        ++server_state->n_ack;
        server_state->received -= server_state->chunk_size;
    }

    return OL_POLL_RC_OK;
}

int
ol_rtt_server(ol_app_state *state, int chunk_size, bool data_check)
{
    int             s = -1;
    int             rc = 0;
    ol_server_data *server_state = NULL;

    printf("Server is running\n");
    printf("chunk size = %d\n", chunk_size);
    assert(state != NULL);

    server_state = malloc(sizeof(ol_server_data));
    if (server_state == NULL)
    {
        printf("client: malloc: %s\n", strerror(errno));
        return -1;
    }
    state->internal_data = server_state;

    if (chunk_size == 0)
    {
        printf("server: invalid chunk size\n");
        return -1;
    }
    server_state->chunk_size = chunk_size;
    server_state->received = 0;
    server_state->n_ack = 0;
    server_state->data_check = data_check;

    s = ol_create_and_connect_socket(OL_CONNECT_PASSIVE, SOCK_STREAM,
                                     SERVER_PORT, NULL, "server");
    if (s < 0)
    {
        printf("server: connection failed\n");
        return -1;
    }

    printf("server: switching off Nagle Algorithm\n");
    if (ol_enable_tcp_no_delay_opt(s, "server") < 0)
        return -1;

    ol_poll_addfd(s, ol_server_pollin_func, NULL);

    do {
        rc = ol_poll_process(state);
    } while (rc == OL_POLL_RC_OK);

    close(s);
    free(server_state);

    return rc == OL_POLL_RC_FAIL ? -1 : 0;
}
