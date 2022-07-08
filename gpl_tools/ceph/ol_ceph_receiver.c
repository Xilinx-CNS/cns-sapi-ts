/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * @author Sergey Nikitin <Sergey.Nikitin@oktetlabs.ru>
 */

#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <assert.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "ol_ceph_receiver.h"
#include "ol_poll.h"
#include "ol_helpers.h"
#include "ol_ceph_protocol.h"
#include "ol_pattern.h"
#include "ol_ceph_offload.h"

/**
 * Receiver internal data structure.
 */
typedef struct ol_ceph_receiver_data
{
    size_t total_ceph_data_read;
    size_t n_recv_chunks;
    bool invalid_data;
    ol_ceph_proto_handle ceph_proto_handle;
} ol_ceph_receiver_data;

static bool
ol_ceph_receiver_validate(const void *buf, size_t len, size_t start_n)
{
    void *patterned_buf = malloc(len);
    bool rc = false;

    if (patterned_buf == NULL)
    {
        fprintf(stderr, "receiver: failed to validate received data\n");
        return false;
    }

    ol_pattern_fill_buff_with_sequence(patterned_buf, len, start_n);
    rc = memcmp(patterned_buf, buf, len) == 0;
    if (!rc)
    {
        fprintf(stderr, "Validation error:\n");
        ol_hex_diff_dump(patterned_buf, buf, len);
    }

    free(patterned_buf);

    return rc;
}

/**
 * See @ref ol_ceph_opread_rd_callback documentation.
 */
static void
ol_ceph_receiver_callback(const void *buf, size_t len, void *user_data)
{
    ol_ceph_receiver_data *state = user_data;

    state->invalid_data = !ol_ceph_receiver_validate(
                                buf, len, state->total_ceph_data_read);

    if (state->invalid_data)
    {
        fprintf(stderr, "Last chunk (%lu:%lu) is not validated\n",
                state->n_recv_chunks, len);
    }

    state->total_ceph_data_read += len;
    ++state->n_recv_chunks;
}

/**
 * Callback for @c POLLIN event.
 *
 * @param s             Socket on which @c POLLIN event occured.
 * @param user_data     Pointer to @ref ol_ceph_state handle.
 *
 * @return Status code according to the types declared in ol_poll.h.
 */
static int
ol_ceph_receiver_pollin_func(int s, void *user_data)
{
    ol_ceph_proto_rc rc;
    ol_ceph_receiver_data *receiver_data = user_data;

    rc = ol_ceph_recv_state_proc(&receiver_data->ceph_proto_handle);

    if (receiver_data->invalid_data)
        return OL_POLL_RC_FAIL;

    return proto_rc2poll_rc(rc);
}

int
ol_ceph_receiver(ol_ceph_state *state, const char *host, int port,
                 const char *iface)
{
    int s = -1;
    int rc = 0;
    ol_ceph_receiver_data receiver_state;
    ol_connection_type conn_type = host == NULL ? OL_CONNECT_PASSIVE
                                                : OL_CONNECT_ACTIVE;

    printf("Receiver is running\n");
    assert(state != NULL);

    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0)
    {
        fprintf(stderr, "receiver: socket(): %s\n", strerror(errno));
        return -1;
    }

    ol_ceph_offload_enable(s);

    receiver_state.total_ceph_data_read = 0;
    receiver_state.invalid_data = false;
    receiver_state.n_recv_chunks = 0;

    s = ol_connect_socket(s, conn_type, port, host, "receiver");
    if (s < 0)
    {
        fprintf(stderr, "receiver: connection failed\n");
        return -1;
    }

    rc = ol_ceph_proto_client_init(&receiver_state.ceph_proto_handle, s, iface,
                                   state->buf, state->bufsize,
                                   ol_ceph_receiver_callback, &receiver_state);
    if (rc < 0)
        printf("Some Onload features are not supported\n");

    ol_poll_addfd(s, ol_ceph_receiver_pollin_func, NULL);

    do {
        rc = ol_poll_process(&receiver_state);
    } while (rc == OL_POLL_RC_OK);

    printf("receiver: total received - %lu bytes\n",
           receiver_state.total_ceph_data_read);

    ol_ceph_conn_close(&receiver_state.ceph_proto_handle.conn);

    return rc == OL_POLL_RC_FAIL ? -1 : 0;
}
