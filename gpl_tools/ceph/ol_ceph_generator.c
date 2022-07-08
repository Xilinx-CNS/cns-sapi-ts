/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * @author Sergey Nikitin <Sergey.Nikitin@oktetlabs.ru>
 */

#include <stdio.h>
#include <stdbool.h>
#include <unistd.h>
#include <assert.h>
#include <time.h>
#include <netinet/in.h>

#include "ol_poll.h"
#include "ol_ceph.h"
#include "ol_ceph_generator.h"
#include "ol_ceph_protocol.h"
#include "ol_helpers.h"
#include "ol_pattern.h"

/**
 * Generator internal data structure.
 */
typedef struct ol_ceph_generator_data
{
    int time_to_run;    /**< How much time the generator has to run, seconds */
    time_t start_time;  /**< Generator execution start time */
    size_t data_sent;   /**< Total amount of Ceph payload sent data. */
    ol_ceph_proto_handle ceph_gn_hdl; /**< Ceph protocol handle. */
} ol_ceph_generator_data;

/**
 * Check whether it is time to stop the generator
 *
 * @return @c true if application needs to stop, @c false otherwise.
 */
static inline bool
ol_ceph_generator_must_stop(ol_ceph_generator_data *state)
{
    return time(NULL) >= state->start_time + state->time_to_run ? true : false;
}

/**
 * Callback that is called by ceph generator to construct ceph payload.
 * See @ref ol_ceph_opread_wr_callback documentation.
 */
static void
ol_ceph_generator_callback(void *data, size_t len, void *user_data)
{
    ol_ceph_generator_data *state = user_data;

    ol_pattern_fill_buff_with_sequence(data, len, state->data_sent);
    state->data_sent += len;
}

/**
 * Callback for @c POLLOUT event.
 *
 * @param s             Socket on which @c POLLOUT event occured.
 * @param user_data     Pointer to @ref ol_ceph_state handle.
 *
 * @return Status code according to the types declared in ol_poll.h.
 */
static int
ol_ceph_generator_pollout_func(int s, void *user_data)
{
    ol_ceph_generator_data *state = user_data;

    if (ol_ceph_generator_must_stop(state))
        return OL_POLL_RC_STOP;

    return proto_rc2poll_rc(ol_ceph_generator_state_proc(&state->ceph_gn_hdl));
}

int
ol_ceph_generator(ol_ceph_state *state, const char *host, int port,
                  int time_to_run)
{
    int s = -1;
    int rc = 0;
    ol_ceph_generator_data generator_state;
    ol_connection_type conn_type = host == NULL ? OL_CONNECT_PASSIVE
                                                : OL_CONNECT_ACTIVE;

    printf("Generator is running\n");
    assert(state != NULL);

    generator_state.data_sent = 0;
    generator_state.time_to_run = time_to_run;

    if (generator_state.time_to_run == OL_CEPH_GENERATOR_LIM_UNSPEC)
    {
        fprintf(stderr, "generator: incompatible parameters: --time-to-run "
                "isn't specified\n");
        return -1;
    }

    s = ol_create_and_connect_socket(conn_type, SOCK_STREAM, port,
                                     host, "generator");
    if (s < 0)
    {
        fprintf(stderr, "generator: connection establishment failed\n");
        return -1;
    }

    ol_ceph_proto_generator_init(&generator_state.ceph_gn_hdl, s, state->buf,
                                 state->bufsize, ol_ceph_generator_callback,
                                 &generator_state);

    ol_poll_addfd(s, NULL, ol_ceph_generator_pollout_func);

    generator_state.start_time = time(NULL);

    do {
        rc = ol_poll_process(&generator_state);
    } while (rc == OL_POLL_RC_OK);

    printf("generator: total ceph payload sent - %lu bytes\n",
           generator_state.data_sent);
    printf("generator: total time elapsed - %ld(s)\n",
           time(NULL) - generator_state.start_time);

    close(s);

    return rc == OL_POLL_RC_FAIL ? -1 : 0;
}
