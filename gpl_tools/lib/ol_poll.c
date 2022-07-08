/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * @author Sergey Nikitin <Sergey.Nikitin@oktetlabs.ru>
 */

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <poll.h>

#include "ol_poll.h"

/** Number of simultaneously polled sockets. */
#define MAX_POLLFDS 1024

/** Socket event callbacks type. */
typedef struct ol_pollfd_callbacks
{
    ol_poll_callback  pollin_callback;  /**< In event callback. */
    ol_poll_callback  pollout_callback; /**< Out event callback. */
} ol_pollfd_callbacks;

/** Array of polled sockets event callbacks. */
static ol_pollfd_callbacks pfds_cbs[MAX_POLLFDS];

/** Array of poll structures. */
static struct pollfd pfds[MAX_POLLFDS];

/** Number of sockets to poll. */
static size_t pfds_num = 0;

void
ol_poll_addfd(int fd, ol_poll_callback pollin_callback,
              ol_poll_callback pollout_callback)
{
    short int evts = 0;

    if (pollin_callback != NULL)
        evts |= POLLIN;

    if (pollout_callback != NULL)
        evts |= POLLOUT;

    pfds[pfds_num].fd = fd;
    pfds[pfds_num].events = evts;
    pfds[pfds_num].revents = 0;

    pfds_cbs[pfds_num].pollin_callback = pollin_callback;
    pfds_cbs[pfds_num].pollout_callback = pollout_callback;

    ++pfds_num;
}

int
ol_poll_process(void *user_data)
{
    int n_evts;
    int i;
    int rc;

    n_evts = poll(pfds, pfds_num, -1);
    if (n_evts < 0)
    {
        printf("poll(): %s\n", strerror(errno));
        return OL_POLL_RC_FAIL;
    }

    for (i = 0; i < n_evts; ++i)
    {
        if ((pfds[i].revents & POLLHUP) != 0)
        {
            printf("poll: peer closed the channel\n");
            return OL_POLL_RC_STOP;
        }
        else if ((pfds[i].revents & POLLERR) != 0)
        {
            printf("poll: error occured\n");
            return OL_POLL_RC_FAIL;
        }
        else
        {
            if ((pfds[i].revents & POLLIN) != 0)
            {
                rc = pfds_cbs[i].pollin_callback(pfds[i].fd, user_data);
                if (rc != OL_POLL_RC_OK)
                    return rc;
            }

            if ((pfds[i].revents & POLLOUT) != 0)
            {
                rc = pfds_cbs[i].pollout_callback(pfds[i].fd, user_data);
                if (rc != OL_POLL_RC_OK)
                    return rc;
            }
        }
    }

    return OL_POLL_RC_OK;
}
