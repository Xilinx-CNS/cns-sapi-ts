/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/** @file
 * @brief Socket API Test Suite
 *
 * Common macros and functions for Onload wire order delivery API.
 *
 *
 * @author Andrey Dmitrov <Andrey.Dmitrov@oktetlabs.ru>
 *
 * $Id$
 */

#ifndef __ONLOAD_ORDERED_EPOLL_H__
#define __ONLOAD_ORDERED_EPOLL_H__

/**
 * Find @b oo_event by file descriptor in the epoll events list.
 * 
 * @param sock       Socket to search event
 * @param events     Epoll events array
 * @param oo_events  Onload extension events array
 * @param num        Events number
 * 
 * @return Pointer to @b oo_event or finish test with verdict if the event
 *         was not found.
 */
static rpc_onload_ordered_epoll_event *
oo_epoll_get_event_by_fd(int sock, struct rpc_epoll_event *events,
                         rpc_onload_ordered_epoll_event *oo_events, int num)
{
    int i;

    for (i = 0; i < num; i++)
    {
        if (events[i].data.fd == sock)
            return oo_events + i;
    }

    ERROR("Onload epoll doesn't observe events on socket %d", sock);
    TEST_VERDICT("Expected event was not returned by oo_epoll");
    return NULL;
}

/**
 * Find @b oo_event by file descriptor in the epoll events list and check
 * its bytes number in the @b bytes field.
 * 
 * @param sock       Socket to search event
 * @param events     Epoll events array
 * @param oo_events  Onload extension events array
 * @param num        Events number
 * @param bytes      Expected bytes number
 * 
 * @return @c TRUE if returned bytes number is NOT equal to expected.
 */
static inline te_bool
oo_epoll_check_bytes(int sock, struct rpc_epoll_event *events,
                     rpc_onload_ordered_epoll_event *oo_events, int num,
                     int bytes)
{
    rpc_onload_ordered_epoll_event *ev;

    ev = oo_epoll_get_event_by_fd(sock, events, oo_events, num);

    if (ev->bytes != bytes)
        return TRUE;
    return FALSE;
}

/**
 * Compare timestamps of two Onload extension events @b oo_events.
 * 
 * @param oo_ev_1  First event
 * @param oo_ev_2  Second event
 * 
 * @return  0: timestamps are equal;
 *         -1: timestamps of the first event is less than the second;
 *          1: timestamps of the first event is greater than the second.
 */
static inline int
oo_epoll_cmp_ts(rpc_onload_ordered_epoll_event *oo_ev_1,
                rpc_onload_ordered_epoll_event *oo_ev_2)
{
    if (memcmp(&oo_ev_1->ts, &oo_ev_2->ts, sizeof(oo_ev_1->ts)) == 0)
        return 0;

    if (oo_ev_1->ts.tv_sec < oo_ev_2->ts.tv_sec ||
        (oo_ev_1->ts.tv_sec == oo_ev_2->ts.tv_sec &&
         oo_ev_1->ts.tv_nsec < oo_ev_2->ts.tv_nsec))
        return -1;

    return 1;
}

#endif /* __ONLOAD_ORDERED_EPOLL_H__ */
