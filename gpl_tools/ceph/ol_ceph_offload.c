/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * @author Sergey Nikitin <Sergey.Nikitin@oktetlabs.ru>
 */

#include <stdio.h>
#include <string.h>
#include <netinet/in.h>

#if HAVE_ZC
#include "onload/extensions_zc.h"
#endif

#include "ol_ceph_offload.h"

/**
 * Set @c ONLOAD_TCP_OFFLOAD socket option with @p optval.
 *
 * @param socket    Socket
 * @param optval    Value to set.
 *
 * @return zero, on success, or @c -1 in case of error.
 */
static int
set_offload_option(int socket, int optval)
{
    int rc = -1;

#ifdef ONLOAD_TCP_OFFLOAD
    rc = setsockopt(socket, IPPROTO_TCP, ONLOAD_TCP_OFFLOAD, &optval,
                    sizeof(optval));
    if (rc != 0)
    {
        fprintf(stderr, "setsockopt(IPPROTO_TCP, ONLOAD_TCP_OFFLOAD, %d) "
                "failed with error - %s\n", optval, strerror(errno));
    }
#else
    printf("ONLOAD_TCP_OFFLOAD is undefined. TCP/Ceph offloading is not "
           "supported\n");
#endif /* ONLOAD_TCP_OFFLOAD */

    return rc;
}

void
ol_ceph_offload_enable(int socket)
{
    if (set_offload_option(socket, OFFLOAD_ID_CEPH) != 0)
        fprintf(stderr, "Failed to enable TCP/Ceph offloading\n");
}

void
ol_ceph_offload_disable(int socket)
{
    if (set_offload_option(socket, 0) != 0)
        fprintf(stderr, "Failed to disable TCP/Ceph offloading\n");
}

bool
ol_ceph_offload_check(int socket)
{
#ifdef ONLOAD_TCP_OFFLOAD
    int offload = 0;
    socklen_t offload_len = sizeof(offload);
    int rc = 0;

    rc = getsockopt(socket, IPPROTO_TCP, ONLOAD_TCP_OFFLOAD, &offload,
                    &offload_len);

    if (rc == 0 && offload == OFFLOAD_ID_CEPH)
        return true;
#endif /* ONLOAD_TCP_OFFLOAD */
    return false;
}
