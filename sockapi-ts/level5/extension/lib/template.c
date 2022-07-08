/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Helper functions for Onload templates transmission
 *
 * $Id$
 */

#include "sockapi-test.h"
#include "template.h"

/**
 * Set number to its position in array
 * 
 * @param pos   Ordered array with number
 * @param max   Actual number of items in the array
 * @param new   New ite to be added
 * 
 * @return @c TRUE if the same number exists in the array
 */
static te_bool
add_to_pos(int *pos, int max, int new)
{
    int i;
    int tmp;

    for (i = 0; i < max + 1; i++)
    {
        if (new == pos[i])
            return TRUE;

        if (new < pos[i] || pos[i] < 0)
        {
            tmp = pos[i];
            pos[i] = new;
            new = tmp;
        }
    }

    return FALSE;
}

/**
 * Split total length to iov vectors
 * 
 * @param iov       Vectors array
 * @param iovcnt    Length of the array
 * @param total     Total payload length of all vectors
 */
static void
generate_vectors_length(rpc_iovec *iov, int iovcnt, int total)
{
    int  i;
    int offt = 0;
    int *pos = te_calloc_fill(iovcnt, sizeof(*pos), 0xff);

    int check_total = 0;

    if (iovcnt < 1)
        TEST_FAIL("Argument iovcnt must not be less 1");
    else if (iovcnt == 1)
    {
        iov->iov_len = iov->iov_rlen = total;
        return;
    }

    for (i = 0; i < iovcnt - 1; i++)
        while (add_to_pos(pos, i, rand_range(1, total - 1)))
            ;

    for (i = 0; i < iovcnt - 1; i++)
    {
        iov[i].iov_len = iov[i].iov_rlen = pos[i] - offt;
        offt = pos[i];
        check_total += iov[i].iov_len;
    }
    iov[i].iov_len = iov[i].iov_rlen = total - pos[i - 1];
    check_total += iov[i].iov_len;
    if (check_total != total)
        TEST_FAIL("Wrong total sum of generated vectors");

    free(pos);
}

/* See template.h */
rpc_iovec *
init_iovec(int iovcnt, int total, char **sndbuf)
{
    rpc_iovec *iov;
    int i;
    int offt = 0;

    iov = te_calloc_fill(iovcnt, sizeof(*iov), 0);

    generate_vectors_length(iov, iovcnt, total);

    for (i = 0; i < iovcnt; i++)
        iov[i].iov_base = te_make_buf_by_len(iov[i].iov_len);

    if (sndbuf == NULL)
        return iov;

    *sndbuf = te_calloc_fill(total, 1, 0);
    for (i = 0; i < iovcnt; i++)
    {
        memcpy(*sndbuf + offt, iov[i].iov_base, iov[i].iov_len);
        offt += iov[i].iov_len;
    }

    return iov;
}

/* See template.h */
void
release_iovec(rpc_iovec *iov, int iovcnt)
{
    int i;

    if (iov == NULL)
        return;

    for (i = 0; i < iovcnt; i++)
        free(iov[i].iov_base);

    free(iov);
}
