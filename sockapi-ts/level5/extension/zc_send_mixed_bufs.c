/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Onload extensions
 */

/** @page extension-zc_send_mixed_bufs Pass to onload_zc_send() array of buffers allocated in different ways
 *
 * @objective Check that @b onload_zc_send() can handle a message in
 *            which part of buffers is allocated with
 *            @b onload_zc_alloc_buffers() while others are
 *            configured with @b onload_zc_register_buffers().
 *
 * @param env               Network environment configuration:
 *                          - @ref arg_types_env_peer2peer
 *                          - @ref arg_types_env_peer2peer_ipv6
 * @param sock_type         Socket type:
 *                          - @c tcp_active
 *                          - @c tcp_passive
 *                          - @c tcp_passive_close
 * @param allocation        How to allocate ZC buffers:
 *                          - @c two_groups_first_alloc (two groups of
 *                            buffers, the first one is configured with
 *                            @b onload_zc_alloc_buffers(), the second
 *                            one - with @b onload_zc_register_buffers())
 *                          - @c two_groups_first_reg (two groups of
 *                            buffers, the first one is configured with
 *                            @b onload_zc_register_buffers(), the second
 *                            one - with @b onload_zc_alloc_buffers())
 *                          - @c random (for each buffer choose randomly
 *                            which Onload function to use)
 *
 * @type Conformance
 *
 * @par Scenario:
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME  "level5/extension/zc_send_mixed_bufs"

#include "sockapi-test.h"

/** Minimum number of buffers to send */
#define MIN_BUFS 2
/** Maximum number of buffers to send */
#define MAX_BUFS 15
/** Maximum length of the single buffer */
#define MAX_BUF_LEN 1400

/** Values of allocation parameter */
enum {
    ALLOC_TWO_GROUPS_FIRST_ALLOC, /**< "two_groups_first_alloc" */
    ALLOC_TWO_GROUPS_FIRST_REG,   /**< "two_groups_first_reg" */
    ALLOC_RANDOM,                 /**< "random" */
};

/** List of allocation parameter values for TEST_GET_ENUM_PARAM() */
#define ALLOCATION_TYPES \
    { "two_groups_first_alloc", ALLOC_TWO_GROUPS_FIRST_ALLOC }, \
    { "two_groups_first_reg", ALLOC_TWO_GROUPS_FIRST_REG },     \
    { "random", ALLOC_RANDOM }

int
main(int argc, char *argv[])
{
    rcf_rpc_server            *pco_iut = NULL;
    rcf_rpc_server            *pco_tst = NULL;
    const struct sockaddr     *iut_addr = NULL;
    const struct sockaddr     *tst_addr = NULL;
    sockts_socket_type         sock_type;
    int                        allocation;

    int                        bufs_num;
    int                        first_num;
    rpc_iovec                  iovs[MAX_BUFS];
    char                       bufs[MAX_BUFS][MAX_BUF_LEN];
    char                       recv_buf[MAX_BUFS * MAX_BUF_LEN];

    struct tarpc_onload_zc_buf_spec  buf_specs[MAX_BUFS];
    tarpc_onload_zc_buf_type         first_type;
    tarpc_onload_zc_buf_type         second_type;

    int                        i;
    int                        total_bytes = 0;
    int                        processed_bytes = 0;
    struct rpc_onload_zc_mmsg  mmsg;

    int        iut_s  = -1;
    int        iut_l  = -1;
    int        tst_s  = -1;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    SOCKTS_GET_SOCK_TYPE(sock_type);
    TEST_GET_ENUM_PARAM(allocation, ALLOCATION_TYPES);

    TEST_STEP("Establish TCP connection according to @p sock_type.");
    SOCKTS_CONNECTION(pco_iut, pco_tst, iut_addr, tst_addr, sock_type,
                      &iut_s, &tst_s, &iut_l);

    bufs_num = rand_range(MIN_BUFS, MAX_BUFS);
    first_num = rand_range(1, bufs_num - 1);

    if (allocation == ALLOC_TWO_GROUPS_FIRST_ALLOC)
    {
        first_type = TARPC_ONLOAD_ZC_BUF_NEW_ALLOC;
        second_type = TARPC_ONLOAD_ZC_BUF_NEW_REG;
    }
    else
    {
        first_type = TARPC_ONLOAD_ZC_BUF_NEW_REG;
        second_type = TARPC_ONLOAD_ZC_BUF_NEW_ALLOC;
    }

    memset(iovs, 0, sizeof(iovs));
    memset(buf_specs, 0, sizeof(buf_specs));
    for (i = 0; i < bufs_num; i++)
    {
        iovs[i].iov_base = bufs[i];
        iovs[i].iov_len = iovs[i].iov_rlen = rand_range(1, MAX_BUF_LEN);
        te_fill_buf(bufs[i], iovs[i].iov_len);
        total_bytes += iovs[i].iov_len;

        if (allocation == ALLOC_RANDOM)
        {
            if (rand_range(1, 2) % 2 == 0)
                buf_specs[i].type = TARPC_ONLOAD_ZC_BUF_NEW_ALLOC;
            else
                buf_specs[i].type = TARPC_ONLOAD_ZC_BUF_NEW_REG;
        }
        else
        {
            if (i < first_num)
                buf_specs[i].type = first_type;
            else
                buf_specs[i].type = second_type;
        }
    }

    memset(&mmsg, 0, sizeof(mmsg));
    mmsg.msg.msg_iov = iovs;
    mmsg.msg.msg_iovlen = mmsg.msg.msg_riovlen = bufs_num;
    mmsg.fd = iut_s;
    mmsg.buf_specs = buf_specs;

    TEST_STEP("Call @b onload_zc_send() on the IUT socket, passing to it "
              "array of buffers allocated/registered according to "
              "@p allocation.");
    RPC_AWAIT_ERROR(pco_iut);
    rc = rpc_simple_zc_send_gen(pco_iut, &mmsg, 1, 0, -1, FALSE,
                                RPC_NULL, NULL);
    if (rc < 0)
    {
        TEST_VERDICT("onload_zc_send() failed with unexpected error "
                     RPC_ERROR_FMT, RPC_ERROR_ARGS(pco_iut));
    }
    else if (rc == 0)
    {
        TEST_VERDICT("onload_zc_send() returned zero");
    }
    else if (rc != 1)
    {
        TEST_VERDICT("onload_zc_send() returned unexpected value");
    }
    else if (mmsg.rc < 0)
    {
        TEST_VERDICT("onload_zc_send() returned error %r in mmsg.rc",
                     -mmsg.rc);
    }
    else if (mmsg.rc != total_bytes)
    {
        TEST_VERDICT("onload_zc_send() set mmsg.rc to unexpected value");
    }

    TAPI_WAIT_NETWORK;

    TEST_STEP("Receive all data on the Tester socket, check that it "
              "matches the sent data.");

    RPC_AWAIT_ERROR(pco_tst);
    rc = rpc_recv(pco_tst, tst_s, recv_buf, sizeof(recv_buf), 0);
    if (rc < 0)
    {
        TEST_VERDICT("recv() failed on Tester with errno %r",
                      RPC_ERRNO(pco_tst));
    }
    else if (rc != total_bytes)
    {
        ERROR("recv() returned %d instead of %d", rc, total_bytes);
        TEST_VERDICT("recv() on Tester returned unexpected value");
    }

    for (i = 0; i < bufs_num; i++)
    {
        if (memcmp(recv_buf + processed_bytes, iovs[i].iov_base,
                   iovs[i].iov_len) != 0)
        {
            TEST_VERDICT("Received data does not match sent data");
        }
        processed_bytes += iovs[i].iov_len;
    }

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_iut, iut_l);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    TEST_END;
}
