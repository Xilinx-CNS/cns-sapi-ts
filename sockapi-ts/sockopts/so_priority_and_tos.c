/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Socket options
 * 
 * $Id$
 */

/** @page sockopts-so_priority_and_tos SO_PRIORITY and IP_TOS socket options interaction.
 *
 * @objective Check that both @c SO_PRIORITY and @c IP_TOS options can be used
 *            to set @c TOS field of outgoing IP packets.
 *
 * @type conformance
 *
 * @param pco_iut       PCO on IUT
 * @param pco_tst       PCO on TESTER
 * @param iut_addr      Address on IUT
 * @param tst_addr      Address on Tester
 *
 * @par Test sequence:
 * -# Open datagram sockets: @p iut_s on @p pco_iut and @p tst_s on @p pco_tst.
 * -# Enable @c IP_RECVTOS socket option on @p tst_s.
 * -# Bind @p iut_s to @p iut_addr.
 * -# Perform the following operations on it:
 *     -# Get @c SO_PRIORITY option value. Make sure it equals 0.
 *     -# Set @c IP_TOS option value equal to @c IPTOS_MINCOST.
 *     -# Get @c SO_PRIORITY option value. Make sure it is equal to 1.
 *     -# Set @c IP_TOS option value equal to @c IPTOS_THROUGHPUT.
 *     -# Get @c SO_PRIORITY option value. Make sure it is equal to 2.
 *     -# Set all allowed @c SO_PRIORITY option values (from 0 up to 6).
 *     -# For each value:
 *         -# Make sure @c IP_TOS options value remains equal
 *            to @c IPTOS_THROUGHPUT.
 *         -# Send a datagram from @p tst_s to @p iut_addr.
 *         -# Receive TOS information message. Check that TOS is equal
 *            to @c IPTOS_THROUGHPUT.
 * -# Close sockets.
 *
 * @author Ivan Soloducha <Ivan.Soloducha@oktetlabs.ru>
 */

#define TE_TEST_NAME  "sockopts/so_priority_and_tos"

#include "sockapi-test.h"
#if HAVE_NETINET_IP_H
#include <netinet/ip.h>
#endif

#define SPAT_PRIORITY_MAX 6
#define SPAT_PRIORITY_MIN 0
#define DATA_BULK         1024
#define MSG_LEN           10

int
main(int argc, char *argv[])
{
    rcf_rpc_server        *pco_iut = NULL;
    rcf_rpc_server        *pco_tst = NULL;
    const struct sockaddr *iut_addr = NULL;
    const struct sockaddr *tst_addr = NULL;
    int                    iut_s = -1;
    int                    tst_s = -1;
    
    uint32_t               tos_val;
    uint32_t               prior_val;
    uint32_t               tos_received = 0;
    uint32_t               opt_enable = 1;

    rpc_iovec  vector = { .iov_base = NULL,
                          .iov_len = DATA_BULK,
                          .iov_rlen = DATA_BULK };
    rpc_msghdr message = { .msg_name = NULL,
                           .msg_namelen = 0,
                           .msg_iov = &vector,
                           .msg_iovlen = 1,
                           .msg_control = NULL,
                           .msg_controllen = 0,
                           .msg_flags = 0,
                           .msg_rnamelen = 0,
                           .msg_riovlen = 1,
                           .msg_cmsghdr_num = 1,
                           .msg_flags_mode = RPC_MSG_FLAGS_SET_CHECK };

    struct cmsghdr        *cmsg = NULL;
    uint8_t               *sendbuf = NULL;
    uint8_t               *recvbuf = NULL;
    uint8_t               *ctrl_buf = NULL;
    int                    ret;

    te_bool                connected = FALSE;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_BOOL_PARAM(connected);

    sendbuf = te_make_buf_by_len(DATA_BULK);
    CHECK_NOT_NULL(recvbuf = malloc(DATA_BULK));
    CHECK_NOT_NULL(ctrl_buf = malloc(DATA_BULK));
    vector.iov_base = recvbuf;
    message.msg_control = ctrl_buf;
    message.msg_controllen = DATA_BULK;

    iut_s = rpc_socket(pco_iut, RPC_PF_INET, RPC_SOCK_DGRAM, RPC_PROTO_DEF);
    tst_s = rpc_socket(pco_tst, RPC_PF_INET, RPC_SOCK_DGRAM, RPC_PROTO_DEF);

    rpc_bind(pco_iut, iut_s, iut_addr);
    rpc_bind(pco_tst, tst_s, tst_addr);
    if (connected)
        rpc_connect(pco_iut, iut_s, tst_addr);

    rpc_setsockopt(pco_tst, tst_s, RPC_IP_RECVTOS, &opt_enable);

    RPC_AWAIT_IUT_ERROR(pco_iut);
    ret = rpc_getsockopt(pco_iut, iut_s, RPC_SO_PRIORITY, &tos_val);
    if (ret != 0)
    {
        TEST_VERDICT("getsockopt(SOL_SOCKET, SO_PRIORITY) failed with "
                     "errno %s", errno_rpc2str(RPC_ERRNO(pco_iut)));
    }

    if (tos_val != 0)
        TEST_VERDICT("SO_PRIORITY value is not zero by default");

    tos_val = IPTOS_MINCOST;
    rpc_setsockopt(pco_iut, iut_s, RPC_IP_TOS, &tos_val);
    rpc_getsockopt(pco_iut, iut_s, RPC_SO_PRIORITY, &tos_val);


    RING_VERDICT("Setting IP_TOS option to IPTOS_MINCOST leads to "
                 "SO_PRIORITY option value is %d", tos_val);

    tos_val = IPTOS_THROUGHPUT;
    
    rpc_setsockopt(pco_iut, iut_s, RPC_IP_TOS, &tos_val);
    rpc_getsockopt(pco_iut, iut_s, RPC_SO_PRIORITY, &tos_val);

    if (tos_val != 2)
        TEST_VERDICT("Setting IP_TOS option to IPTOS_THROUGHPUT has not "
                     " changed SO_PRIORITY option value to 2");

    for (prior_val = SPAT_PRIORITY_MIN; prior_val <= SPAT_PRIORITY_MAX;
         prior_val++)
    {
        rpc_setsockopt(pco_iut, iut_s, RPC_SO_PRIORITY, &prior_val);
        rpc_getsockopt(pco_iut, iut_s, RPC_IP_TOS, &tos_val);
        if (tos_val != IPTOS_THROUGHPUT)
            TEST_VERDICT("Setting SO_PRIORITY value has changed IP_TOS value");
        
        if (connected)
            rpc_send(pco_iut, iut_s, sendbuf, MSG_LEN, 0);
        else
            rpc_sendto(pco_iut, iut_s, sendbuf, MSG_LEN, 0, tst_addr);

        /*
         * Field should be reset before each call because it may be updated
         * by the previous call.
         */
        message.msg_controllen = DATA_BULK;

        rpc_recvmsg(pco_tst, tst_s, &message, 0);
        cmsg = sockts_msg_lookup_control_data(&message, SOL_IP, IP_TOS);
        if (cmsg == NULL)
        {
            TEST_VERDICT("Could not get TOS value");
        }

        tos_received = *(uint8_t *)CMSG_DATA(cmsg);
        
        if (tos_received != IPTOS_THROUGHPUT)
            TEST_FAIL("Setting SO_PRIORITY value has changed "
                      "real TOS value to %d", tos_received);
    }

    TEST_SUCCESS;               

cleanup:
    free(sendbuf);
    free(recvbuf);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    TEST_END;
}

