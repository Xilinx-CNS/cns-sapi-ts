/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Socket options
 */

/** @page bnbvalue-send_oob_dgram Behavior of the sending functions on socket of SOCK_DGRAM type if flag MSG_OOB is passed
 *
 * @objective Check that sending functions correctly process @c MSG_OOB flag if
 *            called on socket of the @c SOCK_DGRAM type.
 *
 * @type conformance
 *
 * @param env           Testing environment
 *                       - @ref arg_types_env_peer2peer_all_ipv4_ipv6
 * @param func_tested   Name of function to be tested:
 *                      - @b send
 *                      - @b sendto
 *                      - @b sendmsg
 *                      - @b sendmmsg
 *                      - @b onload_zc_send
 *                      - @b onload_zc_send_user_buf
 *
 * @par Test sequence:
 *
 * @author Igor Vasiliev <Igor.Vasiliev@oktetlabs.ru>
 */

#define TE_TEST_NAME  "bnbvalue/send_oob_dgram"

#include "sockapi-test.h"

#define TST_BUF_LEN  300


int
main(int argc, char *argv[])
{
    rcf_rpc_server    *pco_iut = NULL;
    rcf_rpc_server    *pco_tst = NULL;
    int                iut_s = -1;
    int                tst_s = -1;

    const struct sockaddr  *iut_addr;
    const struct sockaddr  *tst_addr;
    const char             *func_tested;

    char                    tx_buf[TST_BUF_LEN];
    char                    rx_buf[TST_BUF_LEN];

    int                     bytes_sent;

    /* Preambule */
    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_STRING_PARAM(func_tested);

    /* Scenario */
    te_fill_buf(tx_buf, TST_BUF_LEN);

    TEST_STEP("Create network connection of sockets of @c SOCK_DGRAM type "
              "by means of @c GEN_CONNECTION, obtain sockets @p iut_s on "
              "@p pco_iut and @p tst_s on @p pco_tst.");
    GEN_CONNECTION(pco_tst, pco_iut, RPC_SOCK_DGRAM, RPC_PROTO_DEF,
                   tst_addr, iut_addr, &tst_s, &iut_s);

    TEST_STEP("Call @p func_tested on @p iut_s with @c MSG_OOB flag.");
    RPC_AWAIT_IUT_ERROR(pco_iut);
    if (strcmp(func_tested, "send") == 0)
    {
        rc = rpc_send(pco_iut, iut_s, tx_buf, TST_BUF_LEN, RPC_MSG_OOB);
    }
    else if (strcmp(func_tested, "sendto") == 0)
    {
        rc = rpc_sendto(pco_iut, iut_s, tx_buf, TST_BUF_LEN, RPC_MSG_OOB,
                        NULL);
    }
    else if (strcmp(func_tested, "sendmsg") == 0 ||
             strcmp(func_tested, "sendmmsg") == 0 ||
             strcmp(func_tested, "onload_zc_send") == 0 ||
             strcmp(func_tested, "onload_zc_send_user_buf") == 0)
    {
        struct rpc_iovec  tx_buf_vec = {tx_buf, TST_BUF_LEN, TST_BUF_LEN};
        struct rpc_msghdr msg;

        memset(&msg, 0, sizeof(msg));
        msg.msg_iov = &tx_buf_vec;
        msg.msg_iovlen = 1;
        msg.msg_riovlen = 1;
        if (strcmp(func_tested, "sendmsg") == 0)
        {
            rc = rpc_sendmsg(pco_iut, iut_s, &msg, RPC_MSG_OOB);
        }
        else if (strcmp(func_tested, "sendmmsg") == 0)
        {
            rc = rpc_sendmmsg_as_sendmsg(pco_iut, iut_s, &msg, RPC_MSG_OOB);
        }
        else if (strcmp(func_tested, "onload_zc_send") == 0)
        {
            rc = rpc_simple_zc_send(pco_iut, iut_s, &msg, RPC_MSG_OOB);
        }
        else
        {
            rc = rpc_simple_zc_send_user_buf(pco_iut, iut_s, &msg,
                                             RPC_MSG_OOB);
        }
    }

    TEST_STEP("Check that @b func_tested returns @c -1 and sets @b errno to "
              "@c EOPNOTSUPP. If @b func_tested succeeds check recv() on "
              "tester side.");
    if (rc != -1)
    {
        RING_VERDICT("%s(MSG_OOB) succeeded unexpectedly", func_tested);

        TAPI_WAIT_NETWORK;
        bytes_sent = rc;

        if (bytes_sent != TST_BUF_LEN)
        {
            RING("%s() returns %i instead of %i", func_tested, bytes_sent,
                 TST_BUF_LEN);
            RING_VERDICT("Less data was sent from IUT than requested");
        }

        RPC_AWAIT_IUT_ERROR(pco_tst);
        rc = rpc_recv(pco_tst, tst_s, rx_buf, TST_BUF_LEN, MSG_DONTWAIT);

        if (rc < 0)
        {
            TEST_VERDICT("recv() on 'tst_s' failed with %r",
                         RPC_ERRNO(pco_tst));
        }

        if (rc != bytes_sent)
        {
            RING("recv() returns %i instead of %i", rc, bytes_sent);
            TEST_VERDICT("Number of bytes received on Tester does not "
                         "match number of bytes sent from IUT");
        }

        if (memcmp(tx_buf, rx_buf, rc) != 0)
        {
            TEST_VERDICT("Data received on 'tst_s' differs from data sent "
                         "from 'iut_s'");
        }
        else
        {
            RING_VERDICT("recv() on 'tst_s' succeeded");
        }
    }
    else
    {
        CHECK_RPC_ERRNO(pco_iut, RPC_EOPNOTSUPP,
                        "%s(MSG_OOB) function called on 'iut_s' "
                        "returns -1, but", func_tested);
    }

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    TEST_END;
}
