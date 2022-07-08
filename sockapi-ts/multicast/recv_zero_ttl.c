/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Socket options
 * 
 * $Id$
 */

/** @page multicast-recv_zero_ttl Receiving multicast packets with zero TTL
 *
 * @objective Check that multicast packets with TTL set to zero cannot be
 *            received if they was sent from another host
 *
 * @type conformance
 *
 * @param pco_iut           PCO on IUT
 * @param pco_tst           PCO on TESTER
 * @param iut_if            Interface name/index on IUT
 * @param tst_if            Interface name/index on TESTER
 * @param mcast_addr        Multicast address used in the test
 * @param bind_wildcard     Whether to bind IUT socket to wildcard or
 *                          multicast address
 * @param method            Method used to join multicasting group
 * @param packet_number     Number of datagrams to send for reliability.
 * @param sock_func         Socket creation function.
 *
 * @par Test sequence:
 *
 * -# Do the following @p packet_number times:
 * -# Send from TESTER multicasting datagram with TTL=0.
 * -# Check that it was not received on IUT or seen on its network
 *    interface.
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME  "multicast/recv_zero_ttl"

#include "sockapi-test.h"
#include "tapi_cfg.h"
#include "multicast.h"
#include "mcast_lib.h"

#define MAX_MSG_LEN 100
#define MAX_MSG_NUM 10

int
main(int argc, char *argv[])
{
    int             sent = 0;
    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst = NULL;
    int             iut_s = -1;
    int             tst_s = -1;

    struct sockaddr_storage     aux_addr;
    const struct sockaddr      *mcast_addr;

    const struct if_nameindex  *iut_if = NULL;
    const struct sockaddr      *iut_addr = NULL;
    const struct if_nameindex  *tst_if = NULL;
    const struct sockaddr      *tst_addr = NULL;

    te_bool                     bind_wildcard;
    tarpc_joining_method        method;

    sockts_socket_func  sock_func;

    void                       *tx_buf = NULL;
    void                       *rx_buf = NULL;
    size_t                      buf_len;
    int                         i = 0;

    struct tarpc_mreqn  mreq;
    int                 optval;
    int                 packet_number;
    te_bool             readable;
    te_bool             is_failed = FALSE;
    mcast_listener_t    listener = CSAP_INVALID_HANDLE;

    /* Preambule */
    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_ADDR(pco_iut, mcast_addr);
    TEST_GET_IF(iut_if);
    TEST_GET_IF(tst_if);
    TEST_GET_BOOL_PARAM(bind_wildcard);
    TEST_GET_MCAST_METHOD(method);
    TEST_GET_INT_PARAM(packet_number);
    SOCKTS_GET_SOCK_FUNC(sock_func);

    MSGS_INIT(test_);

    /* Prepare data to transmit */
    CHECK_NOT_NULL((tx_buf = sockts_make_buf_dgram(&buf_len)));
    rx_buf = te_make_buf_by_len(buf_len);

    /* Scenario */

    iut_s = sockts_socket(sock_func, pco_iut,
                          rpc_socket_domain_by_addr(iut_addr),
                          RPC_SOCK_DGRAM, RPC_PROTO_DEF);

    tst_s = rpc_socket(pco_tst, rpc_socket_domain_by_addr(tst_addr),
                       RPC_SOCK_DGRAM, RPC_PROTO_DEF);

    rpc_bind(pco_tst, tst_s, tst_addr);
    memcpy(&aux_addr, mcast_addr, te_sockaddr_get_size(mcast_addr));
    if (bind_wildcard)
        te_sockaddr_set_wildcard(SA(&aux_addr));
    rpc_bind(pco_iut, iut_s, SA(&aux_addr));

    if (SIN(mcast_addr)->sin_addr.s_addr != htonl(INADDR_ALLHOSTS_GROUP))
    {
        CHECK_MCAST_HASH_COLLISION_CREATE_SOCK(pco_iut, pco_tst, iut_if,
                                               tst_addr, mcast_addr);
    }

    optval = 0;
    rpc_setsockopt(pco_tst, tst_s, RPC_IP_MULTICAST_TTL, &optval);

    optval = 0;
    rpc_getsockopt(pco_tst, tst_s, RPC_IP_MULTICAST_TTL, &optval);

    if (optval != 0)
        TEST_VERDICT("Changing multicast TTL value failure; "
                     "expected: 0, returned: %d", optval);

    rpc_mcast_join(pco_iut, iut_s, mcast_addr, iut_if->if_index, method);

    memset(&mreq, 0, sizeof(mreq));
    mreq.type = OPT_IPADDR;
    memcpy(&mreq.address, te_sockaddr_get_netaddr(tst_addr),
           sizeof(struct in_addr));
    rpc_setsockopt(pco_tst, tst_s, RPC_IP_MULTICAST_IF, &mreq);

    TAPI_WAIT_NETWORK;
        
    listener = mcast_listener_init(pco_iut, iut_if, mcast_addr, NULL, 1);

    for (i = 0; i < packet_number; i++)
    {
        test_msg_n = 0;
        mcast_listen_start(pco_iut, listener);

        RPC_SENDTO(sent, pco_tst, tst_s, tx_buf, buf_len, 0,
                   mcast_addr);

        TAPI_WAIT_NETWORK;

        rc = mcast_listen_stop(pco_iut, listener, NULL);
        if (rc > 0)
        {
            if (test_msg_n == MAX_MSG_NUM)
                TEST_FAIL("Too many error messages");
            snprintf(test_msgs[i][test_msg_n++], MAX_MSG_LEN,
                     "Multicasting packets were detected on "
                     "IUT interface");
            ERROR(test_msgs[i][test_msg_n - 1]);
            is_failed = TRUE;
        }

        RPC_GET_READABILITY(readable, pco_iut, iut_s, 1);
        if (readable)
        {
            if (test_msg_n == MAX_MSG_NUM)
                TEST_FAIL("Too many error messages");
            snprintf(test_msgs[i][test_msg_n++], MAX_MSG_LEN,
                     "IUT socket is readable");
            ERROR(test_msgs[i][test_msg_n - 1]);
            is_failed = TRUE;
            RECV_AND_CHECK(is_failed, test_msgs[i], MAX_MSG_LEN,
                           MAX_MSG_NUM, test_msg_n, 
                           pco_iut, iut_s, rx_buf, tx_buf, buf_len);
        }
    }

    MSGS_PRINT_VERDICTS(test_);

    if (is_failed)
        TEST_STOP;

    TEST_SUCCESS;

cleanup:

    MSGS_FREE(test_);

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    mcast_listener_fini(pco_iut, listener);

    free(tx_buf);
    free(rx_buf);

    TEST_END;
}
