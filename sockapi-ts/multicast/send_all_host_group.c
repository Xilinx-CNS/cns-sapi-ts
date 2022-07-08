/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Multicasting in IP
 *
 * $Id$
 */

/** @page multicast-send_all_host_group Receiving multicast traffic sent to all-hosts group, on non-joined socket.
 *
 * @objective Check that IUT receives multicast traffic sent to address
 *            224.0.0.1 (all-hosts group).
 *
 * @type Conformance.
 *
 * @param pco_iut         PCO on IUT
 * @param pco_tst         PCO on Tester
 * @param iut_s           Datagram socket on IUT
 * @param tst_s           Datagram socket on Tester
 * @param mcast_addr      Multicasting address
 * @param bind_multiaddr  If TRUE, bind @p iut_s to @p mcast_addr,
 *                        otherwise bind it to @c INADDR_ANY
 * @param packet_number   Number of datagrams to send for reliability.
 * @param sock_func       Socket creation function.
 *
 * @par Scenario:
 *
 * -# Create datagram sockets: @p iut_s on @p pco_iut and
 *    @p tst_s on @p pco_tst.
 * -# Bind @p iut_s to @c INADDR_ANY or to @p mcast_addr,
 *    depending on @p bind_multiaddr value.
 * -# Send @p packet_number datagrams from @p tst_s to @p mcast_addr.
 * -# Sleep a little.
 * -# Receive and verify datagrams on @p iut_s. If no error occured,
 *    test is passed.
 *     
 * @author Ivan Soloducha <Ivan.Soloducha@oktetlabs.ru>
 */

#define TE_TEST_NAME  "multicast/send_all_host_group"

#include "sockapi-test.h"
#include "mcast_lib.h"

#define DATA_BULK          200

int
main(int argc, char *argv[])
{
    rpc_socket_domain      domain = RPC_PF_INET;
    rcf_rpc_server        *pco_iut = NULL;
    rcf_rpc_server        *pco_tst = NULL;

    const struct if_nameindex   *iut_if;
    const struct if_nameindex   *tst_if;

    int                    iut_s = -1;
    int                    tst_s = -1;
    const struct sockaddr *mcast_addr = NULL;
    te_bool                bind_multiaddr;
    uint8_t               *sendbuf = NULL;
    uint8_t               *recvbuf = NULL;
    te_bool                sock_readable;
    int                    packet_number;
    int                    i;

    mcast_listener_t listener = CSAP_INVALID_HANDLE;
    int              detected = 0;

    te_bool          use_zc = FALSE;
    rpc_msghdr       msg;
    struct rpc_iovec vector;

    sockts_socket_func  sock_func;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_IF(iut_if);
    TEST_GET_IF(tst_if);
    TEST_GET_ADDR(pco_tst, mcast_addr);
    TEST_GET_BOOL_PARAM(bind_multiaddr);
    TEST_GET_INT_PARAM(packet_number);
    TEST_GET_BOOL_PARAM(use_zc);
    SOCKTS_GET_SOCK_FUNC(sock_func);

    iut_s = sockts_socket(sock_func, pco_iut, domain,
                          RPC_SOCK_DGRAM, RPC_IPPROTO_UDP);
    tst_s = rpc_socket(pco_tst, domain, RPC_SOCK_DGRAM, RPC_IPPROTO_UDP);

    rpc_setsockopt_raw(pco_tst, tst_s, RPC_SO_BINDTODEVICE,
                       tst_if->if_name, IFNAMSIZ);

    if (bind_multiaddr)
    {
        rpc_bind(pco_iut, iut_s, mcast_addr);
    }
    else
    {
        struct sockaddr_storage bind_addr;

        memset(&bind_addr, 0, sizeof(bind_addr));
        SIN(&bind_addr)->sin_family = SIN(mcast_addr)->sin_family;
        SIN(&bind_addr)->sin_port = SIN(mcast_addr)->sin_port;
        rpc_bind(pco_iut, iut_s, SA(&bind_addr));
    }

    sendbuf = te_make_buf_by_len(DATA_BULK);
    CHECK_NOT_NULL(recvbuf = (uint8_t *)malloc(DATA_BULK));

    if (!use_zc)
        listener = mcast_listener_init(pco_iut, iut_if, mcast_addr,
                                       NULL, 1);

    for (i = 0; i < packet_number; i++)
    {
        if (!use_zc)
            mcast_listen_start(pco_iut, listener);
        rpc_sendto(pco_tst, tst_s, sendbuf, DATA_BULK, 0, mcast_addr);

        MSLEEP(100);
        if (!use_zc)
        {
            rc = mcast_listen_stop(pco_iut, listener, NULL);
            if (rc > 0)
                detected++;
        }

        RPC_GET_READABILITY(sock_readable, pco_iut, iut_s, 1);
        if (!sock_readable)
        {
            TEST_VERDICT("IUT does not accept traffic destined to "
                         "all-hosts group");
        }

        if (use_zc)
        {
            memset(&msg, 0, sizeof(msg));
            vector.iov_base = recvbuf;
            vector.iov_len = vector.iov_rlen = DATA_BULK;
            msg.msg_iov = &vector;
            msg.msg_iovlen = msg.msg_riovlen = 1;
            RPC_AWAIT_IUT_ERROR(pco_iut);
            rc = rpc_simple_zc_recv_acc(pco_iut, iut_s, &msg, 0);
            if (rc == -1)
            {
                CHECK_RPC_ERRNO(pco_iut, RPC_ENOTEMPTY,
                                "onload_zc_recv() returns %d, but",
                                rc);
                rc = rpc_simple_zc_recv(pco_iut, iut_s, &msg, 0);
                detected++;
            }
        }
        else
            rc = rpc_recv(pco_iut, iut_s, recvbuf, DATA_BULK, 0);
        if (rc != DATA_BULK ||
            memcmp(sendbuf, recvbuf, DATA_BULK) != 0)
        {
            TEST_VERDICT("Data verification failed");
        }
        if (detected == 1)
            RING_VERDICT("Multicast packet was detected by system");
    }

    TEST_SUCCESS;

cleanup:
    if (!use_zc)
        mcast_listener_fini(pco_iut, listener);
    free(sendbuf);
    free(recvbuf);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    TEST_END;
}
