/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Basic Socket API
 */

/** @page tcp-out_of_socks_tcp_loopback Testing of TCP loopback connection in case of many created TCP sockets
 *
 * @objective Check that TCP loopback connection is accelerated when all
 *            TCP accelerated sockets are opened and 1/2/3 socket are
 *            closed after this.
 *
 * @type conformance
 *
 * @param pco_iut        PCO on IUT
 * @param pco_tst        Another PCO on IUT
 * @param iut_addr       Address on SFC interface
 * @param conn_stack     If @c TRUE, open many sockets on active (Tester)
 *                       side of TCP loopback connection; otherwise
 *                       open them on IUT
 * @param sock_close_num Number of socket to close:
 *                       - @c 1
 *                       - @c 2
 *                       - @c 3
 *
 * @par Test sequence:
 *
 * @author Yurij Plotnikov <Yurij.Plotnikov@oktetlabs.ru>
 */

#define TE_TEST_NAME    "tcp/out_of_socks_tcp_loopback"

#include "sockapi-test.h"
#include "onload.h"
#include "tapi_tcp.h"
#include "iomux.h"

/** Maximum number of sockets to create */
#define MAX_SOCKS 1024

int
main(int argc, char *argv[])
{
    rcf_rpc_server    *pco_iut = NULL;
    rcf_rpc_server    *pco_tst = NULL;
    rcf_rpc_server    *pco_socks = NULL;
    int                iut_s = -1;
    int                tst_s = -1;
    int                acc_s = -1;
    int                socks[MAX_SOCKS];

    const struct sockaddr *iut_addr = NULL;

    te_bool                conn_stack;
    int                    sock_close_num;
    int                    sock_num = 0;
    int                    i = 0;

    int                    sid;
    unsigned int           received_packets_number = 0;
    csap_handle_t          csap = CSAP_INVALID_HANDLE;

    const struct if_nameindex *iut_if = NULL;

    struct tarpc_rlimit rlim_tst = { 0 };
    struct tarpc_rlimit rlim_iut = { 0 };
    struct tarpc_rlimit rlim_new = { 0 };
    te_bool             rlimit_met = FALSE;

    /* Preambule */
    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_IF(iut_if);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_BOOL_PARAM(conn_stack);
    TEST_GET_INT_PARAM(sock_close_num);

    for (i = 0; i < MAX_SOCKS; i++)
        socks[i] = -1;

    TEST_STEP("Create a pair of TCP sockets on IUT (@b iut_s) and Tester "
              "(@b tst_s).");
    iut_s = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr),
                       RPC_SOCK_STREAM, RPC_PROTO_DEF);
    tst_s = rpc_socket(pco_tst, rpc_socket_domain_by_addr(iut_addr),
                       RPC_SOCK_STREAM, RPC_PROTO_DEF);

    TEST_STEP("Bind the IUT socket to @p iut_addr, call @b listen() "
              "on it.");
    rpc_bind(pco_iut, iut_s, iut_addr);
    rpc_listen(pco_iut, iut_s, SOCKTS_BACKLOG_DEF);

    rpc_getrlimit(pco_iut, RPC_RLIMIT_NOFILE, &rlim_iut);
    rpc_getrlimit(pco_tst, RPC_RLIMIT_NOFILE, &rlim_tst);

    TEST_STEP("Set @c RLIMIT_NOFILE to @c MAX_SOCKS - @c 1 on IUT "
              "and Tester.");

    rlim_new.rlim_cur = rlim_new.rlim_max = MAX_SOCKS - 1;
    rpc_setrlimit(pco_iut, RPC_RLIMIT_NOFILE, &rlim_new);
    rpc_setrlimit(pco_tst, RPC_RLIMIT_NOFILE, &rlim_new);

    TEST_STEP("If @p conn_stack is @c TRUE, try to create @c MAX_SOCKS "
              "TCP sockets on Tester, otherwise try to do it on IUT.");
    TEST_STEP("Check that eventually creating the next socket fails with "
              "@c EMFILE.");
    pco_socks = (conn_stack) ? pco_tst : pco_iut;
    do {
        RPC_AWAIT_IUT_ERROR(pco_socks);
        socks[sock_num] = rpc_socket(pco_socks,
                                     rpc_socket_domain_by_addr(iut_addr),
                                     RPC_SOCK_STREAM, RPC_PROTO_DEF);
        if (socks[sock_num] < 0)
        {
            CHECK_RPC_ERRNO(pco_socks, RPC_EMFILE,
                            "When there is no available "
                            "file descriptors for the process socket() "
                            "returns -1, but");
            rlimit_met = TRUE;
            break;
        }
        sock_num++;
    } while (sock_num < MAX_SOCKS);

    if (!rlimit_met)
        TEST_VERDICT("More sockets were opened than RLIMIT_NOFILE allows");

    TEST_STEP("Close @p sock_close_num sockets randomly chosen from the "
              "sockets created successfully on the previous step.");
    while (sock_close_num > 0)
    {
        do {
            i = rand_range(0, sock_num - 1);
        } while(socks[i] == -1);
        RPC_CLOSE(pco_socks, socks[i]);
        sock_close_num--;
    }

    TEST_STEP("Create a CSAP to capture packets received over "
              "loopback interface.");
    CHECK_RC(rcf_ta_create_session(pco_iut->ta, &sid));
    CHECK_RC(tapi_tcp_ip_eth_csap_create(
                                     pco_iut->ta, sid, iut_if->if_name,
                                     TAD_ETH_RECV_HOST |
                                     TAD_ETH_RECV_NO_PROMISC,
                                     NULL, NULL, iut_addr->sa_family,
                                     te_sockaddr_get_netaddr(iut_addr),
                                     NULL,
                                     te_sockaddr_get_port(iut_addr), -1,
                                     &csap));

    CHECK_RC(tapi_tad_trrecv_start(pco_iut->ta, sid, csap, NULL,
                                   TAD_TIMEOUT_INF,
                                   0,
                                   RCF_TRRECV_PACKETS));

    TEST_STEP("@b connect() @b tst_s to @p iut_addr.");
    RPC_AWAIT_IUT_ERROR(pco_tst);
    rc = rpc_connect(pco_tst, tst_s, iut_addr);
    if (rc < 0)
    {
        TEST_VERDICT("connect() failed with %s",
                     errno_rpc2str(RPC_ERRNO(pco_tst)));
    }

    TEST_STEP("@b accept() connection on @b iut_s.");
    RPC_AWAIT_IUT_ERROR(pco_iut);
    acc_s = rpc_accept(pco_iut, iut_s, NULL, NULL);
    if (acc_s < 0)
    {
        TEST_VERDICT("accept() failed with %s",
                     errno_rpc2str(RPC_ERRNO(pco_iut)));
    }

    TEST_STEP("Send data in both directions over the established "
              "connection. Try to capture packets with CSAP, check "
              "whether it sees any packets.");

    CHECK_RC(sockts_test_send(pco_iut, acc_s, pco_tst, tst_s, NULL, NULL,
                              RPC_PF_UNSPEC, FALSE, ""));
    /*
     * Do not exit silently if getting IUT readability within
     * sockts_test_send() function fails.
     * Print verdict about it.
     */
    RPC_AWAIT_ERROR(pco_iut);
    CHECK_RC(sockts_test_send(pco_tst, tst_s, pco_iut, acc_s, NULL, NULL,
                              RPC_PF_UNSPEC, FALSE, ""));

    if (tapi_tad_trrecv_stop(pco_iut->ta, sid, csap, NULL,
                             &received_packets_number))
        TEST_FAIL("Failed to receive packets");
    RING("Received packets number %d", received_packets_number);
    if (received_packets_number > 0)
        RING_VERDICT("CSAP registered data traffic on the loopback "
                     "interface");

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_iut, acc_s);

    for (i = 0; i < sock_num; i++)
        CLEANUP_RPC_CLOSE(pco_socks, socks[i]);

    if (csap != CSAP_INVALID_HANDLE &&
        tapi_tad_csap_destroy(pco_iut->ta, sid, csap))
        ERROR("Failed to destroy CSAP");

    if (rlim_iut.rlim_cur != 0)
        rpc_setrlimit(pco_iut, RPC_RLIMIT_NOFILE, &rlim_iut);
    if (rlim_tst.rlim_cur != 0)
        rpc_setrlimit(pco_tst, RPC_RLIMIT_NOFILE, &rlim_tst);

    TEST_END;
}
