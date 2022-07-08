/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Network interface related tests
 */

/** @page ifcfg-if_bind_on_down_if Bind socket to an address of a down interface
 *
 * @objective Bind a socket to an address of a down interface, check the
 *            socket API trying to send some data or establish TCP connection.
 *            Then check that socket works correctly when the interface is up.
 *
 * @type conformance
 *
 * @param pco_iut       PCO on @p IUT
 * @param pco_tst       PCO on @p TESTER
 * @param iut_if        Network interface name on @p IUT to interact with
 *                      @p TESTER
 * @param iut_addr      Network address assigned to @p iut_if
 * @param sock_type     @c SOCK_DGRAM or @c SOCK_STREAM
 * @param connect       If @c TRUE, actively connect IUT socket in case of
 *                      TCP or call @c connect() for UDP socket.
 *
 * @par Test sequence:
 *
 * @author Oleg Kravtsov <Oleg.Kravtsov@oktetlabs.ru>
 * @author Igor Vasiliev <Igor.Vasiliev@oktetlabs.ru>
 * @author Andrey Dmitrov <Andrey.Dmitrov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "ifcfg/if_bind_on_down_if"

#include "sockapi-test.h"
#include "tapi_cfg_base.h"
#include "tapi_cfg.h"
#include "iomux.h"

int
main(int argc, char *argv[])
{
    rpc_socket_type             sock_type;
    const struct if_nameindex  *iut_if = NULL;
    const struct if_nameindex  *tst_if = NULL;

    rcf_rpc_server        *pco_iut = NULL;
    rcf_rpc_server        *pco_tst = NULL;
    rcf_rpc_server        *pco_srv = NULL;
    rcf_rpc_server        *pco_cln = NULL;
    rcf_rpc_server        *pco_iut_thread = NULL;
    const struct sockaddr *iut_addr = NULL;
    const struct sockaddr *tst_addr = NULL;
    const struct sockaddr *srv_addr = NULL;

    int                    iut_s = -1;
    int                    tst_s = -1;
    int                    srv_s = -1;
    int                    cln_s = -1;
    int                    acc_s = -1;

    void                  *rx_buf = NULL;
    void                  *tx_buf = NULL;
    size_t                 rx_buflen = 1024;
    size_t                 tx_buflen;

    te_bool                connect = FALSE;

    iomux_evt              revt = 0;

    TEST_START;
    TEST_GET_SOCK_TYPE(sock_type);
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_IF(iut_if);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_BOOL_PARAM(connect);
    TEST_GET_IF(tst_if);

    rx_buf = te_make_buf_by_len(rx_buflen);
    tx_buf = te_make_buf(1, rx_buflen, &tx_buflen);

    CHECK_RC(rcf_rpc_server_thread_create(pco_iut, "pco_iut_thread",
                                          &pco_iut_thread));

    TEST_STEP("Create socket of @p sock_type type.");
    iut_s = rpc_socket(pco_iut, RPC_AF_INET, sock_type, RPC_PROTO_DEF);
    tst_s = rpc_socket(pco_tst, RPC_AF_INET, sock_type, RPC_PROTO_DEF);

    /* Resolve ARPs before interface goes down */
    tapi_rpc_provoke_arp_resolution(pco_iut, tst_addr);

    TEST_STEP("Put IUT interface down.");
    CHECK_RC(tapi_cfg_base_if_down(pco_iut->ta, iut_if->if_name));
    CFG_WAIT_CHANGES;

    TEST_STEP("Bind the socket to IP address which belongs to the interface.");
    rpc_bind(pco_iut, iut_s, iut_addr);
    rpc_bind(pco_tst, tst_s, tst_addr);

    if (sock_type == RPC_SOCK_DGRAM)
    {
        TEST_STEP("If @p sock_type is UDP and @p connect is @c TRUE - connect the "
                  "socket.");
        if (connect)
            rpc_connect(pco_iut, iut_s, tst_addr);
        rpc_connect(pco_tst, tst_s, iut_addr);
    }

    if (sock_type == RPC_SOCK_STREAM)
    {
        TEST_STEP("If TCP:");
        if (connect == FALSE)
        {
            pco_srv = pco_iut;
            srv_s = iut_s;
            srv_addr = iut_addr;
            pco_cln = pco_tst;
            cln_s = tst_s;
        }
        else
        {
            pco_srv = pco_tst;
            srv_s = tst_s;
            srv_addr = tst_addr;
            pco_cln = pco_iut;
            cln_s = iut_s;
        }
        iut_s = -1;
        tst_s = -1;

        TEST_SUBSTEP("Create listener socket on tester if @p connect is @c TRUE, else "
                     "listen on the IUT socket.");
        rpc_listen(pco_srv, srv_s, SOCKTS_BACKLOG_DEF);

        TEST_SUBSTEP("Connect from the peer or IUT in dependence on @p connect.");
        pco_cln->op = RCF_RPC_CALL;
        rpc_connect(pco_cln, cln_s, srv_addr);

        TEST_SUBSTEP("Check with iomux that no connections come to the listener.");
        rc = iomux_call_default_simple(pco_srv, srv_s, EVT_RD, &revt,
                                       TAPI_WAIT_NETWORK_DELAY);
        if (rc != 0)
            TEST_VERDICT("iomux_call() returned an event");
    }
    else if (sock_type == RPC_SOCK_DGRAM)
    {
        TEST_STEP("If UDP:");
        TEST_SUBSTEP("Transmit data from IUT.");
        if (connect)
            rc = rpc_send(pco_iut, iut_s, tx_buf, tx_buflen, 0);
        else
            rc = rpc_sendto(pco_iut, iut_s, tx_buf, tx_buflen, 0, tst_addr);
        if (rc != (int)tx_buflen)
            TEST_FAIL("Unexpectedly sendto() returns %d instead of %d",
                      rc, tx_buflen);

        TEST_SUBSTEP("Check with iomux that tester socket does not receive data.");
        rc = iomux_call_default_simple(pco_tst, tst_s, EVT_RD, &revt,
                                       TAPI_WAIT_NETWORK_DELAY);
        if (rc != 0)
            TEST_VERDICT("iomux_call() returned an event");

        TEST_SUBSTEP("Transmit data from tester.");
        rpc_send(pco_tst, tst_s, tx_buf, tx_buflen, 0);

        TEST_SUBSTEP("Check with iomux that IUT socket does not receive data.");
        rc = iomux_call_default_simple(pco_iut, iut_s, EVT_RD, &revt,
                                       TAPI_WAIT_NETWORK_DELAY);
        if (rc != 0)
            TEST_VERDICT("iomux_call() returned an event");
    }

    TEST_STEP("Get up IUT interface.");
    CHECK_RC(tapi_cfg_base_if_up(pco_iut->ta, iut_if->if_name));
    CHECK_RC(sockts_wait_for_if_up(pco_iut_thread, iut_if->if_name));

    TEST_STEP("For TCP: finish the connection establishing.");
    TEST_STEP("Check data transmission in both directions.");
    if (sock_type == RPC_SOCK_DGRAM)
    {
        CFG_WAIT_CHANGES;

        if (connect)
            rpc_send(pco_iut, iut_s, tx_buf, tx_buflen, 0);
        else
            rpc_sendto(pco_iut, iut_s, tx_buf, tx_buflen, 0, tst_addr);
        rc = rpc_read(pco_tst, tst_s, rx_buf, rx_buflen);
        SOCKTS_CHECK_RECV(pco_tst, tx_buf, rx_buf, tx_buflen, rc);

        rpc_send(pco_tst, tst_s, tx_buf, tx_buflen, 0);
        rc = rpc_read(pco_iut, iut_s, rx_buf, rx_buflen);
        SOCKTS_CHECK_RECV(pco_iut, tx_buf, rx_buf, tx_buflen, rc);
    }
    else
    {
        rpc_connect(pco_cln, cln_s, srv_addr);
        acc_s = rpc_accept(pco_srv, srv_s, NULL, NULL);
        sockts_test_connection(pco_srv, acc_s, pco_cln, cln_s);
    }

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_srv, srv_s);
    CLEANUP_RPC_CLOSE(pco_srv, acc_s);
    CLEANUP_RPC_CLOSE(pco_cln, cln_s);
    CLEANUP_CHECK_RC(rcf_rpc_server_destroy(pco_iut_thread));

    TEST_END;
}
