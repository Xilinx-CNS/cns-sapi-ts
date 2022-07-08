/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * I/O Multiplexing
 *
 * $Id$
 */

/** @page iomux-nb_accept_read Non-blocking accept and read with iomux
 *
 * @objective Repeatedly: (non-blocking) accept connections, add accepted
 *            socket to the iomux set, receive data. Wait for events using
 *            an iomux.
 *
 * @param type  Iomux function type.
 *
 * @par Scenario:
 *
 * @author Andrey Dmitrov <Andrey.Dmitrov@oktetlabs.ru>
 */

#define TE_TEST_NAME "iomux/nb_accept_read"

#include "sockapi-test.h"
#include "iomux.h"

/* The main loop iterations number, equal to connections number. */
#define CONNECTIONS_NUM 10

/* Timeout to use in iomux. */
#define TIMEOUT 1000

int
main(int argc, char *argv[])
{
    rcf_rpc_server             *pco_iut = NULL;
    rcf_rpc_server             *pco_tst = NULL;
    const struct sockaddr      *iut_addr = NULL;
    const struct sockaddr      *tst_addr = NULL;
    const struct if_nameindex  *tst_if = NULL;
    const struct if_nameindex  *iut_if = NULL;
    tapi_iomux_type             type;
    tapi_iomux_handle          *iomux = NULL;

    tapi_iomux_evt_fd *evts = NULL;
    int domain;
    int iut_s = -1;
    int acc_s[CONNECTIONS_NUM] = {};
    int tst_s[CONNECTIONS_NUM] = {};
    int i;

    char *sndbuf = NULL;
    char *rcvbuf = NULL;
    size_t len;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_IF(tst_if);
    TEST_GET_IF(iut_if);
    TEST_GET_IOMUX_FUNC(type);

    sndbuf = sockts_make_buf_stream(&len);
    rcvbuf = te_make_buf_by_len(len);

    domain = rpc_socket_domain_by_addr(iut_addr);

    TEST_STEP("Create a listener socket.");
    iut_s = rpc_socket(pco_iut, domain, RPC_SOCK_STREAM, RPC_PROTO_DEF);
    rpc_bind(pco_iut, iut_s, iut_addr);
    rpc_listen(pco_iut, iut_s, SOCKTS_BACKLOG_DEF);

    TEST_STEP("Set non-blocking mode on the socket.");
    rpc_fcntl(pco_iut, iut_s, RPC_F_SETFL, RPC_O_NONBLOCK);

    TEST_STEP("Check @c accept() call fails with @c EAGAIN.");
    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_accept(pco_iut, iut_s, NULL, NULL);
    if (rc != -1 || RPC_ERRNO(pco_iut) != RPC_EAGAIN)
        TEST_VERDICT("Non-blocking accept had to fail with EAGAIN");

    memset(tst_s, -1, sizeof(tst_s));

    TEST_STEP("Create an iomux set and add the listener to it.");
    iomux = sockts_iomux_create(pco_iut, type);
    tapi_iomux_add(iomux, iut_s, EVT_RD | EVT_WR | EVT_EXC);

    TEST_STEP("Repeat in the loop a few times:");
    for (i = 0; i < CONNECTIONS_NUM; i++)
    {
        TEST_SUBSTEP("Wait on the iomux for incoming events, check it is blocked.");
        pco_iut->op = RCF_RPC_CALL;
        tapi_iomux_call(iomux, TIMEOUT, &evts);
        SOCKTS_CALL_IS_BLOCKED(pco_iut, "The first iomux");

        TEST_SUBSTEP("Create socket on Tester and connect it to the listener.");
        tst_s[i] = rpc_socket(pco_tst, domain, RPC_SOCK_STREAM,
                              RPC_PROTO_DEF);
        rpc_connect(pco_tst, tst_s[i], iut_addr);

        TEST_SUBSTEP("Get @c IN event on the iomux.");
        rc = tapi_iomux_call(iomux, TIMEOUT, &evts);
        if (rc != 1)
            TEST_VERDICT("Unexpected events number %d instead of 1", rc);
        if (evts->revents != EVT_RD)
            TEST_VERDICT("Unexpected events %s instead of %s",
                         tapi_iomux_event_rpc2str(evts->revents),
                         tapi_iomux_event_rpc2str(EVT_RD));

        TEST_SUBSTEP("Accept the connection and add new socket to the iomux set.");
        acc_s[i] = rpc_accept(pco_iut, iut_s, NULL, NULL);
        tapi_iomux_add(iomux, acc_s[i], EVT_RD | EVT_EXC);

        TEST_SUBSTEP("Wait on the iomux for incoming events, check it is blocked.");
        pco_iut->op = RCF_RPC_CALL;
        tapi_iomux_call(iomux, TIMEOUT, &evts);
        SOCKTS_CALL_IS_BLOCKED(pco_iut, "The second iomux");

        TEST_SUBSTEP("Send a data packet from Tester.");
        rpc_send(pco_tst, tst_s[i], sndbuf, len, 0);

        TEST_SUBSTEP("Get @c IN event on the iomux and read data.");
        rc = tapi_iomux_call(iomux, TIMEOUT, &evts);
        if (rc != 1)
            TEST_VERDICT("Unexpected events number %d instead of 1", rc);
        if (evts->revents != EVT_RD)
            TEST_VERDICT("Unexpected events %s instead of %s",
                         tapi_iomux_event_rpc2str(evts->revents),
                         tapi_iomux_event_rpc2str(EVT_RD));
        rc = rpc_recv(pco_iut, acc_s[i], rcvbuf, len, 0);
        SOCKTS_CHECK_RECV(pco_iut, sndbuf, rcvbuf, len, rc);

        TEST_SUBSTEP("Send the data back to Tester.");
        rpc_send(pco_iut, acc_s[i], sndbuf, len, 0);
        rc = rpc_recv(pco_tst, tst_s[i], rcvbuf, len, 0);
        SOCKTS_CHECK_RECV(pco_tst, sndbuf, rcvbuf, len, rc);
    }

    TEST_STEP("Check @c accept() call fails with @c EAGAIN.");
    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_accept(pco_iut, iut_s, NULL, NULL);
    if (rc != -1 || RPC_ERRNO(pco_iut) != RPC_EAGAIN)
        TEST_VERDICT("Non-blocking accept had to fail with EAGAIN");

    tapi_iomux_del(iomux, iut_s);
    tapi_iomux_destroy(iomux);

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    for (i = 0; i < CONNECTIONS_NUM; i++)
    {
        CLEANUP_RPC_CLOSE(pco_iut, acc_s[i]);
        CLEANUP_RPC_CLOSE(pco_tst, tst_s[i]);
    }

    TEST_END;
}
