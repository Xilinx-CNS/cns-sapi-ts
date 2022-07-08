/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * I/O Multiplexing
 *
 * $Id$
 */

/** @page iomux-udp_zero_dgram Zero-length packet handling by iomux functions
 *
 * @objective Check I/O multiplexing functions behaviour when zero-length
 *            packet is received.
 *
 * @type conformance, compatibility
 *
 * @param pco_iut       PCO on IUT
 * @param iut_addr      Address/port to be used to connect to @p pco_iut
 * @param pco_tst       Auxiliary PCO
 * @param tst_addr      Address/port to be used to connect to @p pco_tst
 * @param iomux         Type of I/O Multiplexing function
 *                      (@b select(), @b pselect(), @b poll())
 * @param iomux_before  Call iomux function before or after @b send() call.
 * @param timeout       Timeout for iomux function
 *
 * @par Scenario:
 * -# Create @c SOCK_DGRAM connection between @p pco_iut and
 *    @p pco_tst by means of @c GEN_CONNECTION and return socket
 *    descriptors for both client and server side.
 * -# Call @b iomux function with @p timeout waiting for read event if
 *    @p iomux_before is @c TRUE.
 * -# Send zero-lenght datagram to @p iut_s.
 * -# Call @b iomux function with @p timeout waiting for read event if
 *    @p iomux_before is @c FALSE.
 * -# Check that @b iomux function reports read event.
 *
 * @author Yurij Plotnikov <Yurij.Plotnikov@oktetlabs.ru>
 */

#define TE_TEST_NAME "iomux/udp_zero_dgram"
#include "sockapi-test.h"
#include "iomux.h"

int
main(int argc, char *argv[])
{
    iomux_call_type         iomux;

    rcf_rpc_server         *pco_iut = NULL;
    rcf_rpc_server         *pco_tst = NULL;

    const struct sockaddr  *iut_addr = NULL;
    const struct sockaddr  *tst_addr = NULL;

    int                     iut_s = -1;
    int                     tst_s = -1;

    iomux_evt_fd            event;
    int                     timeout;
    tarpc_timeval           tv;
    te_bool                 iomux_before;

    /* Preambule */
    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_IOMUX_FUNC(iomux);
    TEST_GET_INT_PARAM(timeout);
    TEST_GET_BOOL_PARAM(iomux_before);

    GEN_CONNECTION_WILD(pco_iut, pco_tst, RPC_SOCK_DGRAM, RPC_PROTO_DEF,
                        iut_addr, tst_addr, &iut_s, &tst_s, TRUE);

    memset(&event, 0, sizeof(event));
    memset(&tv, 0, sizeof(tv));
    tv.tv_sec = timeout;
    tv.tv_usec = 0;
    event.fd = iut_s;
    event.events = EVT_RD;
    if (iomux_before)
    {
        pco_iut->op = RCF_RPC_CALL;
        iomux_call(iomux, pco_iut, &event, 1, &tv);
    }

    RPC_SEND(rc, pco_tst, tst_s, "", 0, 0);
    TAPI_WAIT_NETWORK;

    if (iomux_before)
        pco_iut->op = RCF_RPC_WAIT;
    if (timeout == 0)
        rc = iomux_call(iomux, pco_iut, &event, 1, NULL);
    else
    {
        rc = iomux_call(iomux, pco_iut, &event, 1, &tv);
    }

    if (rc != 1)
        TEST_VERDICT("iomux call doesn't detect read event");

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    TEST_END;
}
