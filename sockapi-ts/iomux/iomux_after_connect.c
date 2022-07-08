/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * I/O Multiplexing
 *
 * $Id$
 */

/** @page iomux-iomux_after_connect Check I/O multiplexer during non-blocking TCP connect() call
 *
 * @objective Check behaviour of iomux function when it is called during and
 *            after connect() on a non-blocking TCP socket
 *
 * @type conformance, compatibility
 *
 * @param pco_iut               PCO with IUT
 * @param pco_tst               PCO with Tester
 * @param iut_addr              Network address on IUT
 * @param tst_addr              Network address on Tester
 * @param tst_alien_addr        Alien network address on Tester
 * @param iomux                 Type of I/O Multiplexing function
 * @param connection_result     Type of connection result
 *
 * @par Scenario:
 *
 * @author Oleg Sadakov <Oleg.Sadakov@oktetlabs.ru>
 */

#define TE_TEST_NAME "iomux/iomux_after_connect"

#include "sockapi-test.h"
#include "iomux.h"
#include "tapi_route_gw.h"

/** SYN retransmission number */
#define SYN_RETRIES_NUM 2

/** Timeout of iomux() call in seconds */
#define IOMUX_TIMEOUT 1

/** Check events number and value returned from iomux call */
#define CHECK_IOMUX_RESULTS()                                           \
    do {                                                                \
        if (cnt != expected_cnt || event.revents != expected_events)    \
        {                                                               \
            ERROR("Number of events: %d (expected: %d), "               \
                  "events: %s (expected: %s)",                          \
                  cnt, expected_cnt,                                    \
                  iomux_event_rpc2str(event.revents),                   \
                  iomux_event_rpc2str(expected_events));                \
            TEST_VERDICT("Unexpected iomux events");                    \
        }                                                               \
    } while (0)

int
main(int argc, char *argv[])
{
    TAPI_DECLARE_ROUTE_GATEWAY_PARAMS;
    tapi_route_gateway gw;

    const struct sockaddr      *tst_alien_addr = NULL;

    iomux_call_type             iomux = IC_UNKNOWN;
    sockts_conn_problem_t       connection_result;

    int                         iut_s = -1;
    int                         tst_s = -1;
    int                         fdflags;
    te_bool                     expected = FALSE;
    int                         cnt;
    iomux_evt_fd                event;
    int                         expected_cnt = 0;
    uint16_t                    expected_events = 0;
    tarpc_timeval               timeout = {
        .tv_sec = IOMUX_TIMEOUT,
        .tv_usec = 0
    };

    TEST_START;
    TAPI_GET_ROUTE_GATEWAY_PARAMS;
    TEST_GET_ADDR(pco_tst, tst_alien_addr);
    TEST_GET_IOMUX_FUNC(iomux);
    TEST_GET_ENUM_PARAM(connection_result,
                        SOCKTS_CONN_PROBLEM_MAPPING_LIST);

    /**
     * -# Set small TCP SYN retries number on IUT to decrease
     *    TCP connection timeout if the value @b connection_result is equal
     *    @c SOCKTS_CONN_TIMEOUT.
     */
    if (connection_result == SOCKTS_CONN_TIMEOUT)
    {
        CHECK_RC(tapi_cfg_sys_ns_set_int(pco_iut->ta, SYN_RETRIES_NUM, NULL,
                                         "net/ipv4/tcp_syn_retries"));
        rcf_rpc_server_restart(pco_iut);
    }

    TAPI_INIT_ROUTE_GATEWAY(gw);

    /** -# Configure gateway. */
    tapi_route_gateway_configure(&gw);

    /**
     * -# Break network connectivity from Tester to gateway so that packets
     *    from Tester will not reach IUT
     */
    tapi_route_gateway_break_tst_gw(&gw);
    CFG_WAIT_CHANGES;

    /**
     * -# Create a listening socket on Tester if @b connection_result
     *    is equal @c SOCKTS_CONN_OK.
     */
    if (connection_result == SOCKTS_CONN_OK)
        tst_s = rpc_stream_server(pco_tst, RPC_PROTO_DEF, FALSE, tst_addr);

    /** -# Create a non-blocking client socket on IUT. */
    iut_s = rpc_stream_client(pco_iut, rpc_socket_domain_by_addr(iut_addr),
                              RPC_PROTO_DEF, iut_addr);
    fdflags = rpc_fcntl(pco_iut, iut_s, RPC_F_GETFL, RPC_O_NONBLOCK);
    fdflags |= RPC_O_NONBLOCK;
    fdflags = rpc_fcntl(pco_iut, iut_s, RPC_F_SETFL, fdflags);

    /** -# Start connection from IUT to Tester. */
    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_connect(pco_iut, iut_s, tst_addr);
    if ((rc != -1) || (RPC_ERRNO(pco_iut) != RPC_EINPROGRESS))
    {
        TEST_VERDICT("connect() unexpectedly %s with rc = %d and errno %r",
                     rc == 0 ? "passed" : "failed", rc, RPC_ERRNO(pco_iut));
    }
    TAPI_WAIT_NETWORK;

    /** -# Check that iomux call didn't receive any events. */
    event.fd = iut_s;
    event.events = EVT_RDWR;
    event.revents = 0;
    cnt = iomux_call(iomux, pco_iut, &event, 1, &timeout);
    CHECK_IOMUX_RESULTS();

    /** -# Check that connection isn't established. */
    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_connect(pco_iut, iut_s, tst_addr);
    if ((rc != -1) || (RPC_ERRNO(pco_iut) != RPC_EALREADY))
    {
        TEST_VERDICT("connect() unexpectedly %s with rc = %d and errno %r",
                     rc == 0 ? "passed" : "failed", rc, RPC_ERRNO(pco_iut));
    }

    /** -# Check that iomux call didn't receive any events. */
    cnt = iomux_call(iomux, pco_iut, &event, 1, &timeout);
    CHECK_IOMUX_RESULTS();

    /**
     * -# Restore network connectivity from Tester to gateway in case when
     *    @b connection_result is equal @c SOCKTS_CONN_OK or
     *    @c SOCKTS_CONN_REFUSED.
     */
    if (connection_result != SOCKTS_CONN_TIMEOUT)
    {
        tapi_route_gateway_repair_tst_gw(&gw);
        CFG_WAIT_CHANGES;
    }

    /**
     * -# Check that blocking iomux call received one event with value
     *    depending on @b connection_result
     */
    cnt = iomux_call(iomux, pco_iut, &event, 1, NULL);
    if (connection_result == SOCKTS_CONN_OK)
    {
        expected_cnt = 1;
        expected_events = EVT_WR;
    }
    else
    {
        if (iomux == IC_SELECT || iomux == IC_PSELECT)
        {
            expected_cnt = 2;
            expected_events = EVT_RD | EVT_WR;
        }
        else
        {
            expected_cnt = 1;
            expected_events = EVT_RD | EVT_WR | EVT_EXC | EVT_ERR | EVT_HUP;

            /*
             * CentOS with kernel 2.6.32 doesn't generate event EVT_WR.
             */
            if (event.revents != expected_events)
            {
                expected_events &= ~EVT_WR;
                if (event.revents == expected_events)
                {
                    ERROR_VERDICT("Events: %s",
                                  iomux_event_rpc2str(expected_events));
                }
            }
        }
    }
    CHECK_IOMUX_RESULTS();

    /** -# Check the result of @b connect() and returned @b errno. */
    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_connect(pco_iut, iut_s, tst_addr);
    switch (connection_result)
    {
        case SOCKTS_CONN_OK:
            expected = (rc == 0);
            break;

        case SOCKTS_CONN_REFUSED:
            expected = (rc == -1) &&
                    (RPC_ERRNO(pco_iut) == RPC_ECONNREFUSED);
            break;

        case SOCKTS_CONN_TIMEOUT:
            expected = (rc == -1) && (RPC_ERRNO(pco_iut) == RPC_ETIMEDOUT);
            break;

        default:
            TEST_VERDICT("Unknown connection result");
    }
    if (!expected)
    {
        TEST_VERDICT("connect() unexpectedly %s with rc = %d and errno %r",
                     rc == 0 ? "passed" : "failed", rc, RPC_ERRNO(pco_iut));
    }

    /** -# Check iomux events and return code. */
    cnt = iomux_call(iomux, pco_iut, &event, 1, &timeout);
    if (connection_result == SOCKTS_CONN_OK)
    {
        expected_cnt = 1;
        expected_events = EVT_WR;
    }
    else
    {
        if (iomux == IC_SELECT || iomux == IC_PSELECT)
        {
            expected_cnt = 2;
            expected_events = EVT_RD | EVT_WR;
        }
        else
        {
            expected_cnt = 1;
            expected_events = EVT_WR | EVT_EXC | EVT_HUP;
        }
    }
    CHECK_IOMUX_RESULTS();

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    TEST_END;

}
