/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * I/O Multiplexing
 *
 * $Id$
 */

/** @page iomux-timeout_update Update of timeout argument
 *
 * @objective Check if @b select(), @b pselect() or @b poll()
 *            update timeout argument.
 *
 * @type Conformance, compatibility
 *
 * @requirement REQ-3, REQ-13
 *
 * @reference @ref STEVENS Section 6.3
 *
 * @param pco_iut   PCO with IUT
 * @param pco_tst   Auxiliary PCO
 * @param iut_addr  Address/port to be used to connect to @p pco_iut
 * @param tst_addr  Address/port to be used to connect to @p pco_tst
 * @param iomux     IO multiplexing function to be tested
 *
 * @note POSIX.1g specifies the @b const qualifier for @b timeout
 *       parameter. Current Linux systems modify the @b timeval
 *       structure.
 *
 * @par Scenario:
 * -# Create datagram socket @p iut_s on @p pco_iut;
 * -# Create datagram socket @p tst_s on @p pco_tst;
 * -# @b bind() socket @p iut_s to @p iut_addr address;
 * -# Call tested function to wait for @e read event on @b iut_s socket
 *    with 10 seconds timeout;
 * -# Sleep 1 second;
 * -# Send data from @p tst_s to @p iut_addr using @b sendto() function;
 * -# Wait for tested function completion, it must return @c 1 and
 *    @p iut_s socket must be marked as readable;
 * -# Check if value in @a timeout parameter was not modified and log
 *    result.
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 * @author Andrew Rybchenko <Andrew.Rybchenko@oktetlabs.ru>
 */

#define TE_TEST_NAME "iomux/timeout_update"

#include "sockapi-test.h"
#include "iomux.h"

#define TESTED_CALL \
    do {                                                        \
        switch (iomux)                                          \
        {                                                       \
            case IC_SELECT:                                     \
                rc = rpc_select(pco_iut, iut_s + 1, readfds,    \
                                RPC_NULL, RPC_NULL, &timeout);  \
                break;                                          \
                                                                \
            case IC_PSELECT:                                    \
                rc = rpc_pselect(pco_iut, iut_s + 1, readfds,   \
                                 RPC_NULL, RPC_NULL,            \
                                 &ts_timeout, RPC_NULL);        \
                break;                                          \
                                                                \
            case IC_PPOLL:                                      \
                rc = rpc_ppoll(pco_iut, pollfd, 1,              \
                               &ts_timeout, RPC_NULL);          \
                break;                                          \
                                                                \
            default:                                            \
                TEST_FAIL("Incorrect function was specified "   \
                          "to the test");                       \
                break;                                          \
        }                                                       \
    } while (0)

int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst = NULL;

    int iut_s = -1;
    int tst_s = -1;

    const struct sockaddr *iut_addr = NULL;
    const struct sockaddr *tst_addr = NULL;

    tarpc_timeval   timeout, timeout_cp;
    tarpc_timespec  ts_timeout, ts_timeout_cp;
    unsigned char   buffer[1];

    rpc_fd_set_p        readfds = RPC_NULL;
    struct rpc_pollfd   pollfd[1];
    iomux_call_type     iomux;

    long int    sec;
    long int    nsec;
    long int    cp_sec;
    long int    cp_nsec;

    struct timespec ts_start, ts_stop;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_IOMUX_FUNC(iomux);

    iut_s = rpc_create_and_bind_socket(pco_iut, RPC_SOCK_DGRAM,
                                       RPC_PROTO_DEF, TRUE, FALSE,
                                       iut_addr);
    tst_s = rpc_socket(pco_tst, rpc_socket_domain_by_addr(tst_addr),
                       RPC_SOCK_DGRAM, RPC_PROTO_DEF);

    if (iomux == IC_SELECT || iomux == IC_PSELECT)
    {
        readfds = rpc_fd_set_new(pco_iut);
        rpc_do_fd_zero(pco_iut, readfds);
        rpc_do_fd_set(pco_iut, iut_s, readfds);
    }
    else
    {
        memset(pollfd, 0, sizeof(pollfd));
        pollfd->fd = iut_s;
        pollfd->events = RPC_POLLIN;
    }

    if (iomux == IC_SELECT)
    {
        timeout.tv_usec = 0;
        timeout.tv_sec = rand_range(10, 20);
        timeout_cp = timeout;
    }
    else
    {
        ts_timeout.tv_nsec = 0;
        ts_timeout.tv_sec = rand_range(10, 20);
        ts_timeout_cp = ts_timeout;
    }

    pco_iut->op = RCF_RPC_CALL;
    TESTED_CALL;

    CHECK_RC(clock_gettime(CLOCK_MONOTONIC, &ts_start));
    SLEEP(1);
    CHECK_RC(clock_gettime(CLOCK_MONOTONIC, &ts_stop));

    RPC_SENDTO(rc, pco_tst, tst_s, buffer, sizeof(buffer), 0, iut_addr);
    pco_iut->op = RCF_RPC_WAIT;
    RPC_AWAIT_IUT_ERROR(pco_iut);
    TESTED_CALL;

    if (rc != 1)
    {
        TEST_FAIL("%s() function called on IUT returned %d instead of 1",
                  iomux_call_en2str(iomux), rc);
    }

    if (((iomux == IC_SELECT || iomux == IC_PSELECT) &&
         !rpc_do_fd_isset(pco_iut, iut_s, readfds)) ||
        (iomux == IC_PPOLL && !(pollfd->revents & RPC_POLLIN)))
        TEST_FAIL("%s() didn't return iut_s socket as ready for reading",
                  iomux_call_en2str(iomux));

    if (iomux == IC_SELECT)
    {
        sec = timeout.tv_sec;
        nsec = timeout.tv_usec * 1000;
        cp_sec = timeout_cp.tv_sec;
        cp_nsec = timeout_cp.tv_usec * 1000;
    }
    else
    {
        sec = ts_timeout.tv_sec;
        nsec = ts_timeout.tv_nsec;
        cp_sec = ts_timeout_cp.tv_sec;
        cp_nsec = ts_timeout_cp.tv_nsec;
    }

    if (sec != cp_sec || nsec != cp_nsec)
    {
        double ref_time = ts_stop.tv_sec - ts_start.tv_sec +
            (double)(ts_stop.tv_nsec - ts_start.tv_nsec) / 1000000000;
        /*
         * We allow a deviation of iomux_time in the range of 0.5 seconds,
         * due to timeout inaccuracy esp. in case of spinning
         */
        double min_time = ref_time - 0.5;
        double max_time = ref_time + 0.5;

        double iomux_time = cp_sec - sec +
            (double)(cp_nsec - nsec) / 1000000000;

        if (min_time < iomux_time && iomux_time < max_time)
        {
            RING("The iomux_time %.1fs is in the acceptable range "
                 "%.1fs..%.1fs", iomux_time, min_time, max_time);
            TEST_VERDICT("Timeout parameter was modified "
                         "by %s() function",
                         iomux_call_en2str(iomux));
        }
        else
        {
            WARN("The iomux_time %.1fs is out of the acceptable range "
                 "%.1fs..%.1fs", iomux_time, min_time, max_time);
            TEST_VERDICT("Timeout parameter was incorrectly modified "
                         "by %s() function", iomux_call_en2str(iomux));
        }
    }

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    if (iomux == IC_SELECT || iomux == IC_PSELECT)
        rpc_fd_set_delete(pco_iut, readfds);

    TEST_END;
}
