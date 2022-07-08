/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Bad Parameters and Boundary Values
 *
 * $Id$
 */

/** @page iomux-notconn Using iomux() function with not connected socket
 *
 * @objective Check that @b iomux() function does not mark not connected
 *            socket as readable or writable.
 *
 * @type conformance, robustness
 *
 * @reference @ref STEVENS, section 6.10
 *
 * @param domain    Domain used for the test (@c PF_INET, or smth.)
 * @param pco_iut   PCO on IUT
 * @param evt       Event we are interested in
 * @param sock_type Type of socket on @p pco_iut
 * @param bound     If value is @c TRUE @b bind() socket to @p iut_addr
 *                  address
 * @param iomux     Type of I/O Multiplexing function
 *
 * @par Scenario:
 * -# Create @p iut_s socket from @p domain domain of type @c sock_type
 *    on @p pco_iut;
 * -# If @p bound is @c TRUE @b bind() @p iut_s socket to @p iut_addr.
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Prepare @c iomux_evt_fd structure as follows:
 *        - @a fd      - @p iut_s;
 *        - @a events  - @p evt;
 *        - @a revents - @c 0xffff.
 *        .
 * -# Call @b iomux() with prepared structure specifying some @p timeout;
 * -# If @p sock_type is @c SOCK_DGRAM and @p evt is @c EVT_WR check that
 *    functions return @c 1 and sets @c EVT_WR to @a revents.
 * -# If @p sock_type is @c SOCK_STREAM and @p iomux is not @b poll() check
 *    that it returns @c 1 and sets @p evt to @a revents.
 * -# Check that the function returns @c 0 and its duration is @p timeout
 *    milliseconds. See @ref iomux-notconn "note 1";
 * -# Check that @a revents field of the structure is updated to @c 0;
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Close @p iut_s socket.
 *
 * @note
 * -# @anchor iomux-notconn_1
 *    For @c SOCK_STREAM sockets on Linux the function returns @c 1 and
 *    always sets @c EVT_HUP and @c EVT_EXC to @a revents field.
 *    Additionally if @c EVT_WR is set in @a events, then this bit is also
 *    set in @a revents.
 *
 * @author Oleg Kravtsov <Oleg.Kravtsov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "iomux/notconn"

#include "sockapi-test.h"
#include "iomux.h"


int
main(int argc, char *argv[])
{
    rcf_rpc_server       *pco_iut = NULL;
    const char           *evt;
    rpc_socket_type       sock_type;
    iomux_call_type       iomux;
    rpc_socket_domain     domain;
    
    const struct sockaddr *iut_addr = NULL;
    
    int                   iut_s = -1;
    tarpc_timeval         timeout;

    iomux_evt_fd          fds;
    te_bool               bound;

    TEST_START;

    TEST_GET_PCO(pco_iut);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_SOCK_TYPE(sock_type);
    TEST_GET_STRING_PARAM(evt);
    TEST_GET_DOMAIN(domain);
    TEST_GET_IOMUX_FUNC(iomux);
    TEST_GET_BOOL_PARAM(bound);

    if (bound)
        iut_s = rpc_socket(pco_iut, domain, sock_type, RPC_PROTO_DEF);
    else
        iut_s = rpc_create_and_bind_socket(pco_iut, sock_type,
                                           RPC_PROTO_DEF, TRUE, FALSE,
                                           iut_addr);

    timeout.tv_sec = 0;
    timeout.tv_usec = rand_range(0, 500000);
    
    if (strcmp(evt, "EVT_RD") == 0)
        fds.events = EVT_RD;
    else if (strcmp(evt, "EVT_WR") == 0)
        fds.events = EVT_WR;
    else
        TEST_FAIL("Unexpected event - %s", evt);
    
    fds.fd = iut_s;
    fds.revents = 0xFFFF;
    
    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = iomux_call(iomux, pco_iut, &fds, 1, &timeout);

    if (iomux == IC_OO_EPOLL && rc < 0 && RPC_ERRNO(pco_iut) == RPC_EINVAL)
        TEST_VERDICT("WODA is not supported");

    if ((sock_type == RPC_SOCK_DGRAM) && (strcmp(evt, "EVT_WR") == 0))
    {
        if (rc != 1)
        {
            TEST_VERDICT("%s() called on SOCK_DGRAM socket to wait for "
                         "write event returned %d instead 1",
                         iomux_call_en2str(iomux), rc);
        }
        if ((fds.revents != (EVT_WR | EVT_WR_NORM)) &&
            (fds.revents != EVT_WR))
        {
            TEST_VERDICT("%s() called on not connected SOCK_DGRAM "
                         "socket to wait for write event returns %d "
                         "and sets events to %s instead of EVT_WR "
                         "(possibly with EVT_WR_NORM)",
                         iomux_call_en2str(iomux), rc,
                         iomux_event_rpc2str(fds.revents));
        }
    }
    else if ((sock_type == RPC_SOCK_STREAM) && iomux != IC_POLL && 
             iomux != IC_PPOLL && iomux != IC_EPOLL &&
             iomux != IC_EPOLL_PWAIT && iomux != IC_OO_EPOLL)
    {
        if (rc != 0 || fds.revents != 0)
        {
            TEST_VERDICT("%s() called on not connected SOCK_STREAM "
                         "socket to wait for %s event returns %d and "
                         "sets events to %s instead of 0",
                         iomux_call_en2str(iomux), evt, rc,
                         iomux_event_rpc2str(fds.revents));
        }
    }
    else
    {
        if ((rc == 0) && (fds.revents == 0))
        {
            /* That's OK */
        }
        else if ((rc == 1) && (fds.revents == (EVT_HUP | EVT_EXC)))
        {
            RING_VERDICT("EVT_HUP | EVT_EXC event is set");
        }
        else
        {
            TEST_VERDICT("%s() called on not connected %s socket "
                         "to wait for %s event returns %d and sets "
                         "events to %s instead of 0 with empty events or "
                         "1 with EVT_HUP|EVT_EXC",
                         iomux_call_en2str(iomux),
                         socktype_rpc2str(sock_type),
                         evt, rc, iomux_event_rpc2str(fds.revents));
        }
    }

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);

    TEST_END;
}
