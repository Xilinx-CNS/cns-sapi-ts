/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Interoperability of L5 stack with system stack.
 *
 * $Id$
 */

/** @page level5-interop-close_iomux Usage of system close call on socket with active iomux function
 *
 * @objective Check that it is possible to use system provided @b close()
 *            function on L5 socket when @b select() or @b poll() started
 *            but havn't satisfied yet.
 *
 * @param sock_type   Socket type used in the test
 * @param iomux       @b poll() or @b select() function which will be used
 *                    for the test purposes
 *                    
 * @type interop
 * 
 * @pre Sockets @p iut_s and @p tst_s are connected.
 *
 * @par Test sequence:
 * -# Call @p iomux function on @p pco_iut and with 3 seconds timeout.
 * -# Resolve @b close() function with system (libc) library
 * -# Call @b close() on @p iut_s socket in @p pco_aux thread.
 * -# Check that state of @p iut_s socket is @c STATE_CLOSED.
 * -# Wait for @b iomux function on @p pco_iut and check its returning
 *    value:
 *      - it may return timeout (closed description has not been noticed);
 *      - it may return invalid file description detection (@c -1 with
 *        @c EBADF @b errno in the case of @b select() and @b pselect(),
 *        @c 1 with @c POLLNVAL in the case of @b poll()).
 * -# Close @p tst_s socket.
 *
 * @author Yurij Plotnikov <Yurij.Plotnikov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "level5/interop/close_iomux"

#include "sockapi-test.h"
#include "iomux.h"

#define DATA_BULK 1024

int
main(int argc, char *argv[])
{
    iomux_call_type         iomux;
    rcf_rpc_server         *pco_iut = NULL;
    rcf_rpc_server         *pco_aux = NULL;
    rcf_rpc_server         *pco_tst = NULL;

    const char             *syscall_method = NULL;
    
    int                     iut_s = -1;
    int                     tst_s = -1;

    iomux_evt_fd            event;

    const struct sockaddr  *iut_addr;
    const struct sockaddr  *tst_addr;

    rpc_socket_type         sock_type;

    int                     sock = -1;
    
    tarpc_timeval           timeout;
    
    TEST_START;

    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_aux);
    TEST_GET_PCO(pco_tst);
    TEST_GET_IOMUX_FUNC(iomux);
    TEST_GET_SOCK_TYPE(sock_type);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_STRING_PARAM(syscall_method);

    memset(&event, 0, sizeof(event));

    GEN_CONNECTION(pco_iut, pco_tst, sock_type, RPC_PROTO_DEF,
                    iut_addr, tst_addr, &iut_s, &tst_s);
    sock = iut_s;
    
    event.fd = iut_s;
    event.events = EVT_RD;
    timeout.tv_sec = 3;
    timeout.tv_usec = 0;
    pco_iut->op = RCF_RPC_CALL;
    rc = iomux_call(iomux, pco_iut, &event, 1, &timeout);
    TAPI_WAIT_NETWORK;
    
    pco_aux->use_libc_once = TRUE;
    rpc_close_alt(pco_aux, sock, syscall_method);
    CHECK_SOCKET_STATE(pco_aux, iut_s, NULL, -1, STATE_CLOSED);
    
    pco_iut->op = RCF_RPC_WAIT;
    rc = iomux_call(iomux, pco_iut, &event, 1, &timeout);
    if (rc == 0)
    {
        RING_VERDICT("%s() has not noticed that subject file "
                     "descriptor was closed from another thread "
                     "during the call", iomux_call_en2str(iomux));
    }
    else if (IOMUX_IS_SELECT_LIKE(iomux))
    {
        if (rc == -1)
        {
            CHECK_RPC_ERRNO(pco_iut, RPC_EBADF, "Socket was closed "
                            "when %s() was in progress",
                            iomux_call_en2str(iomux));
        }
        else
        {
            TEST_VERDICT("%s() returned %d unexpectedly",
                         iomux_call_en2str(iomux), rc);
        }
    }
    else
    {
        if (rc == -1)
        {
            TEST_VERDICT("poll() fails unexpectedly with errno %s when "
                         "one of its sockets is closed",
                         errno_rpc2str(RPC_ERRNO(pco_iut)));
        }
        else if (rc != 1)
        {
            TEST_VERDICT("poll() returned %d unexpectedly", rc);
        }
        else if (~event.revents & EVT_NVAL)
        {
            TEST_VERDICT("poll() returned unexpected events %s",
                         iomux_event_rpc2str(event.revents));
        }
    }       
  
    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    
    TEST_END;
}
