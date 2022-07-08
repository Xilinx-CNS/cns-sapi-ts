/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Interoperability of L5 stack with system stack.
 *
 * $Id$
 */

/** @page level5-interop-close_udp_readable_socket Usage of system close() call on readable UDP
 *
 * @objective Check that it is possible to use system provided @b close()
 *            function on UDP L5 socket if there are some data for read.
 *
 * @type interop
 *
 * @pre Sockets @p iut_s and @p tst_s are connected.
 * 
 * @par Test sequence:
 * -# Send some data to @p iut_s socket.
 * -# Check that @p iut_s socket is readable.
 * -# Resolve @b close() function with system (libc) library.
 * -# Call @b close() function on @p iut_s socket.
 * -# Close @p tst_s socket.
 *
 * @author Yurij Plotnikov <Yurij.Plotnikov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "level5/interop/close_udp_readable_socket"

#include "sockapi-test.h"

#define DATA_BULK 1024
#define SLEEP_TIME 100

int
main(int argc, char *argv[])
{
    rcf_rpc_server         *pco_iut = NULL;
    rcf_rpc_server         *pco_tst = NULL;

    const char             *syscall_method = NULL;
    
    int                     iut_s = -1;
    int                     tst_s = -1;

    const struct sockaddr  *iut_addr;
    const struct sockaddr  *tst_addr;
    
    uint8_t                *tx_buf = NULL;

    int                     sock;

    TEST_START;

    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_STRING_PARAM(syscall_method);

    GEN_CONNECTION(pco_iut, pco_tst, RPC_SOCK_DGRAM, RPC_PROTO_DEF,
                   iut_addr, tst_addr, &iut_s, &tst_s);
    
    /* Prepare data to transmit */
    tx_buf = te_make_buf_by_len(DATA_BULK);
    
    RPC_WRITE(rc, pco_tst, tst_s, tx_buf, DATA_BULK);

    MSLEEP(SLEEP_TIME);

    RPC_CHECK_READABILITY(pco_iut, iut_s, TRUE);
    
    sock = iut_s;
    pco_iut->use_libc_once = TRUE;
    rpc_close_alt(pco_iut, iut_s, syscall_method);
    iut_s = -1;
    CHECK_SOCKET_STATE(pco_iut, sock, NULL, -1, STATE_CLOSED);
    
    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    
    TEST_END;
}
