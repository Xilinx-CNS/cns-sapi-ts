/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Interoperability of L5 stack with system stack.
 *
 * $Id$
 */

/** @page level5-interop-close_connected_socket Usage of system close() call on connected socket
 *
 * @objective Check that it is possible to use system provided @b close()
 *            function on connected L5 socket.
 *
 * @type interop
 *
 * @param data       TRUE/FALSE for close connected socket with/without
 *                   data in send or recieve buffer
 * @param s_buf      TRUE/FASLE for close connected socket with data in
 *                   send/recieve buffer
 * 
 * @pre Sockets @p iut_s and @p tst_s are connected.
 *
 * @par Test sequence:
 * -# If @p data parameter is @c TRUE and @p s_buf parameter is @c TRUE
 *    write to @p iut_s socket while the socket is writable (i.e. fill in
 *    @p iut_s Tx and @p tst_s Rx buffers). If @p s_buf parameter is
 *    @c FALSE send some data from @p tst_s socket.
 * -# If @p data parameter is @c TRUE and @p s_buf parameter is @c TRUE
 *    check that @p iut_s socket isn't writable. If @p s_buf parameter is
 *    @c FALSE check that @p iut_s socket is readable.
 * -# Resolve @b close() function with system (libc) library.
 * -# Call @b close() function on @p iut_s socket.
 * -# Close @p tst_s socket.
 *
 * @author Yurij Plotnikov <Yurij.Plotnikov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "level5/interop/close_connected_socket"

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

    te_bool                 data;
    te_bool                 s_buf;
    
    uint8_t                *tx_buf = NULL;
    
    uint64_t                total_filled = 0;
    
    int                     sock;
    
    TEST_START;

    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_BOOL_PARAM(data);
    TEST_GET_BOOL_PARAM(s_buf);
    TEST_GET_STRING_PARAM(syscall_method);

    GEN_CONNECTION(pco_iut, pco_tst, RPC_SOCK_STREAM, RPC_PROTO_DEF,
                   iut_addr, tst_addr, &iut_s, &tst_s);

    /* Prepare data to transmit */
    tx_buf = te_make_buf_by_len(DATA_BULK);

    if (data)
    {
        if (s_buf)
        {
            rpc_overfill_buffers(pco_iut, iut_s, &total_filled);
        }
        else
        {
            RPC_WRITE(rc, pco_tst, tst_s, tx_buf, DATA_BULK);
            MSLEEP(SLEEP_TIME);
            RPC_CHECK_READABILITY(pco_iut, iut_s, TRUE);
        }
    }
            
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
