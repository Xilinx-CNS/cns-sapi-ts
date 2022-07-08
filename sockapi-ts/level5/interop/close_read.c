/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Interoperability of L5 stack with system stack.
 *
 * $Id$
 */

/** @page level5-interop-close_read Usage of system close call on reading socket
 *
 * @objective Check that it is possible to use system provided @b close()
 *            function on L5 socket when @b read() started but havn't
 *            satisfied yet.
 *
 * @type interop
 *
 * @pre Sockets @p iut_s and @p tst_s are connected.
 * 
 * @par Test sequence:
 * -# Call @b read() on @p iut_s socket in @p pco_iut thread.
 * -# Call @b close() on @p iut_s socket in @p pco_aux thread.
 * -# Check that state of @p iut_s socket is @c STATE_CLOSED.
 * -# Send some data from @p tst_s socket to @p iut_s socket.
 * -# Check that recieved and sent data are equel in case of successful
 *    @b read() or check that @b read() returned @c -1 and sets errno to
 *    @c EBADF.
 * -# Close @p tst_s socket.
 *
 * @author Yurij Plotnikov <Yurij.Plotnikov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "level5/interop/close_read"

#include "sockapi-test.h"

#define DATA_BULK 1024
#define SLEEP_TIME 100

static uint8_t buf[DATA_BULK];

int
main(int argc, char *argv[])
{
    rcf_rpc_server         *pco_iut = NULL;
    rcf_rpc_server         *pco_aux = NULL;
    rcf_rpc_server         *pco_tst = NULL;

    rpc_socket_type         sock_type;

    const char             *syscall_method = NULL;

    int                     iut_s = -1;
    int                     tst_s = -1;

    const struct sockaddr  *iut_addr;
    const struct sockaddr  *tst_addr;

    int                     sock;

    uint8_t                *tx_buf = NULL;

    int                     len;
    
    TEST_START;

    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_aux);
    TEST_GET_PCO(pco_tst);
    TEST_GET_SOCK_TYPE(sock_type);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_STRING_PARAM(syscall_method);

    GEN_CONNECTION(pco_iut, pco_tst, sock_type, RPC_PROTO_DEF,
                   iut_addr, tst_addr, &iut_s, &tst_s);
    
    pco_iut->op = RCF_RPC_CALL;
    rpc_read(pco_iut, iut_s, buf, DATA_BULK);
    
    sock = iut_s;
    pco_aux->use_libc_once = TRUE;
    rpc_close_alt(pco_aux, sock, syscall_method);
    sock = -1;
    CHECK_SOCKET_STATE(pco_aux, iut_s, NULL, -1, STATE_CLOSED);
    
    /* Prepare data to transmit */
    tx_buf = te_make_buf_by_len(DATA_BULK);
    RPC_WRITE(rc, pco_tst, tst_s, tx_buf, DATA_BULK);

    RPC_AWAIT_IUT_ERROR(pco_iut);
    pco_iut->op = RCF_RPC_WAIT;
    len = rpc_read(pco_iut, iut_s, buf, DATA_BULK);
    if (len == -1)
        CHECK_RPC_ERRNO(pco_iut, RPC_EBADF,
                        "RPC read() on iut_s failed with unexpected"
                        " errno.");
    else
    {
        if (len != rc)
            TEST_FAIL("There were send %d bytes but recieved %d", rc, len);
        if (memcmp(buf, tx_buf, len) != 0)
            TEST_FAIL("Recieved and sent data are not equel.");
    }
  
    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, sock);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    
    TEST_END;
}
