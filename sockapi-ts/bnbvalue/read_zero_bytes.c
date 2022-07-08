/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Bad Parameters and Boundary Values
 */

/** @page bnbvalue-read_zero_bytes Reading zero bytes from fd
 *
 * @objective Check that attempt to read zero bytes never blocks.
 *
 * @type conformance, robustness
 *
 * @param is_pipe               Whether we test a pipe or a socket
 * @param pco_iut               PCO on IUT
 * @param pco_tst               PCO on TESTER (if !(@p is_pipe))
 * @param iut_addr              Network address on IUT (if !(@p is_pipe))
 * @param tst_addr              Network address on TESTER (if !(@p is_pipe))
 * @param sock_type             Socket type (if !(@p is_pipe))
 * @param data_ready            Whether some data can be read on IUT
 * @param func                  Function used to read data
 *
 * @par Scenario:
 *  -# Create connected pair of file descriptors (@p iut_fd, @p tst_fd).
 *  -# If @p data_ready, write some data on @p tst_fd.
 *  -# Try to read zero bytes from @p iut_fd, check that it returns
 *     immediately.
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME  "bnbvalue/read_zero_bytes"

#include "sockapi-test.h"

#define DATA_LEN 100

int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst = NULL;

    rpc_recv_f              func;
    te_bool                 is_pipe;
    te_bool                 data_ready;
    te_bool                 op_done = FALSE;
    rpc_socket_type         sock_type;
    const struct sockaddr  *iut_addr;
    const struct sockaddr  *tst_addr;
    int                     iut_fd = -1;
    int                     tst_fd = -1;
    int                     pipefds[2] = { -1, -1};
    char                    tx_buf[DATA_LEN];
    char                    rx_buf[DATA_LEN];

    te_bool                 test_failed = FALSE;

    TEST_START;

    TEST_GET_PCO(pco_iut);
    TEST_GET_RECV_FUNC(func);
    TEST_GET_BOOL_PARAM(is_pipe);
    TEST_GET_BOOL_PARAM(data_ready);
    if (!is_pipe)
    {
        TEST_GET_SOCK_TYPE(sock_type);
        TEST_GET_PCO(pco_tst);
        TEST_GET_ADDR(pco_tst, tst_addr);
        TEST_GET_ADDR(pco_iut, iut_addr);
    }

    if (is_pipe) 
    {
        rpc_pipe(pco_iut, pipefds);
        rcf_rpc_server_fork(pco_iut, "iut_child", &pco_tst);
        iut_fd = pipefds[0];
        tst_fd = pipefds[1];
        rpc_close(pco_iut, tst_fd);
        rpc_close(pco_tst, iut_fd);
    }
    else
        GEN_CONNECTION_WILD(pco_iut, pco_tst, sock_type, RPC_PROTO_DEF,
                            iut_addr, tst_addr, &iut_fd, &tst_fd, TRUE);


    if (data_ready)
        rpc_write(pco_tst, tst_fd, tx_buf, DATA_LEN);

    /* Fixme: disable msg_flags auto check for datagrams. In case of
     * incomplete reading of a datagram flag MSG_TRUNC is set, what is
     * detected by the check. If msg_flags check is desired then explicit
     * call of recvmsg() like functions should be done with subsequent
     * flags check.
     *
     * This does not require any reversion, i.e. the check is disabled only
     * for the current test run. */
    if (sock_type == RPC_SOCK_DGRAM)
        tapi_rpc_msghdr_msg_flags_init_check(FALSE);

    pco_iut->op = RCF_RPC_CALL;
    func(pco_iut, iut_fd, rx_buf, 0, 0);

    TAPI_WAIT_NETWORK;

    rcf_rpc_server_is_op_done(pco_iut, &op_done);
    if (!op_done)
    {
        if (!data_ready)
            rpc_write(pco_tst, tst_fd, tx_buf, DATA_LEN);
        TAPI_WAIT_NETWORK;
        rcf_rpc_server_is_op_done(pco_iut, &op_done);

        if (!op_done)
        {
            rcf_rpc_server_restart(pco_iut);
            iut_fd = -1;
            TEST_VERDICT("read is still hanging even after data were "
                         "sent from peer");
        }
        else
        {
            test_failed = TRUE;
            ERROR_VERDICT("Attempt to read zero bytes blocks");
        }
    }

    pco_iut->op = RCF_RPC_WAIT;
    RPC_AWAIT_ERROR(pco_iut);
    rc = func(pco_iut, iut_fd, rx_buf, 0, 0);

    if (rc < 0)
    {
        TEST_VERDICT("Attempt to read zero bytes resulted "
                     "in error " RPC_ERROR_FMT,
                     RPC_ERROR_ARGS(pco_iut));
    }
    else if (rc != 0)
    {
        TEST_VERDICT("Attempt to read zero bytes terminated "
                     "with strange result");
    }

    if (test_failed)
        TEST_STOP;

    TEST_SUCCESS;

cleanup:

    if (is_pipe && pco_tst != NULL)
        rcf_rpc_server_destroy(pco_tst);

    CLEANUP_RPC_CLOSE(pco_iut, iut_fd);
    if (!is_pipe)
        CLEANUP_RPC_CLOSE(pco_tst, tst_fd);

    TEST_END;
}
