/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Basic Socket API
 */

/** @page basic-pipe_write_nonblock Write operation on non-blocking pipes.
 *
 * @objective Check that @c write() operation returns @c -1
 *            with @c EAGAIN when called on full non-blocking pipe.
 * 
 * @type Conformance, compatibility
 *
 * @param env   Testing environment:
 *              - @ref arg_types_env_iut_only
 * @param data_size Size of data to send:
 *                  - 512
 * @param func      Function to set @c O_NONBLOCK flag:
 *                  - fcntl()
 *                  - pipe2()
 *                  - ioctl()
 *
 * @par Scenario:
 *
** -# Create @p pipefds pipe on pco_iut. If @p func is "pipe2", set
 *    @c O_NONBLOCK flag on both ends of pipe with help of it.
 * -# Set @c O_NONBLOCK flag on write end of pipe with help of @b fcntl()
 *    or @b ioctl if @func is "fcntl" or "ioctl".
 * -# Call @b write() on write end of pipe multiple times until it returns
 *    @c -1.
 * -# Check that @b write() set errno to @c EINVAL.
 * -# Read all data from the pipe.
 * -# Call @b write() on write end and check that it returns @p data_size.
 * -# Call @b write() multiple times until it returns @c -1.
 * -# Check that @b write() set errno to @c EINVAL.
 *
 * @author Yurij Plotnikov <Yurij.Plotnikov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "basic/pipe_write_nonblock"

#include "sockapi-test.h"

int
main(int argc, char *argv[])
{
    rcf_rpc_server     *pco_iut = NULL;
    int                 pipefds[2] = { -1, -1};

    void               *tx_buf = NULL;
    void               *rx_buf = NULL;
    int                 data_size;
    uint64_t            total_bytes = 0;

    rpc_send_f          send_f;
    rpc_recv_f          recv_f;
    
    fdflag_set_func_type_t    func = UNKNOWN_SET_FDFLAG;

    /*
     * Test preambule.
     */
    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_INT_PARAM(data_size);
    TEST_GET_SEND_FUNC(send_f);
    TEST_GET_RECV_FUNC(recv_f);
    TEST_GET_FDFLAG_SET_FUNC(func);

    tx_buf = te_make_buf_by_len(data_size);
    rx_buf = te_make_buf_by_len(data_size);
    te_fill_buf(tx_buf, data_size);

    if (func == PIPE2_SET_FDFLAG)
    {
        if (rpc_find_func(pco_iut, "pipe2") != 0)
            TEST_VERDICT("Failed to find pipe2() on pco_iut");

        rpc_pipe2(pco_iut, pipefds, RPC_O_NONBLOCK);
    }
    else
        rpc_pipe(pco_iut, pipefds);

    rpc_overfill_fd(pco_iut, pipefds[1], &total_bytes);

    if (func == IOCTL_SET_FDFLAG) {
        int nblock = 1;

        rpc_ioctl(pco_iut, pipefds[1], RPC_FIONBIO, &nblock);
    }
    else if (func == FCNTL_SET_FDFLAG)
        rpc_fcntl(pco_iut, pipefds[1], RPC_F_SETFL, RPC_O_NONBLOCK);

    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = send_f(pco_iut, pipefds[1], tx_buf, data_size, 0);
    if (rc != -1)
        TEST_FAIL("Non-blocking %s() returns %d instead of -1",
                  rpc_send_func_name(send_f), rc);
    else
        CHECK_RPC_ERRNO(pco_iut, RPC_EAGAIN,
                        "Non-blocking %s() fails, but",
                        rpc_send_func_name(send_f));

    do {
        rc = recv_f(pco_iut, pipefds[0], rx_buf, data_size, 0);
        total_bytes -= rc;
    } while (total_bytes != 0);

    rc = send_f(pco_iut, pipefds[1], tx_buf, data_size, 0);
    if (rc != data_size)
        TEST_FAIL("%s() function called with on pipe without data"
                  "returned %d instead of %d",
                  rpc_send_func_name(send_f), rc, data_size);

    rpc_overfill_fd(pco_iut, pipefds[1], &total_bytes);

    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = send_f(pco_iut, pipefds[1], tx_buf, data_size, 0);
    if (rc != -1)
        TEST_FAIL("Non-blocking %s() returns %d instead of -1",
                  rpc_send_func_name(send_f), rc);
    else
        CHECK_RPC_ERRNO(pco_iut, RPC_EAGAIN,
                        "Non-blocking %s() fails, but",
                        rpc_send_func_name(send_f));

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, pipefds[0]);
    CLEANUP_RPC_CLOSE(pco_iut, pipefds[1]);

    TEST_END;
}
