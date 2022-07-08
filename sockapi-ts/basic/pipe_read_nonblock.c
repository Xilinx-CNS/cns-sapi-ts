/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Basic Socket API
 */

/** @page basic-pipe_read_nonblock Read operation on non-blocking pipes.
 *
 * @objective Check that @c read() operation returns @c -1
 *            with @c EAGAIN when called on empty non-blocking pipe.
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
 * -# Create @p pipefds pipe on pco_iut. If @p func is "pipe2", set
 *    @c O_NONBLOCK flag on both ends of pipe with help of it.
 * -# Set @c O_NONBLOCK flag on read end of pipe with help of @b fcntl()
 *    or @b ioctl if @func is "fcntl" or "ioctl".
 * -# Call @b read() on read end.
 * -# Check that @b read() returned @c -1 and set errno to @c EAGAIN.
 * -# Write @p data_size bytes of data to the pipe.
 * -# Call @b read() on read end and check that it returns @p data_size.
 * -# Call @b read() once again and check that it returns @c -1 and set
 *    errno to @c EAGAIN.
 *
 * @author Yurij Plotnikov <Yurij.Plotnikov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "basic/pipe_read_nonblock"

#include "sockapi-test.h"
#include "tapi_rpc.h"

#define BUF_SIZE 1024

int
main(int argc, char *argv[])
{
    rcf_rpc_server     *pco_iut = NULL;
    int                 pipefds[2] = { -1, -1};

    int                 data_size;
    int                 buf[BUF_SIZE];

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

    if (func == PIPE2_SET_FDFLAG)
    {
        if (rpc_find_func(pco_iut, "pipe2") != 0)
            TEST_VERDICT("Failed to find pipe2() on pco_iut");

        rpc_pipe2(pco_iut, pipefds, RPC_O_NONBLOCK);
    }
    else
        rpc_pipe(pco_iut, pipefds);

    if (func == IOCTL_SET_FDFLAG) {
        int nblock = 1;

        rpc_ioctl(pco_iut, pipefds[0], RPC_FIONBIO, &nblock);
    }
    else if (func == FCNTL_SET_FDFLAG)
        rpc_fcntl(pco_iut, pipefds[0], RPC_F_SETFL, RPC_O_NONBLOCK);

    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = recv_f(pco_iut, pipefds[0], buf, data_size, 0);
    if (rc != -1)
        TEST_FAIL("Non-blocking %s() returns %d instead of -1",
                  rpc_recv_func_name(recv_f), rc);
    else
        CHECK_RPC_ERRNO(pco_iut, RPC_EAGAIN,
                        "Non-blocking read() fails, but");

    if (tapi_check_pipe(pco_iut, pipefds))
        TEST_FAIL("Failed to exchange data on the pipe");

    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = recv_f(pco_iut, pipefds[0], buf, data_size, 0);
    if (rc != -1)
        TEST_FAIL("Non-blocking %s() returns %d instead of -1",
                  rpc_recv_func_name(recv_f), rc);
    else
        CHECK_RPC_ERRNO(pco_iut, RPC_EAGAIN,
                        "Non-blocking %s() fails, but",
                        rpc_recv_func_name(recv_f));

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, pipefds[0]);
    CLEANUP_RPC_CLOSE(pco_iut, pipefds[1]);

    TEST_END;
}
