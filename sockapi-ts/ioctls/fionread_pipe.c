/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * IOCTL Requests
 * 
 * $Id: 
 */

/** @page ioctls-fionread_pipe Usage of FIONREAD on pipe fds
 *
 * @objective Check that @c FIONREAD and @c SIOCINQ requests return
 *            the current number of bytes in the pipe.
 * 
 *
 * @param pco_iut       PCO on IUT
 * @param pco_tst       PCO on TESTER
 * 
 * @par Test sequence:

 * @author Konstantin Ushakov <Konstantin.Ushakov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "ioctls/fionread_udp"

#include "sockapi-test.h"

int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;
    int             req_val;
    int             fds[2];
    char           *tx_buf;
    char           *rx_buf;
    int             data_size;
    int             writes_num;
    int             i;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_INT_PARAM(data_size);
    TEST_GET_INT_PARAM(writes_num);

    tx_buf = te_make_buf_by_len(data_size);
    rx_buf = te_make_buf_by_len(data_size);

    TEST_STEP("Create a pipe");
    rpc_pipe(pco_iut, fds);

#define CALL_IOCTL(_fd)                                             \
    do {                                                            \
        RPC_AWAIT_IUT_ERROR(pco_iut);                               \
        rc = rpc_ioctl(pco_iut, (_fd), RPC_FIONREAD, &req_val);     \
        if (rc != 0)                                                \
            TEST_VERDICT("ioctl(%s) unexpectedly failed with "      \
                         "errno %s", ioctl_rpc2str(RPC_FIONREAD),    \
                         errno_rpc2str(RPC_ERRNO(pco_iut)));        \
    } while (0)

    TEST_STEP("Check that ioctl cmd FIONREAD returns zero when called on both ends "
              "as no data is present in the pipe");
    CALL_IOCTL(fds[0]);
    if (req_val != 0)
        TEST_FAIL("There is not data in the pipe, but "
                  "ioctl(%s) returns %d, but expected 0",
                  ioctl_rpc2str(RPC_FIONREAD), req_val);

    CALL_IOCTL(fds[1]);
    if (req_val != 0)
        TEST_FAIL("ioctl(%s) called on write end of the pipe "
                  "returns %d, but expected 0",
                  ioctl_rpc2str(RPC_FIONREAD), req_val);

    TEST_STEP("Write @data_size bytes to the pipe.");
    rpc_write(pco_iut, fds[1], tx_buf, data_size);

    TEST_STEP("Call ioctl @c FIONREAD on 'read' end of the pipe to check "
              "amount of data available. Ensure that it's equal to @p data_size");
    CALL_IOCTL(fds[0]);
    if (req_val != data_size)
        TEST_FAIL("There are %d bytes in the pipe, but "
                  "ioctl(%s) returns %d, but expected 0",
                  ioctl_rpc2str(RPC_FIONREAD), req_val);

    TEST_STEP("Check that 'write' end of the pipe thinks that @p data_size bytes "
              "can be read from it. This is crazy linux behaviour we're expected to "
              "follow.");
    CALL_IOCTL(fds[1]);
    if (req_val != data_size)
        TEST_FAIL("ioctl(%s) called on write end of the pipe "
                  "returns %d, but expected 0",
                  ioctl_rpc2str(RPC_FIONREAD), req_val);

    TEST_STEP("Write additional @p data_size bytes and check that FIONREAD returns "
              "@p data_size times two bytes. Repeat the action @p writes_num times.");

    for (i = 0; i < writes_num; i++)
    {
        rpc_write(pco_iut, fds[1], tx_buf, data_size);

        CALL_IOCTL(fds[0]);
        if (req_val != data_size * (i + 2))
            TEST_FAIL("There are %d bytes in the pipe, but "
                      "ioctl(%s) returns %d, but expected 0",
                      data_size * (i + 1),
                      ioctl_rpc2str(RPC_FIONREAD), req_val);
    }

    TEST_STEP("Read @data_size bytes from the pipe and check that ioctl() returns "
              "correct amount of data left. Repeat the action @writes_num + 1 "
              "time to check that pipe becomes empty.");
    for (i = 0; i < writes_num + 1; i++) {
        rpc_read(pco_iut, fds[0], rx_buf, data_size);
        CALL_IOCTL(fds[0]);
        if (req_val != data_size * (writes_num - i))
            TEST_FAIL("There are %d bytes in the pipe, but ioctl(%s) "
                      "returns %d", data_size, ioctl_rpc2str(RPC_FIONREAD),
                      req_val);
    }


    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, fds[0]);
    CLEANUP_RPC_CLOSE(pco_iut, fds[1]);

    TEST_END;
}

