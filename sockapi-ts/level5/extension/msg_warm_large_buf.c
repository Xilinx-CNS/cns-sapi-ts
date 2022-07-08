/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Onload extensions
 *
 * $Id$
 */

/**
 * @page level5-extension-msg_warm_large_buf Send large buffer with ONLOAD_MSG_WARM
 *
 * @objective Check that @c ONLOAD_MSG_WARM flag cannot be used
 *            when more than MSS bytes is passed to send function.
 *
 * @param sock_type     Socket type:
 *                      - tcp active
 *                      - tcp passive
 * @param func          Testing send function:
 *                      - send
 *                      - sendto
 *                      - sendmsg
 *
 * @par Scenario:
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME "level5/extension/msg_warm_large_buf"

#include "sockapi-test.h"

/** Buffer size. */
#define BUF_SIZE  (mss + 1)

int
main(int argc, char *argv[])
{
    rcf_rpc_server     *pco_iut = NULL;
    rcf_rpc_server     *pco_tst = NULL;

    const struct sockaddr  *iut_addr = NULL;
    const struct sockaddr  *tst_addr = NULL;

    int   iut_s = -1;
    int   tst_s = -1;
    int   mss;
    char *buf;

    sockts_socket_type    sock_type;
    rpc_send_f            func;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    SOCKTS_GET_SOCK_TYPE(sock_type);
    TEST_GET_SEND_FUNC(func);

    TEST_STEP("Establish TCP connection according to @p sock_type.");
    SOCKTS_CONNECTION(pco_iut, pco_tst, iut_addr, tst_addr, sock_type,
                      &iut_s, &tst_s, NULL);

    TEST_STEP("Get MSS value.");
    rpc_getsockopt(pco_iut, iut_s, RPC_TCP_MAXSEG, &mss);

    buf = TE_ALLOC(BUF_SIZE);
    te_fill_buf(buf, BUF_SIZE);

    TEST_STEP("Call @p func with @c ONLOAD_MSG_WARM flag, passing more than "
              "MSS bytes to it. Check that it fails as expected.");
    RPC_AWAIT_ERROR(pco_iut);
    rc = func(pco_iut, iut_s, buf, BUF_SIZE, RPC_MSG_WARM);

    if (rc >= 0)
        TEST_VERDICT("%s() succeeded", rpc_send_func_name(func));
    else if (RPC_ERRNO(pco_iut) != RPC_EINVAL)
        TEST_VERDICT("%s() failed with unexpected errno %r",
                     rpc_send_func_name(func), RPC_ERRNO(pco_iut));

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    free(buf);

    TEST_END;
}
