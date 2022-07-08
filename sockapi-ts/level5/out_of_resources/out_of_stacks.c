/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Level5-specific test reproducing run out of hardware resources
 *
 * $Id$
 */

/** @page level5-out_of_resources-out_of_stack Too many stacks and packets in them
 *
 * @objective Check that new stack can be created when we get out-of-stacks
 *            condition and then destroy one.
 *
 * @type conformance
 *
 * @param pco_iut            PCO with IUT
 * @param pco_tst            Tester PCO
 *
 * @reference @ref STEVENS
 *
 * @par Scenario:
 *
 * -# Set @c EF_NO_FAIL to @c 0.
 * -# Create child process using @b fork() and @b exec().
 * -# Create @c SOCK_STREAM connection between @p pco_tst and just created
 *    child process.
 * -# Overfill buffer for both directions on created connection.
 * -# Repeat all previous steps until @b socket() on IUT returns @c -1 with
 *    @c EBUSY.
 * -# Close socket from the first connection on @p pco_tst and kill the
 *    first child of @p pco_iut.
 * -# Try to call socket on the last child once again. It should return
 *    correct socket.
 * -# Create connection using this socket and check it works.
 *
 * @author Yurij Plotnikov <Yurij.Plotnikov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "level5/out_of_resources/out_of_stacks"

#include "sockapi-test.h"
#include "onload.h"

#define MAX_SOCKS 1024

/* Maximum waiting time to overfill buffers in seconds. */
#define OVERFILL_BUFFER_TIMEOUT 40

int
main(int argc, char *argv[])
{
    rcf_rpc_server         *pco_iut = NULL;
    rcf_rpc_server         *pco_tst = NULL;
    rcf_rpc_server         *child[MAX_SOCKS];

    int                     sock_iut[MAX_SOCKS];
    int                     sock_tst[MAX_SOCKS];
    int                     aux_s = -1;
    int                     i = 0;

    const struct sockaddr     *iut_addr;
    const struct sockaddr     *tst_addr;
    struct sockaddr_storage    iut_addr_aux;
    struct sockaddr_storage    tst_addr_aux;

    char                    name[64];

    int         rcvbuf = 100000;
    uint64_t    sent;
    int         count;

    int                last_loop = FALSE;
    te_bool            ef_no_fail;
    te_bool            op_done;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR_NO_PORT(iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_BOOL_PARAM(ef_no_fail);

    memset(child, 0, sizeof(child));
    for (i = 0; i < MAX_SOCKS; i++)
        sock_iut[i] = sock_tst[i] = -1;

    i = 0;
    while (i < MAX_SOCKS)
    {
        if (i != 0)
        {
            memset(name, 0, sizeof(name));
            sprintf(name, "child_%d", i);
            CHECK_RC(rcf_rpc_server_fork_exec(pco_iut, name,
                                              &child[i]));
        }
        else
            child[i] = pco_iut;

        CHECK_RC(tapi_sockaddr_clone(pco_iut, iut_addr, &iut_addr_aux));
        CHECK_RC(tapi_sockaddr_clone(pco_tst, tst_addr, &tst_addr_aux));

        RPC_AWAIT_IUT_ERROR(child[i]);
        sock_iut[i] = rpc_socket(child[i], RPC_AF_INET, RPC_SOCK_STREAM,
                                 RPC_IPPROTO_TCP);
        if (sock_iut[i] < 0)
        {
            if (ef_no_fail)
                TEST_VERDICT("Socket opening failed despite EF_NO_FAIL=1");

            if (sock_iut[i] != -1)
                TEST_VERDICT("socket() returns %d instead of -1",
                             sock_iut[i]);
            CHECK_RPC_ERRNO(child[i], RPC_EBUSY,
                            "socket() called in out-of-stacks condition,"
                            " returns -1, but");
            last_loop = TRUE;
        }
        else if (tapi_onload_is_onload_fd(child[i], sock_iut[i]) ==
                 TAPI_FD_IS_SYSTEM)
        {
            if (ef_no_fail)
                last_loop = TRUE;
            else
                TEST_VERDICT("Unaccelerated socket was opened despite "
                             "EF_NO_FAIL=0");
        }

        if (last_loop)
        {
            RPC_CLOSE(pco_tst, sock_tst[1]);
            TAPI_WAIT_NETWORK;
            rcf_rpc_server_destroy(child[1]);
            child[1] = NULL;
            TAPI_WAIT_NETWORK;
            sock_iut[i] = rpc_socket(child[i], RPC_AF_INET,
                                     RPC_SOCK_STREAM, RPC_IPPROTO_TCP);
            if (tapi_onload_is_onload_fd(child[i], sock_iut[i]) ==
                TAPI_FD_IS_SYSTEM)
                TEST_VERDICT("The last opened socket is unaccelerated.");
        }

        aux_s = rpc_socket(pco_tst, RPC_AF_INET, RPC_SOCK_STREAM,
                           RPC_IPPROTO_TCP);
        rpc_bind(child[i], sock_iut[i], SA(&iut_addr_aux));
        rpc_bind(pco_tst, aux_s, SA(&tst_addr_aux));
        rpc_listen(pco_tst, aux_s, 1);
        rpc_connect(child[i], sock_iut[i], SA(&tst_addr_aux));
        sock_tst[i] = rpc_accept(pco_tst, aux_s, NULL, NULL);
        RPC_CLOSE(pco_tst, aux_s);

        if (last_loop)
        {
            sockts_test_connection(child[i], sock_iut[i], pco_tst,
                                   sock_tst[i]);
            TEST_SUCCESS;
        }

        rpc_setsockopt(child[i], sock_iut[i], RPC_SO_RCVBUF, &rcvbuf);
        rpc_setsockopt(child[i], sock_iut[i], RPC_SO_SNDBUF, &rcvbuf);

        child[i]->op = RCF_RPC_CALL;
        rpc_overfill_buffers(child[i], sock_iut[i], &sent);
        op_done = FALSE;
        for (count = 0; count < OVERFILL_BUFFER_TIMEOUT && !op_done; count++)
        {
            SLEEP(1);
            CHECK_RC(rcf_rpc_server_is_op_done(child[i], &op_done));
        }

        if (op_done == FALSE)
            TEST_VERDICT("Send buffers overfilling timeout was reached");
        else
            rpc_overfill_buffers(child[i], sock_iut[i], &sent);

        rpc_overfill_buffers(pco_tst, sock_tst[i], &sent);
        i++;
    }

    TEST_FAIL("Failed to get out-of-stacks condition.");

cleanup:
    SLEEP(1);
    i = 0;
    while(sock_tst[i] != -1 || i == 1)
    {
        CLEANUP_RPC_CLOSE(pco_tst, sock_tst[i]);
        i++;
    }
    i = child[1] == NULL ? 2 : 1;
    while(child[i] != NULL)
    {
        rcf_rpc_server_destroy(child[i]);
        i++;
    }

    TEST_END;
}
