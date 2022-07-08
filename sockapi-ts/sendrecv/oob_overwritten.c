/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Advanced usage of send/receive functions
 */

/** @page sendrecv-oob_overwritten OOB data delivering
 *
 * @objective Check that OOB data can be lost if these have not be read
 *            before the next OOB is received.
 *
 * @type conformance
 *
 * @param env             Network environment configuration:
 *                        - @ref arg_types_env_peer2peer
 *                        - @ref arg_types_env_peer2peer_tst
 *                        - @ref arg_types_env_peer2peer_lo
 *                        - @ref arg_types_env_peer2peer_fake
 *                        - @ref arg_types_env_peer2peer_ipv6
 *                        - @ref arg_types_env_peer2peer_tst_ipv6
 *                        - @ref arg_types_env_peer2peer_lo_ipv6
 * @param recv_func       Receiving function to check:
 *                        - @b recv()
 *                        - @b recvfrom()
 *                        - @b recvmsg()
 *                        - @b recvmmsg()
 *                        - @b onload_zc_recv()
 *
 * @par Scenario:
 *
 * @author Igor Vasiliev <Igor.Vasiliev@oktetlabs.ru>
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME "sendrecv/oob_overwritten"

#include "sockapi-test.h"

/**
 * Call receiving function, check result if required.
 *
 * @param rpcs                  RPC server handle.
 * @param s                     Socket FD.
 * @param buf                   Buffer where to save received
 *                              data.
 * @param len                   Length of the buffer.
 * @param flags                 Flags to pass to receiving function.
 * @param exp_len               Expected number of received bytes.
 * @param recv_msg_func         Pointer to receiving function to which
 *                              struct msghdr pointer is passed.
 * @param recv_buf_func         Pointer to receiving function to which
 *                              buffer pointer is passed (used if the
 *                              first function pointer is NULL).
 * @param err_msg               Message to print in verdicts.
 * @param test_failed           Will be set to TRUE if some check failed.
 * @param no_rc_check           If TRUE, do not check return value.
 *
 * @return Value returned by the receiving function.
 */
static int
call_recv_func(rcf_rpc_server *rpcs, int s,
               char *buf, size_t len, int flags,
               size_t exp_len,
               rpc_msg_read_f recv_msg_func,
               rpc_recv_f recv_buf_func,
               char *err_msg, te_bool *test_failed,
               te_bool no_rc_check)
{
    int     rc = 0;
    te_bool nonblocking = (rpcs->op == RCF_RPC_CALL);

    RPC_AWAIT_ERROR(rpcs);
    if (recv_msg_func != NULL)
    {
        rpc_msghdr    msg;
        rpc_iovec     vector;
        unsigned int  exp_flags = 0;

        memset(&vector, 0, sizeof(vector));
        vector.iov_base = buf;
        vector.iov_len = vector.iov_rlen = len;

        memset(&msg, 0, sizeof(msg));
        msg.msg_flags_mode = RPC_MSG_FLAGS_NO_CHECK;
        msg.msg_iov = &vector;
        msg.msg_iovlen = msg.msg_riovlen = 1;

        rc = recv_msg_func(rpcs, s, &msg, flags);
        if (rc > 0 && !nonblocking)
        {
            if (flags & RPC_MSG_OOB)
                exp_flags = RPC_MSG_OOB;

            if (msg.msg_flags != exp_flags)
            {
                ERROR_VERDICT("%s: for received message unexpected flags "
                              "'%s' were reported", err_msg,
                              send_recv_flags_rpc2str(msg.msg_flags));
                *test_failed = TRUE;
            }
        }
    }
    else
    {
        rc = recv_buf_func(rpcs, s, buf, len, flags);
    }

    if (!no_rc_check)
    {
        if (rc < 0)
        {
            TEST_VERDICT("%s: receiving function failed unexpectedly with "
                         "error " RPC_ERROR_FMT, err_msg,
                         RPC_ERROR_ARGS(rpcs));
        }
        else if (!nonblocking && rc != (int)exp_len)
        {
            TEST_VERDICT("%s: receiving function returned unexpected "
                         "number of bytes", err_msg);
        }
    }

    return rc;
}

/** Structure describing sent byte */
typedef struct byte_descr {
    char         byte;    /**< Byte value */
    const char  *descr;   /**< String description */
} byte_descr;

/** Array of bytes to send */
static byte_descr bytes[] = {
    { '1', "the first normal byte" },
    { 'a', "the first OOB byte" },
    { '2', "the second normal byte" },
    { 'b', "the second OOB byte" },
    { 'c', "the third OOB byte" },
};

/**
 * Get string description of a byte by its value.
 *
 * @param byte        Value.
 *
 * @return Description.
 */
static const char *
get_byte_descr(char byte)
{
    unsigned int i;

    for (i = 0; i < TE_ARRAY_LEN(bytes); i++)
    {
        if (bytes[i].byte == byte)
            return bytes[i].descr;
    }

    return "unknown byte";
}

int
main(int argc, char *argv[])
{
    rcf_rpc_server         *pco_iut = NULL;
    rcf_rpc_server         *pco_tst = NULL;

    const struct sockaddr  *iut_addr = NULL;
    const struct sockaddr  *tst_addr = NULL;

    int                     iut_s = -1;
    int                     tst_s = -1;
    int                     optval;

    char                    recvoobbuf;
    te_bool                 test_failed = FALSE;
    te_bool                 done = TRUE;

    rpc_msg_read_f          recv_msg_func;
    rpc_recv_f              recv_buf_func;
    const char             *recv_func;

    /* Preambule */
    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_STRING_PARAM(recv_func);

    recv_msg_func = rpc_msg_read_func_by_string(recv_func);
    recv_buf_func = rpc_recv_func_by_string(recv_func);
    if (recv_msg_func == NULL && recv_buf_func == NULL)
        TEST_FAIL("Unknown receiving function");

    TEST_STEP("Create a pair of connected TCP sockets - @b iut_s "
              "on IUT and @b tst_s on Tester.");
    GEN_CONNECTION_FAKE(pco_tst, pco_iut, RPC_SOCK_STREAM, RPC_PROTO_DEF,
                        tst_addr, iut_addr, &tst_s, &iut_s);

    TEST_STEP("Disable @c SO_OOBINLINE on the IUT socket.");
    optval = 0;
    rpc_setsockopt(pco_iut, iut_s, RPC_SO_OOBINLINE, &optval);

    TEST_STEP("Send four different bytes from the Tester socket: the "
              "first and the third byte without @c MSG_OOB, the second "
              "and the fourth bytes with @c MSG_OOB.");
    RPC_SEND(rc, pco_tst, tst_s, &bytes[0].byte, 1, 0);
    RPC_SEND(rc, pco_tst, tst_s, &bytes[1].byte, 1, RPC_MSG_OOB);
    RPC_SEND(rc, pco_tst, tst_s, &bytes[2].byte, 1, 0);
    RPC_SEND(rc, pco_tst, tst_s, &bytes[3].byte, 1, RPC_MSG_OOB);

    TEST_STEP("Wait for a while and call @p recv_func with @c MSG_OOB "
              "flag on the IUT socket. Check that it returns the fourth "
              "byte (the last byte sent with @c MSG_OOB).");
    TAPI_WAIT_NETWORK;
    call_recv_func(pco_iut, iut_s, &recvoobbuf, 1, RPC_MSG_OOB,
                   1, recv_msg_func, recv_buf_func,
                   "The first receiving call", &test_failed, FALSE);
    if (recvoobbuf != bytes[3].byte)
    {
        ERROR_VERDICT("The first receiving call returned %s instead of %s",
                      get_byte_descr(recvoobbuf), bytes[3].descr);
        test_failed = TRUE;
    }

    TEST_STEP("Call receiving function the second time with "
              "@c RCF_RPC_CALL and check that it does not block.");
    pco_iut->op = RCF_RPC_CALL;
    call_recv_func(pco_iut, iut_s, &recvoobbuf, 1, RPC_MSG_OOB,
                   1, recv_msg_func, recv_buf_func,
                   "The second receiving call", &test_failed,
                   TRUE);

    TAPI_WAIT_NETWORK;
    CHECK_RC(rcf_rpc_server_is_op_done(pco_iut, &done));
    if (!done)
    {
        TEST_SUBSTEP("If it is blocked, send additional (the fifth) byte "
                     "from the Tester socket with @c MSG_OOB to "
                     "unblock it.");
        RING_VERDICT("The second receiving call blocked");
        RPC_SEND(rc, pco_tst, tst_s, &bytes[4].byte, 1, RPC_MSG_OOB);
    }

    /*
     * If implementation keeps only one OOB byte, we should expect
     * that the next call returns error.
     */

    TEST_STEP("Obtain result of the second call of @p recv_func.");
    rc = call_recv_func(pco_iut, iut_s, &recvoobbuf, 1, RPC_MSG_OOB,
                        1, recv_msg_func, recv_buf_func,
                        "The second receiving call", &test_failed,
                        TRUE);

    TEST_STEP("Check that it fails with @c EINVAL, unless it was "
              "blocked before, in which case it should return the "
              "last byte sent with @c MSG_OOB.");
    if (rc < 0)
    {
        if (RPC_ERRNO(pco_iut) != RPC_EINVAL || !done)
        {
            TEST_VERDICT("The second receiving call failed with "
                         RPC_ERROR_FMT " instead of %s",
                         RPC_ERROR_ARGS(pco_iut),
                         (done ? "EINVAL" : "succeeding"));
        }
    }
    else if (rc != 1)
    {
        TEST_VERDICT("The second receiving call returned unexpected number "
                     "of bytes");
    }
    else
    {
        if (done)
        {
            RING_VERDICT("The second receiving call returned %s instead of "
                         "failing", get_byte_descr(recvoobbuf));
        }
        else if (recvoobbuf != bytes[4].byte)
        {
            TEST_VERDICT("The second receiving call returned %s instead of "
                         "%s", get_byte_descr(recvoobbuf),
                         bytes[4].descr);
        }
    }

    if (test_failed)
        TEST_STOP;

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    CHECK_CLEAR_TRANSPARENT(iut_addr, pco_tst, tst_addr);

    TEST_END;
}
