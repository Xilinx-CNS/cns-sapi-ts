/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Bad Parameters and Boundary Values
 */

/** @page bnbvalue-tx_buf_len_connected Using different combinations of buffer and buffer length parameters with transmit functions on connected socket
 *
 * @objective Check the behaviour of transmit functions in the following
 *            cases:
 *                - zero length and @c NULL buffer;
 *                - zero length and not @c NULL buffer;
 *                - not zero length and @c NULL buffer.
 *                .
 *
 * @type conformance, robustness
 *
 * @reference @ref XNS5 section 8.1
 *
 * @param sock_type Socket type that can be  @c SOCK_STREAM or @c SOCK_DGRAM
 * @param func      Function used in the test:
 *                  - @b write()
 *                  - @b writev()
 *                  - @b send()
 *                  - @b sendto()
 *                  - @b sendmsg()
 *                  - @b sendmmsg()
 * @param buffer    @c FALSE if @c NULL or @c TRUE in case of the real buffer
 * @param buflen    Buffer length
 * @param env       Test environment
 *                   - @ref arg_types_env_peer2peer_all_ipv4_ipv6
 *
 * @par Scenario:
 *
 * @author Oleg Kravtsov <Oleg.Kravtsov@oktetlabs.ru>
 * @author Igor Vasiliev <Igor.Vasiliev@oktetlabs.ru>
 */

#define TE_TEST_NAME  "bnbvalue/tx_buf_len_connected"

#include "sockapi-test.h"

#define TST_BUF_LEN    300

int
main(int argc, char *argv[])
{
    rcf_rpc_server    *pco_iut = NULL;
    rcf_rpc_server    *pco_tst = NULL;
    int                iut_s = -1;
    int                tst_s = -1;
    rpc_socket_type    sock_type;
    rpc_send_f         func;
    te_bool            buffer = FALSE;
    int                buflen;

    const struct sockaddr  *iut_addr;
    const struct sockaddr  *tst_addr;
    void                   *tx_buf = NULL;

    /* Preambule */
    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_SOCK_TYPE(sock_type);
    TEST_GET_BOOL_PARAM(buffer);
    TEST_GET_INT_PARAM(buflen);
    TEST_GET_SEND_FUNC(func);

    if (strcmp(rpc_send_func_name(func), "template_send") == 0)
        sockts_kill_zombie_stacks(pco_iut);

    if (buffer && (buflen != 0))
        TEST_FAIL("Untested combination of the test parameters: "
                  "buffer pointer is not NULL and buffer length is not 0");

    if (func == rpc_send_func_onload_zc_send ||
        func == rpc_send_func_onload_zc_send_user_buf)
    {
        TEST_VERDICT("onload_zc_send() checking is not supported");
    }

    /* Prepare data to send by means of: */
    /* write(), send(), sendto() */
    if (buffer)
        tx_buf = te_make_buf_by_len(TST_BUF_LEN);
    else
        tx_buf = NULL;

    TEST_STEP("Create a connection for the test purposes");
    GEN_CONNECTION(pco_iut, pco_tst, sock_type, RPC_PROTO_DEF,
                   iut_addr, tst_addr, &iut_s, &tst_s);

    TEST_STEP("Call @p func on @p pco_iut socket passing @p buf as the value "
              "of:\n"
              "    - @a buffer parameter for @b send() and @b sendto();\n"
              "    - @a iov_base field of appropriate vector of @a message "
              "parameter for @b sendmsg() or @b sendmmsg();\n"
              "    - @a buf parameter for @b write();\n"
              "    - @a iov_base field of @a iovec parameter for "
              "@b writev();\n"
              "and @p buflen as the value of:\n"
              "    - @a length parameter for @b send() and @b sendto();\n"
              "    - @a iov_len field of appropriate vector of @a message "
              "parameter for @b sendmsg() or @b sendmmsg();\n"
              "    - @a count parameter for @b write();\n"
              "    - @a iov_len field of @a iovec parameter for @b writev();");
    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = func(pco_iut, iut_s, tx_buf, buflen, 0);

    TEST_STEP("Check the result of the @p func function calling:\n"
              "    - If @p buflen is zero, check that the function "
              "immediately returns @c 0 (it does not matter which value "
              "@p buffer parameter has);\n"
              "    - If @p buflen is not zero and @p buf is @c NULL, check "
              "that the function returns @c -1 and sets @b errno to "
              "@c EFAULT;");
    if (buflen == 0)
    {
        if (rc != 0)
        {
            if (rc < 0)
                TEST_VERDICT("Unexpected failure of the send function, "
                             "errno %s", errno_rpc2str(RPC_ERRNO(pco_iut)));
            else
                TEST_FAIL("Unexpected behaviour of the send function, "
                          "returned code %d instead of 0", rc);
        }
    }

    if ((buffer == FALSE) && (buflen > 0))
    {
        if (rc != -1)
        {
            TEST_VERDICT("Unexpected behaviour of the send function, "
                         "returned code %d instead of -1", rc);
        }
        CHECK_RPC_ERRNO(pco_iut, RPC_EFAULT,
                        "Unexpected behaivour of %s() with NULL "
                        "buffer pointer and positive buffer length",
                        rpc_send_func_name(func));
    }

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    free(tx_buf);

    TEST_END;
}
