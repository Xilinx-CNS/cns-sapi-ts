/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Bad Parameters and Boundary Values
 */

/** @page bnbvalue-tx_buf_len_not_connected Using different combinations of buffer and buffer length parameters with transmit functions on not connected socket
 *
 * @objective Check the behaviour of transmit functions on not connected
 *            socket in the following cases:
 *                - zero length and @c NULL buffer;
 *                - zero length and not @c NULL buffer;
 *                - not zero length and @c NULL buffer.
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
 */

#define TE_TEST_NAME  "bnbvalue/tx_buf_len_not_connected"

#include "sockapi-test.h"


#include "sockapi-test.h"

#define TST_BUF_LEN    300

int
main(int argc, char *argv[])
{
    int                err;
    rcf_rpc_server    *pco_iut = NULL;
    rcf_rpc_server    *pco_tst = NULL;
    int                iut_s = -1;
    int                accepted = -1;
    rpc_socket_type    sock_type;
    rpc_send_f         func;
    te_bool            buffer;
    int                buflen;

    const struct sockaddr  *iut_addr;
    void                   *tx_buf = NULL;
    DEFINE_RPC_STRUCT_SIGACTION(old_act);
    te_bool                 restore_signal_handler = FALSE;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_SOCK_TYPE(sock_type);
    TEST_GET_BOOL_PARAM(buffer);
    TEST_GET_INT_PARAM(buflen);
    TEST_GET_SEND_FUNC(func);

    if (strcmp(rpc_send_func_name(func), "template_send") == 0)
        sockts_kill_zombie_stacks(pco_iut);

    if (func == rpc_send_func_onload_zc_send ||
        func == rpc_send_func_onload_zc_send_user_buf)
    {
        TEST_VERDICT("onload_zc_send() checking is not supported");
    }

    if (buffer && (buflen != 0))
        TEST_FAIL("Untested combination of the test parameters: "
                  "buffer pointer is not NULL and buffer length is not 0");

    if (buffer)
        tx_buf = te_make_buf_by_len(TST_BUF_LEN);
    else
        tx_buf = NULL;

    TEST_STEP("Create @p iut_s socket of type @p sock_type.");
    iut_s = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr),
                       sock_type, RPC_PROTO_DEF);

    /*
     * Register SIGPIPE signal hander for the case some
     * functions generate it
     */
    CHECK_RC(tapi_sigaction_simple(pco_iut, RPC_SIGPIPE,
                                   SIGNAL_REGISTRAR, &old_act));
    restore_signal_handler = TRUE;

    TEST_STEP("Call @p func on @p iut_s socket passing (@c NULL, @c 0) as "
              "destination address and @p buf as the value of:\n"
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
              "    - @a iov_len field of @a iovec parameter for "
              "@b writev().");
    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = func(pco_iut, iut_s, tx_buf, buflen, 0);
    err = RPC_ERRNO(pco_iut);

    TEST_STEP("Check the result of the @p func function calling:");
    TEST_SUBSTEP("If @p buflen is zero, check that the function returns "
                 "@c -1 and sets @b errno to @c ENOTCONN;");
    if (buflen == 0)
    {
        if (rc != -1)
        {
            TEST_VERDICT("%s() function returns %d sending zero length "
                         "buffer on not connected socket instead of -1",
                         rpc_send_func_name(func), rc);
        }
        if (err == RPC_ENOTCONN || err == RPC_EDESTADDRREQ ||
            err == RPC_E_UNEXP_NET_ERR || err == RPC_EFAULT)
        {
            RING("%s() function called with %s NULL buffer and "
                 "zero buffer length returns -1 and sets "
                 "errno to %s", rpc_send_func_name(func),
                 buffer == TRUE ? "not" : "", errno_rpc2str(err));
        }
        else
        {
            TEST_VERDICT("%s() function called with %s NULL buffer and "
                         "zero buffer length returns -1, and sets errno "
                         "to %s instead of ENOTCONN or EDESTADDRREQ",
                         rpc_send_func_name(func),
                         buffer == TRUE ? "not" : "", errno_rpc2str(err));
        }
    }

    TEST_SUBSTEP("If @p buflen is not zero and @p buf is @c NULL, check that "
                 "the function returns @c -1 and sets @b errno to @c EFAULT "
                 "or @c ENOTCONN.");
    if ((buffer == FALSE) && (buflen > 0))
    {
        if (rc != -1)
        {

            TEST_FAIL("%s() function called with NULL buffer and "
                      "not zero buffer length returns %d instead of -1",
                      rpc_send_func_name(func), rc);
        }
        if (err == RPC_EFAULT ||
            err == RPC_ENOTCONN || err == RPC_EDESTADDRREQ ||
            err == RPC_E_UNEXP_NET_ERR || err == RPC_EFAULT)

        {
            RING("%s() function called with NULL buffer and "
                 "not zero buffer length returns -1 and sets "
                 "errno to %s", rpc_send_func_name(func), errno_rpc2str(err));
        }
        else
        {
            TEST_VERDICT("%s() function called with NULL buffer and "
                         "not zero buffer length returns -1, and sets "
                         "errno to %s, but it is expected to be "
                         "EFAULT, ENOTCONN, or EDESTADDRREQ",
                         rpc_send_func_name(func), errno_rpc2str(err));
        }
    }

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, accepted);

    if (restore_signal_handler)
        CLEANUP_RPC_SIGACTION(pco_iut, RPC_SIGPIPE, &old_act,
                              SIGNAL_REGISTRAR);

    free(tx_buf);

    TEST_END;
}
