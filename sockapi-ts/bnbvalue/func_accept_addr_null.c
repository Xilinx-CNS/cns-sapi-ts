/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Bad Parameters and Boundary Values
 */

/** @page bnbvalue-func_accept_addr_null Using NULL pointer as address in accept() function
 *
 * @objective Check that @b accept() function correctly handles
 *            situation with passing @c NULL pointer as the value
 *            of @a address and @a address_len parameters.
 *
 * @type conformance, robustness
 *
 * @reference @ref XNS5 section 8.1
 *
 * @param env       Testing environment:
 *                  - @ref arg_types_env_peer2peer_all_ipv4_ipv6
 * @param use_wildcard  Bind IUT socket to @c INADDR_ANY if @c TRUE.
 *
 * @pre
 *    Create a server socket on @p pco_iut:
 *    -# Create @p pco_iut socket of type @c SOCK_STREAM on @p pco_iut.
 *    -# @b bind() @p pco_iut socket to a local address.
 *    -# Call @b listen() on @p pco_iut socket.
 *
 * @post
 *    Close @p pco_iut socket
 *
 * @par Scenario:
 * -# Call @b accept() on @p pco_iut socket passing @c NULL pointer as
 *    @a address value and size of an appropriate address structure
 *    as the value of @a address_len parameter.
 * -# Check that the function immediately returns @c -1 and sets
 *    @b errno to @c EFAULT.
 * -# Call @b accept() on @p pco_iut socket passing @c non-NULL pointer
 *    as @a address value and @c NULL pointer as @a address_len value.
 * -# Check that the function immediately returns @c -1 and sets 
 *    @b errno to @c EFAULT.
 *    See @ref bnbvalue_func_accept_addr_null_1 "note 1".
 *
 * @note
 * -# @anchor bnbvalue_func_accept_addr_null_1
 *    This step is oriented on FreeBSD behaviour, because Linux blocks
 *    the call waiting for incoming connection, and only after one comes
 *    it returns @c EFAULT;
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 * @author Oleg Kravtsov <Oleg.Kravtsov@oktetlabs.ru>
 */

#define TE_TEST_NAME "bnbvalue/func_accept_addr_null"

#include "sockapi-test.h"


#define TEST_SLEEP  1


int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst = NULL;

    const struct sockaddr *iut_addr;
    int                    iut_s = -1;
    int                    tst_s1 = -1;
    int                    tst_s2 = -1;

    struct sockaddr_storage     peer_addr;
    socklen_t                   peer_addrlen;

    te_bool is_done = FALSE;
    te_bool step_fail = FALSE;
    te_bool use_wildcard = FALSE;

    rpc_socket_domain domain;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_BOOL_PARAM(use_wildcard);

    domain = rpc_socket_domain_by_addr(iut_addr);

    tst_s1 = rpc_socket(pco_tst, domain, RPC_SOCK_STREAM, RPC_PROTO_DEF);
    tst_s2 = rpc_socket(pco_tst, domain, RPC_SOCK_STREAM, RPC_PROTO_DEF);
    iut_s = rpc_create_and_bind_socket(pco_iut, RPC_SOCK_STREAM,
                                       RPC_PROTO_DEF, use_wildcard, TRUE,
                                       iut_addr);
    rpc_listen(pco_iut, iut_s, SOCKTS_BACKLOG_DEF);

    pco_iut->op = RCF_RPC_CALL;
    peer_addrlen = sizeof(struct sockaddr_storage);
    rpc_accept(pco_iut, iut_s, NULL, &peer_addrlen);
    SLEEP(TEST_SLEEP);

    CHECK_RC(rcf_rpc_server_is_op_done(pco_iut, &is_done));

    if (!is_done)
    {
        ERROR_VERDICT("accept(..., NULL, != NULL) waits for "
                      "connection");
        step_fail = TRUE;

        rpc_connect(pco_tst, tst_s1, iut_addr);
        SLEEP(TEST_SLEEP);

        CHECK_RC(rcf_rpc_server_is_op_done(pco_iut, &is_done));

        if (!is_done)
        {
            ERROR_VERDICT("accept(..., NULL, != NULL) seems "
                          "to be blocking infinitely");
            rcf_rpc_server_restart(pco_iut);
            iut_s = rpc_create_and_bind_socket(pco_iut, RPC_SOCK_STREAM,
                                               RPC_PROTO_DEF, use_wildcard,
                                               TRUE, iut_addr);
            rpc_listen(pco_iut, iut_s, SOCKTS_BACKLOG_DEF);
        }
    }

    if (is_done)
    {
        pco_iut->op = RCF_RPC_WAIT;
        RPC_AWAIT_IUT_ERROR(pco_iut);
        peer_addrlen = sizeof(struct sockaddr_storage);
        rc = rpc_accept(pco_iut, iut_s, NULL, &peer_addrlen);
        if (rc != -1)
        {
            ERROR_VERDICT("accept() called with NULL pointer passing as the "
                          "address parameter returned success instead of "
                          "expected failure with EFAULT errno");
            step_fail = TRUE;
        }
        else
        {
            CHECK_RPC_ERRNO(pco_iut, RPC_EFAULT,
                            "accept() called with NULL pointer passing as the "
                            "adress parameter returned -1");
        }
    }

    pco_iut->op = RCF_RPC_CALL;
    rpc_accept_gen(pco_iut, iut_s, SA(&peer_addr), NULL, sizeof(peer_addr));
    SLEEP(TEST_SLEEP);

    CHECK_RC(rcf_rpc_server_is_op_done(pco_iut, &is_done));

    if (!is_done)
    {
        ERROR_VERDICT("accept(..., != NULL, NULL) waits for "
                      "connection");
        step_fail = TRUE;

        rpc_connect(pco_tst, tst_s2, iut_addr);
        SLEEP(TEST_SLEEP);

        CHECK_RC(rcf_rpc_server_is_op_done(pco_iut, &is_done));

        if (!is_done)
        {
            ERROR_VERDICT("accept(..., != NULL, NULL) seems "
                          "to be blocking infinitely");
            iut_s = -1;
        }
    }

    if (is_done)
    {
        pco_iut->op = RCF_RPC_WAIT;
        RPC_AWAIT_IUT_ERROR(pco_iut);
        rc = rpc_accept_gen(pco_iut, iut_s, SA(&peer_addr), NULL,
                            sizeof(peer_addr));
        if (rc != -1)
        {
            ERROR_VERDICT("accept() called with NULL pointer passing as the "
                          "address length parameter returned success instead "
                          "of expected failure with EFAULT errno");
            step_fail = TRUE;
        }
        else
        {
            CHECK_RPC_ERRNO(pco_iut, RPC_EFAULT,
                            "accept() called with NULL pointer passing as the "
                            "adress length parameter returned -1");
        }
    }

    if (!step_fail)
        TEST_SUCCESS;
    else
        TEST_STOP;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s1);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s2);

    TEST_END;
}
