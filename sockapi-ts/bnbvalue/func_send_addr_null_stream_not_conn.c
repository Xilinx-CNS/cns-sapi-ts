/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Bad Parameters and Boundary Values
 */

/** @page bnbvalue-func_send_addr_null_stream_not_conn Using NULL pointer as address in sendto()-like functions with not connected SOCK_STREAM socket
 *
 * @objective Check that @b sendto()-like function correctly reports
 *            an error when it is called on not connected @c SOCK_STREAM
 *            socket with @p address parameter equals to @c NULL.
 *
 * @type conformance, robustness
 *
 * @param env       Testing environment:
 *                  - @ref arg_types_env_iut_only
 * @param domain    Socket domain:
 *                  - PF_INET
 *                  - PF_INET6
 * @param addrlen   Pass zero address length if @c TRUE, else - non-zero.
 * @param func      Tested function:
 *                  - sendto
 *                  - sendmsg
 *                  - sendmmsg
 *                  - onload_zc_send
 *
 * @par Scenario:
 * -# Create @p pco_iut socket of type @c SOCK_STREAM on @b pco_iut.
 * -# Call @p func on @p pco_iut socket passing @c NULL as the
 *    value of @a address parameter and zero or size of an appropriate
 *    sockaddr structure as the value of @a address_len parameter.
 * -# Check that the function immediately returns @c -1 and sets
 *    @b errno to @c ENOTCONN.
 *    See @ref bnbvalue_func_send_addr_null_stream_not_conn_1 "note 1".
 * -# Close @p pco_iut socket.
 *
 * @note
 * -# @anchor bnbvalue_func_send_addr_null_stream_not_conn_1
 *    This step is oriented on @ref XNS5 and FreeBSD behaviour, because in
 *    Linux the function sets @b errno to @c EPIPE and sends @c SIGPIPE
 *    signal to the process.
 * -# @anchor bnbvalue_func_send_addr_null_stream_not_conn_2
 *    On FreeBSD @b sendmsg() sets @b errno to @c EINVAL, which is not fit
 *    in the way @b errno is updated by @b sendto() function when it is
 *    used with @c NULL @a address and zero @a address_len parameters (it
 *    returns @c ENOTCONN,
 * -# @anchor bnbvalue_func_send_addr_null_stream_not_conn_3
 *    It is resonable to set a signal handler for @c SIGPIPE signal.
 *
 * @author Oleg Kravtsov <Oleg.Kravtsov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "bnbvalue/func_send_addr_null_stream_not_conn"

#include "sockapi-test.h"


int
main(int argc, char *argv[])
{
    rcf_rpc_server     *pco_iut = NULL;
    rpc_socket_domain   domain;
    te_bool             addrlen;
    rpc_sendto_f        func;

    struct sockaddr    *addr = NULL;
    tarpc_sa           *rpc_sa = NULL;

    int                 iut_socket = -1;

    char   buffer[] = "Test";
    size_t buffer_size = sizeof(buffer);

    DEFINE_RPC_STRUCT_SIGACTION(old_act);
    te_bool                 restore_signal_handler = FALSE;

    rpc_sigset_p    received_set = RPC_NULL;


    TEST_START;

    TEST_GET_PCO(pco_iut);
    TEST_GET_DOMAIN(domain);
    TEST_GET_BOOL_PARAM(addrlen);
    TEST_GET_SENDTO_FUNC(func);
    
    te_fill_buf(buffer, buffer_size);

    /*
     * Here we inilatise signal handler to handle SIGPIPE.
     */
    CHECK_RC(tapi_sigaction_simple(pco_iut, RPC_SIGPIPE,
                                   SIGNAL_REGISTRAR, &old_act));
    restore_signal_handler = TRUE;

    iut_socket = rpc_socket(pco_iut, domain, RPC_SOCK_STREAM, RPC_PROTO_DEF);

    CHECK_NOT_NULL(addr = sockaddr_to_te_af(NULL, &rpc_sa));
    if (addrlen)
        rpc_sa->len = rpc_get_sizeof(pco_iut,
            addr_family_sockaddr_str(sockts_domain2family(domain)));
    
    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = func(pco_iut, iut_socket, buffer, buffer_size, 0, addr);
    if (rc != -1)
    {
        TEST_FAIL("%s() with NULL destination address and %s "
                  "address length called on not connected SOCK_STREAM "
                  "sockets returned %d instead of -1",
                  rpc_sendto_func_name(func),
                  addrlen ? "non-zero" : "0", rc);
    }
    CHECK_RPC_ERRNO(pco_iut, RPC_ENOTCONN,
                    "%s() with NULL destination address and %s address "
                    "length called on not connected SOCK_STREAM sockets "
                    "returned -1", rpc_sendto_func_name(func),
                    addrlen ? "non-zero" : "0");

    /* here we must handle SIGPIPE */
    received_set = rpc_sigreceived(pco_iut);
    rc = rpc_sigismember(pco_iut, received_set, RPC_SIGPIPE);
    if (rc != 0)
    {
        TEST_FAIL("Unexpected signal SIGPIPE after calling %s() "
                  "with NULL destination address and %s "
                  "address length", rpc_sendto_func_name(func),
                  addrlen ? "non-zero" : "0");
    }

    TEST_SUCCESS;

cleanup:

    if (restore_signal_handler)
        CLEANUP_RPC_SIGACTION(pco_iut, RPC_SIGPIPE, &old_act, 
                              SIGNAL_REGISTRAR);

    CLEANUP_RPC_CLOSE(pco_iut, iut_socket);

    free(addr);

    TEST_END;
}
