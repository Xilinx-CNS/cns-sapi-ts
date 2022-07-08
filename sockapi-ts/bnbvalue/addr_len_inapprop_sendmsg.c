/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Bad Parameters and Boundary Values
 */

/** @page bnbvalue-addr_len_inapprop_sendmsg Using inappropriate address length value in sendmsg(), sendmmsg() or onload_zc_send() functions
 *
 * @objective The test deals with @b sendmsg(), @b sendmmsg() or
 *            @b onload_zc_send() function. It checks that Socket API
 *            functions take into account the value passed in
 *            @a address_len parameter, and report an appropriate
 *            error if it is incorrect.
 *
 * @type conformance, robustness
 *
 * @reference @ref XNS5 section 8.1
 *
 * @param env       Testing environment:
 *                  - @ref arg_types_env_peer2peer_all_ipv4_ipv6
 * @param sock_type Socket type used in the test:
 *                  - SOCK_STREAM
 *                  - SOCK_DGRAM
 * @param conn_func Connect function:
 *                  - connect
 *                  - notconn: don't connect, iterate only with
 *                  @p sock_type = @c SOCK_DGRAM.
 * @param len_val   Length of @a address_len field:
 *                  - small: 4 bytes;
 *                  - big: the length value is greater than address size,
 *                    but not greater than struct sockaddr_storage size;
 *                  - large: the length value is greater than struct
 *                    sockaddr_storage size.
 * @param func      Tested function:
 *                  - @b sendmsg()
 *                  - @b sendmmsg()
 *                  - @b onload_zc_send()
 *                  - @b onload_zc_send_user_buf() (@b onload_zc_send() +
 *                    @b onload_zc_register_buffers())
 *
 * @par Scenario:
 * -# Create @p tst_s socket of type @p sock_type on @p pco_tst.
 * -# Create @p iut_s socket of type @p sock_type on @p pco_iut.
 * -# @b bind() @p tst_s socket to a local address.
 * -# @b bind() @p iut_s socket to a local address.
 * -# If @p sock_type parameter equals to @c SOCK_STREAM,
 *    call @b listen() on  @p tst_s socket.
 * -# If @p conn_func value is not @c notconn call @b connect() on iut_s
 *    socket to connect to tst_addr.
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Call @p func on @p iut_s socket sending some data towards
 *    @p tst_s socket passing @a msg_namelen field of @a message parameter
 *    equals to something that is less than size of an appropriate
 *    @c sockaddr structure.
 * -# Check that the function returns @c -1 and sets @b errno to @c EINVAL.
 *    See @ref bnbvalue_addr_len_inapprop_sendmsg_2 "note 2".
 * -# Call @p func on @p iut_s socket sending some data towards
 *    @p tst_s socket passing @a msg_namelen field of @a message parameter
 *    equals to  something that is more than size of an appropriate
 *    @c sockaddr structure.
 * -# Check that the function returns size of sent data.
 *    See @ref bnbvalue_addr_len_inapprop_sendmsg_1 "note 1".
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Close @p tst_s, and @p iut_s sockets.
 *
 * @note
 * -# @anchor bnbvalue_addr_len_inapprop_sendmsg_1
 *    On FreeBSD systems it is not allowed for @c PF_INET sockets to pass
 *    @a address_len anything but @c sizeof(sockaddr_in).
 *    Functions return @c -1 and set @b errno to @c EINVAL;
 * -# @anchor bnbvalue_addr_len_inapprop_sendmsg_2
 *    On Linux @b sendmsg() with sockets of type @c SOCK_STREAM returns
 *    @c -1 and sets @b errno to @c EPIPE, and the process also receives
 *    SIGPIPE signal.
 *
 * @author Oleg Kravtsov <Oleg.Kravtsov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "bnbvalue/addr_len_inapprop_sendmsg"

#include "sockapi-test.h"

#define MAX_BUF_LEN 300

int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst = NULL;

    rpc_socket_type   sock_type;

    const struct sockaddr *iut_addr;
    int                    iut_s = -1;

    const struct sockaddr *tst_addr;
    int                    tst_s = -1;

    const char             *conn_func;

    struct rpc_msghdr      *msg = NULL;
    ssize_t                 msg_datalen;

    tarpc_ssize_t           sockaddr_size = 0;
    tarpc_ssize_t           storage_size = 0;

    DEFINE_RPC_STRUCT_SIGACTION(old_act);
    te_bool                 restore_signal_handler = FALSE;

    rpc_sigset_p    received_set = RPC_NULL;

    uint8_t addr_buf[MAX_BUF_LEN];

    const char *len_val;

    const char *func;

    unsigned int i;
    te_bool      msg_good = FALSE;

    TEST_START;

    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_SOCK_TYPE(sock_type);
    TEST_GET_STRING_PARAM(conn_func);
    TEST_GET_STRING_PARAM(len_val);
    TEST_GET_STRING_PARAM(func);

    /* msg_name prepared below, msg_control MUST be empty */
    msg_datalen = -1;
    CHECK_NOT_NULL(msg = sockts_make_msghdr(0, -1, &msg_datalen, 0));
    if (strcmp(func, "onload_zc_send") == 0 ||
        strcmp(func, "onload_zc_send_user_buf") == 0)
    {
        while (!msg_good)
        {
            msg_good = TRUE;
            for (i = 0; i < msg->msg_iovlen; i++)
            {
                if (msg->msg_iov[i].iov_base == NULL)
                {
                    sockts_free_msghdr(msg);
                    msg_datalen = -1;
                    CHECK_NOT_NULL(msg = sockts_make_msghdr(0, -1,
                                                            &msg_datalen,
                                                            0));
                    msg_good = FALSE;
                    break;
                }
            }
        }
    }

    /*
     * Preambule.
     */
    CHECK_RC(tapi_sigaction_simple(pco_iut, RPC_SIGPIPE,
                                   SIGNAL_REGISTRAR, &old_act));
    restore_signal_handler = TRUE;
    iut_s = rpc_create_and_bind_socket(pco_iut, sock_type, RPC_PROTO_DEF,
                                       TRUE, FALSE, SA(iut_addr));
    if (iut_s < 0)
    {
        TEST_FAIL("Cannot create 'iut_s' socket of type %s",
                  socktype_rpc2str(sock_type));
    }
    tst_s = rpc_socket(pco_tst, rpc_socket_domain_by_addr(tst_addr),
                       sock_type, RPC_PROTO_DEF);
    rpc_bind(pco_tst, tst_s, tst_addr);

    if (sock_type == RPC_SOCK_STREAM)
    {
        rpc_listen(pco_tst, tst_s, SOCKTS_BACKLOG_DEF);
    }

    if (strcmp(conn_func, "connect") == 0)
    {
        rpc_connect(pco_iut, iut_s, tst_addr);
    }
    else if (strcmp(conn_func, "notconn") != 0)
    {
        TEST_FAIL("Unknown function is testing"); 
    }

    memset(addr_buf, 0, MAX_BUF_LEN);
    msg->msg_name = addr_buf;
    msg->msg_rnamelen = sizeof(addr_buf);
    tapi_sockaddr_clone_exact(tst_addr,
                              (struct sockaddr_storage *)addr_buf);

    sockaddr_size = rpc_get_sizeof(pco_iut,
                        addr_family_sockaddr_str(
                          addr_family_h2rpc(tst_addr->sa_family)));
    storage_size = rpc_get_sizeof(pco_iut, "struct sockaddr_storage");

    msg->msg_namelen_exact = TRUE;
    if (strcmp(len_val, "small") == 0)
    {
        /* Check address length 4 */
        msg->msg_namelen = 4;
    }
    else if (strcmp(len_val, "big") == 0)
    {
        if (sockaddr_size >= storage_size)
        {
            TEST_FAIL("It is expected that address size is less than "
                      "struct sockaddr_storage size");
        }
        msg->msg_namelen = rand_range(sockaddr_size + 1, storage_size);
    }
    else if (strcmp(len_val, "large") == 0)
    {
        msg->msg_namelen = rand_range(storage_size + 1, 2 * storage_size);
    }
    else
    {
        TEST_FAIL("Incorrect value of 'len_val'");
    }

    RPC_AWAIT_ERROR(pco_iut);
    if (strcmp(func, "sendmsg") == 0)
    {
        rc = rpc_sendmsg(pco_iut, iut_s, msg, 0);
    }
    else if (strcmp(func, "sendmmsg") == 0)
    {
        rc = rpc_sendmmsg_as_sendmsg(pco_iut, iut_s, msg, 0);
    }
    else if (strcmp(func, "onload_zc_send") == 0)
    {
        rc = rpc_simple_zc_send(pco_iut, iut_s, msg, 0);
    }
    else if (strcmp(func, "onload_zc_send_user_buf") == 0)
    {
        rc = rpc_simple_zc_send_gen_msg(pco_iut, iut_s, msg, 0,
                                        -1, TRUE);
    }
    else
        TEST_FAIL("Incorrect value of 'func' parameter");

    if (strcmp(len_val, "small") != 0)
    {
        if (rc != msg_datalen)
        {
            if (rc < 0)
            {
                TEST_VERDICT("%s() called with big 'len_val' parameter "
                             "failed with errno " RPC_ERROR_FMT, func,
                             RPC_ERROR_ARGS(pco_iut));
            }
            else
            {
                TEST_FAIL("%s() called with big 'len_val' parameter "
                          "returned %d instead of %d", func, rc, msg_datalen);
            }
        }
        else
            TEST_SUCCESS;
    }

    if (rc != -1)
    {
        if (rc == (int)msg_datalen)
            TEST_VERDICT("%s() called with %s 'len_val' parameter "
                         "returned success instead of expected "
                         "failure(-1)", func, len_val);
        else
            ERROR_VERDICT("%s() called with %s 'len_val' parameter "
                          "returned strange result instead of expected "
                          "failure(-1)", func, len_val);
    }
    else
    {
        CHECK_RPC_ERRNO(pco_iut, RPC_EINVAL,
                        "%s() called with %s 'len_val' parameter "
                        "returned -1", func, len_val);
    }

    if (strcmp(len_val, "small") == 0)
    {
        /* here we must handle SIGPIPE */
        received_set = rpc_sigreceived(pco_iut);
        rc = rpc_sigismember(pco_iut, received_set, RPC_SIGPIPE);
        if (rc != 0)
        {
            TEST_FAIL("Unexpected SIGPIPE after calling %s() with "
                      "too short but msg_namelen", func);
        }
    }

    TEST_SUCCESS;

cleanup:

    if (restore_signal_handler)
        CLEANUP_RPC_SIGACTION(pco_iut, RPC_SIGPIPE, &old_act, 
                              SIGNAL_REGISTRAR);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    msg->msg_name = NULL;
    sockts_free_msghdr(msg);

    TEST_END;
}
