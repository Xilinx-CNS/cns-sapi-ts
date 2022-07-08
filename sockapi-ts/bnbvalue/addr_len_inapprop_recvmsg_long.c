/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Bad Parameters and Boundary Values
 */

/** @page bnbvalue-addr_len_inapprop_recvmsg_long Using a long address length value in recvmsg()-like functions
 *
 * @objective Check that recvmsg()-like functions allow to pass msg_namelen
 *            with value that is greater than actual size of address structure.
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
 * @param len_val   Length of @a msg_namelen field:
 *                  - @c big: the length value is greater than address size,
 *                    but less then double address size;
 *                  - @c large: the length value is greater than
 *                    sockaddr_storage structure size.
 * @param func      Tested function:
 *                  - @ref arg_types_recv_func_with_msg
 *
 * @par Scenario:
 *
 * @author Oleg Kravtsov <Oleg.Kravtsov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "bnbvalue/addr_len_inapprop_recvmsg_long"

#include "sockapi-test.h"

int
main(int argc, char *argv[])
{
    rcf_rpc_server    *pco_iut = NULL;
    rcf_rpc_server    *pco_tst = NULL;
    int                srv_s = -1;
    int                iut_s = -1;
    int                tst_s = -1;
    rpc_socket_type    sock_type;

    const struct sockaddr *iut_addr;
    const struct sockaddr *tst_addr;
    int                    sockaddr_len;
    struct sockaddr       *sender_addr = NULL;
    struct sockaddr       *sender_addr_bkp = NULL;
    socklen_t              sender_addr_len;
    const char            *len_val;

    const char            *func;

    rpc_socket_domain domain;

#define BUF_LEN 10
    unsigned char    tx_buf[BUF_LEN];
    unsigned char    rx_buf[BUF_LEN];
    size_t           buf_len = BUF_LEN;
    struct rpc_iovec iov = {
        rx_buf, buf_len, buf_len
    };

    struct rpc_mmsghdr mmsghdr[] = {
        {
            {
                .msg_name = NULL,
                .msg_namelen = 0,
                .msg_iov = &iov,
                .msg_iovlen = 1,
                .msg_control = NULL,
                .msg_controllen = 0,
                .msg_flags = 0,
                .msg_rnamelen = 0,
                .msg_riovlen = 1,
                .msg_cmsghdr_num = 0,
                .msg_flags_mode = RPC_MSG_FLAGS_SET_CHECK
            },
            .msg_len = 0
        }
    };
    rpc_msghdr  *msg = &mmsghdr[0].msg_hdr;

    struct tarpc_timespec    timeout = { 1, 0 };

    /* Preambule */
    TEST_START;
    TEST_GET_SOCK_TYPE(sock_type);
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);

    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);

    TEST_GET_STRING_PARAM(len_val);

    TEST_GET_STRING_PARAM(func);

    domain = rpc_socket_domain_by_addr(iut_addr);

    sockaddr_len = sockaddr_get_size_by_domain(domain);
    if (sockaddr_len == 0)
    {
        TEST_FAIL("Cannot get size of sockaddr structure for %s domain",
                  domain_rpc2str(domain));
    }

    if (strcmp(len_val, "big") == 0)
    {
        sender_addr_len = sockaddr_len + rand_range(1, sockaddr_len);
    }
    else if (strcmp(len_val, "large") == 0)
    {
        sender_addr_len = sizeof(struct sockaddr_storage);
        sender_addr_len += rand_range(1, sender_addr_len);
    }
    else
    {
        TEST_FAIL("Incorrect value of 'len_val'");
    }

    CHECK_NOT_NULL(sender_addr = (struct sockaddr *)
                                      tapi_calloc(sender_addr_len, 1));
    CHECK_NOT_NULL(sender_addr_bkp =
            (struct sockaddr *)tapi_calloc(sender_addr_len, 1));

    te_fill_buf(sender_addr, sender_addr_len);
    memcpy(sender_addr_bkp, sender_addr, sender_addr_len);

    /* Set msg_name to sender_addr */
    msg->msg_name = sender_addr;
    msg->msg_namelen = sender_addr_len;
    msg->msg_namelen_exact = TRUE;
    msg->msg_rnamelen = msg->msg_namelen;

    TEST_STEP("Create a pair of sockets of type @p sock_type. Bind "
              "IUT socket to @b iut_addr and Tester socket to "
              "@b tst_addr.");

    srv_s = rpc_create_and_bind_socket(pco_iut, sock_type, RPC_PROTO_DEF,
                                       TRUE, FALSE, SA(iut_addr));
    if (srv_s < 0)
    {
        TEST_FAIL("Cannot create 'iut_s' socket of type %s from %s domain",
                  domain_rpc2str(domain), socktype_rpc2str(sock_type));
    }

    tst_s = rpc_socket(pco_tst, domain, sock_type, RPC_PROTO_DEF);
    rpc_bind(pco_tst, tst_s, tst_addr);

    if (sock_type == RPC_SOCK_STREAM)
    {
        TEST_STEP("If TCP sockets are checked, call @b listen() on the IUT "
                  "socket.");
        rpc_listen(pco_iut, srv_s, SOCKTS_BACKLOG_DEF);
    }

    TEST_STEP("Connect Tester socket to @p iut_addr.");
    rpc_connect(pco_tst, tst_s, iut_addr);

    if (sock_type == RPC_SOCK_STREAM)
    {
        TEST_STEP("If TCP sockets are tested, accept connection on IUT "
                  "and work with the accepted socket in the following "
                  "steps.");
        iut_s = rpc_accept(pco_iut, srv_s, NULL, NULL);
        RPC_CLOSE(pco_iut, srv_s);
    }
    else
    {
        iut_s = srv_s;
    }
    srv_s = -1;

    TEST_STEP("Send some data from the Tester socket.");
    te_fill_buf(tx_buf, buf_len);
    RPC_SEND(rc, pco_tst, tst_s, tx_buf, buf_len, 0);

    TEST_STEP("Call @p func on the IUT socket to receive data, passing "
              "@a msg_namelen computed according to @p len_val.");

    RING("msg_namelen passed on IUT is %d", (int)msg->msg_namelen);

    RPC_AWAIT_IUT_ERROR(pco_iut);
    if (strcmp(func, "recvmsg") == 0)
    {
        rc = rpc_recvmsg(pco_iut, iut_s, msg, 0);
    }
    else if (strcmp(func, "onload_zc_recv") == 0)
    {
        rc = rpc_simple_zc_recv(pco_iut, iut_s, msg, 0);
    }
    else if (strcmp(func, "onload_zc_hlrx_recv_zc") == 0)
    {
        rc = rpc_simple_hlrx_recv_zc(pco_iut, iut_s, msg, 0, TRUE);
    }
    else if (strcmp(func, "onload_zc_hlrx_recv_copy") == 0)
    {
        rc = rpc_simple_hlrx_recv_copy(pco_iut, iut_s, msg, 0, TRUE);
    }
    else if (strcmp(func, "recvmmsg") == 0)
    {
        rc = rpc_recvmmsg_alt(pco_iut, iut_s, mmsghdr, 1, 0, &timeout);
        if (rc > 0)
            rc = mmsghdr[0].msg_len;
    }
    else
    {
        TEST_FAIL("Incorrect value of 'func' parameter");
    }

    RING("msg_namelen obtained on IUT is %d", (int)msg->got_msg_namelen);

    TEST_STEP("Check that @p func succeeded and returned expected data.");

    if (rc < 0)
    {
        TEST_VERDICT("%s() fails with %r", func, RPC_ERRNO(pco_iut));
    }
    else if (rc == 0)
    {
        TEST_VERDICT("%s() returns zero", func);
    }
    else if (rc != (int)buf_len)
    {
        ERROR("%s() returns %d, but it is expected to return %d",
              func, rc, (int)buf_len);
        TEST_VERDICT("%s() returns unexpected number of bytes", func);
    }
    else if (memcmp(tx_buf, rx_buf, buf_len) != 0)
    {
        TEST_VERDICT("%s() returns unexpected data", func);
    }

    TEST_STEP("Check that @p func set @a msg_namelen to actual "
              "length of address structure.");
    if (msg->got_msg_namelen != (socklen_t)sockaddr_len)
    {
        if (msg->got_msg_namelen == sender_addr_len)
        {
            TEST_VERDICT("%s() returns success, and does not update "
                         "msg_namelen field of msghdr structure", func);
        }
        else
        {
            TEST_VERDICT("%s() returns success and modifies "
                         "msg_namelen field of msghdr structure to %u",
                         func, (unsigned)msg->msg_namelen);
        }
    }

    TEST_STEP("Check that @p func returned @p tst_addr in @a msg_name.");
    if (te_sockaddrcmp(sender_addr, sockaddr_len,
                       tst_addr, te_sockaddr_get_size(tst_addr)) != 0)
    {
        TEST_VERDICT("The address assigned to 'tst_s' and the address "
                     "obtained with receive function are different");
    }

    TEST_STEP("Check that bytes beyond @a msg_namelen returned by "
              "@p func were not changed.");

    if (memcmp(((void *)sender_addr) + sockaddr_len,
               ((void *)sender_addr_bkp) + sockaddr_len,
               sender_addr_len - sockaddr_len) != 0)
    {
        TEST_VERDICT("%s() function spoils bytes that "
                     "are out of the length returned by it", func);
    }

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_tst, srv_s);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    free(sender_addr);
    free(sender_addr_bkp);

    TEST_END;
}

