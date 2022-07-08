/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Bad Parameters and Boundary Values
 */

/** @page bnbvalue-addr_len_inapprop_recv_short Using too short address length value with receiving functions
 *
 * @objective Check that receiving functions allow to pass address length
 *            value that is less than actual size of address structure.
 *
 * @type conformance, robustness
 *
 * @reference @ref XNS5 section 8.1
 *
 * @param env       Testing environment:
 *                  - @ref arg_types_env_peer2peer_all_ipv4_ipv6
 * @param func      Tested function:
 *                  - @ref arg_types_recv_func_with_addr
 * @param zero      If @c TRUE pass @c 0 as address length to the tested
 *                  function.
 * @param null_buf  If @c TRUE pass @c NULL as address pointer to the tested
 *                  function.
 *
 * @note
 * - The test describes steps for @b recvfrom() function, the same steps
 *   should be done for @b recvmsg() and recvmmsg() functions.
 * .
 *
 * @par Scenario:
 *
 * @author Oleg Kravtsov <Oleg.Kravtsov@oktetlabs.ru>
 */

#define TE_TEST_NAME "bnbvalue/addr_len_inapprop_recv_short"

#include "sockapi-test.h"


#define MAX_CONNECTIONS 1


int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;         /* pointer to PCO on IUT */
    rcf_rpc_server *pco_tst = NULL;


    const struct sockaddr *iut_addr = NULL;
    const struct sockaddr *tst_addr = NULL;
    int                    iut_s = -1;
    int                    tst_s = -1;


    char *sender_addr_buf = NULL;
    int   sender_addr_buf_len;

    const char        *func;

    void *tx_data_buf = NULL;
    void *rx_data_buf = NULL;

    socklen_t   sockaddr_size;
    size_t      data_len;
    socklen_t   addr_buf_len = 14;
    socklen_t   len;
    ssize_t     returned_data;

    rpc_socket_domain domain;

    te_bool     zero;
    te_bool     null_buf;

    struct rpc_mmsghdr mmsghdr[1];
    struct rpc_msghdr *msg = &mmsghdr[0].msg_hdr;
    struct rpc_iovec   rx_buf_vec;

    struct tarpc_timespec    timeout = { 1, 0 };

    TEST_START;

    /*
     * Preambule.
     */

    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_BOOL_PARAM(zero);
    TEST_GET_BOOL_PARAM(null_buf);
    TEST_GET_STRING_PARAM(func);

    domain = rpc_socket_domain_by_addr(iut_addr);

    sockaddr_size = sockaddr_get_size_by_domain(domain);

    TEST_STEP("Create @b iut_s socket of type @c SOCK_DGRAM on @p pco_iut "
              "and bind it to a local address.");
    iut_s = rpc_create_and_bind_socket(pco_iut, RPC_SOCK_DGRAM,
                                       RPC_PROTO_DEF, TRUE, FALSE,
                                       SA(iut_addr));
    if (iut_s < 0)
    {
        TEST_FAIL("Cannot create SOCK_DGRAM 'iut_s' socket");
    }

    TEST_STEP("Create @b tst_s socket of type @c SOCK_DGRAM on @p pco_tst.");
    tst_s = rpc_socket(pco_tst, domain, RPC_SOCK_DGRAM, RPC_PROTO_DEF);

    TEST_STEP("Create @p sender_addr_buf buffer of size of an appropriate "
              "@c sockaddr structure.");
    sender_addr_buf_len = sockaddr_size;
    sender_addr_buf = te_make_buf_by_len(sender_addr_buf_len);

    data_len = rand_range(1, 512);
    tx_data_buf = te_make_buf_by_len(data_len);
    rx_data_buf = te_make_buf_by_len(data_len);

    rpc_bind(pco_tst, tst_s, tst_addr);

    addr_buf_len = (zero) ? 0 : addr_buf_len;
    len = addr_buf_len;

    if (strcmp(func, "recvfrom") != 0)
    {
        rx_buf_vec.iov_base = rx_data_buf;
        rx_buf_vec.iov_rlen = rx_buf_vec.iov_len = data_len;

        memset(msg, 0, sizeof(*msg));
        msg->msg_name = (null_buf) ? NULL : SA(sender_addr_buf);
        msg->msg_namelen = len;
        msg->msg_namelen_exact = TRUE;
        msg->msg_rnamelen = (null_buf) ? 0 : sockaddr_size;
        msg->msg_iov = &rx_buf_vec;
        msg->msg_riovlen = msg->msg_iovlen = 1;
    }

    TEST_STEP("Call @p func on @b iut_s, setting address length parameter "
              "to zero if @p zero is @c TRUE or to value smaller than size "
              "of address structure otherwise. If @p null_buf is @c TRUE, "
              "also set address parameter to @c NULL when calling @p func.");
    pco_iut->op = RCF_RPC_CALL;
    if (strcmp(func, "recvfrom") == 0)
    {
        returned_data = rpc_recvfrom_gen(
            pco_iut, iut_s, rx_data_buf, data_len, 0,
            (null_buf) ? NULL : SA(sender_addr_buf),
            &len, data_len,
            (null_buf) ? 0 : sockaddr_size);
    }
    else if (strcmp(func, "recvmsg") == 0)
    {
        returned_data = rpc_recvmsg(pco_iut, iut_s, msg, 0);
    }
    else if (strcmp(func, "onload_zc_recv") == 0)
    {
        returned_data = rpc_simple_zc_recv(pco_iut, iut_s, msg, 0);
    }
    else if (strcmp(func, "onload_zc_hlrx_recv_zc") == 0)
    {
        returned_data = rpc_simple_hlrx_recv_zc(pco_iut, iut_s, msg,
                                                0, TRUE);
    }
    else if (strcmp(func, "onload_zc_hlrx_recv_copy") == 0)
    {
        returned_data = rpc_simple_hlrx_recv_copy(pco_iut, iut_s, msg,
                                                  0, TRUE);
    }
    else
    {
        rpc_recvmmsg_alt(pco_iut, iut_s, mmsghdr, 1, 0, &timeout);
    }

    TEST_STEP("Send some data from @b tst_s socket to @p iut_addr.");
    RPC_SENDTO(rc, pco_tst, tst_s, tx_data_buf, data_len, 0, iut_addr);

    TEST_STEP("Check that @p func call terminated, returning data sent "
              "from Tester.");
    RPC_AWAIT_IUT_ERROR(pco_iut);
    pco_iut->op = RCF_RPC_WAIT;
    if (strcmp(func, "recvfrom") == 0)
    {
        returned_data = rpc_recvfrom_gen(
            pco_iut, iut_s, rx_data_buf, data_len, 0,
            (null_buf) ? NULL : SA(sender_addr_buf),
            &len, data_len,
            (null_buf) ? 0 : sockaddr_size);
    }
    else if (strcmp(func, "recvmsg") == 0)
    {
        returned_data = rpc_recvmsg(pco_iut, iut_s, msg, 0);
    }
    else if (strcmp(func, "onload_zc_recv") == 0)
    {
        returned_data = rpc_simple_zc_recv(pco_iut, iut_s, msg, 0);
    }
    else if (strcmp(func, "onload_zc_hlrx_recv_zc") == 0)
    {
        returned_data = rpc_simple_hlrx_recv_zc(pco_iut, iut_s, msg,
                                                0, TRUE);
    }
    else if (strcmp(func, "onload_zc_hlrx_recv_copy") == 0)
    {
        returned_data = rpc_simple_hlrx_recv_copy(pco_iut, iut_s, msg,
                                                  0, TRUE);
    }
    else
    {
        rpc_recvmmsg_alt(pco_iut, iut_s, mmsghdr, 1, 0, &timeout);
        returned_data = mmsghdr[0].msg_len;
    }

    if (strcmp(func, "recvfrom") != 0)
    {
        len = msg->got_msg_namelen;
        RING("msg_namelen got on remote host: %d", (int)len);
    }

    if (returned_data == -1)
    {
        TEST_VERDICT("%s() with too short peer address buffer "
                     "fails with errno %s", func,
                     errno_rpc2str(RPC_ERRNO(pco_iut)));
    }
    if ((size_t)returned_data != data_len)
    {
        TEST_VERDICT("%s() returned wrong recived data size", func);
    }
    if (memcmp(tx_data_buf, rx_data_buf, data_len) != 0)
    {
        TEST_VERDICT("%s() returned wrong data", func);
    }

    TEST_STEP("Check that @p func has not changed value of address length "
              "parameter.");
    /* recvfrom, recvmsg, recvmmsg calls change value of address length, but
       onload_zc_recv, onload_zc_hlrx_recv_zc and onload_zc_hlrx_recv_copy
       calls - do not. */
    if ( (strncmp(func, "onload_", 7) != 0) && zero && !null_buf)
    {
        if (len == 0)
        {
            TEST_VERDICT("%s() %s size of buffer for peer address", func,
                         "has not changed");
        }
    }
    else if (len != addr_buf_len)
    {
        TEST_VERDICT("%s() %s size of buffer for peer address", func,
                     (len > addr_buf_len) ? "increased" : "changed");
    }

    if (!zero && !null_buf)
    {
        TEST_STEP("Check that @p func updated address parameter up to the "
                  "specified address length to match contents of @p tst_addr.");
        if (te_sockaddrncmp(SA(sender_addr_buf), len, tst_addr, len) != 0)
        {
            TEST_VERDICT("%s() returns incorrect peer address", func);
        }
    }

    TEST_SUCCESS;

cleanup:

    free(sender_addr_buf);
    free(rx_data_buf);
    free(tx_data_buf);

    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);

    TEST_END;
}
