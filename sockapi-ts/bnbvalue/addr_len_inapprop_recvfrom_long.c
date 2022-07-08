/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Bad Parameters and Boundary Values
 */

/** @page bnbvalue-addr_len_inapprop_recvfrom_long Using a long address length value in recvfrom() function
 *
 * @objective Check that @b recvfrom() function allows to pass  @a address_len
 *            parameter with value that is bigger than actual size of address
 *            structure.
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
 * @param len_val   Length of @a address_len field:
 *                  - big: the length value is greater than address size, but
 *                  lesser then double address size;
 *                  - large: the length value is greater than double address
 *                  size.
 *
 * @par Scenario:
 * -# Create @p tst_s socket from of type @p sock_type on @p pco_tst.
 * -# Create @p iut_s socket of type @p sock_type on @p pco_iut.
 * -# Create @p sender_addr buffer whose size is more than 
 *    @c sizeof(struct sockaddr for used address family) bytes.
 * -# Create @p tx_buf buffer of size @p buf_len.
 * -# Create @p rx_buf buffer of size @p buf_len.
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# @b bind() @p iut_s socket to a local address.
 * -# @b bind() @p tst_s socket to a local address.
 * -# The following should be done only on @c SOCK_STREAM sockets:
 *        - Call @b listen() on @p iut_s.
 * -# @b connect() @p tst_s socket to @p iut_s socket.
 * -# The following should be done only on @c SOCK_STREAM sockets:
 *        - Call @b accept() on @p iut_s and get a new @p acc_s socket;
 *        - Close @p iut_s socket;
 *        - rename @p acc_s socket to @p iut_s socket, test works with @p
 *          iut_s socket.
 *        .
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Send @p tx_buf from @p tst_s socket to @p iut_s.
 * -# Set @p len to the length of @p sender_addr buffer.
 * -# Call @b recvfrom(@p iut_s, @p rx_buf, @p buf_len, 0,
 *                     @p sender_addr, @p &len).
 * -# Check that @b recvfrom() function returns @p buf_len.
 * -# Check that the value of @p len is set to 
 *    @c sizeof(struct sockaddr for uaed address family).
 * -# Check that sockaddr returned in @p sender_addr has the same value
 *    as address @p tst_s socket is bound to.
 * -# Check that bytes of @p sender_addr buffer that go after the first 
 *    @c sizeof(struct sockaddr for used address family) bytes are not changed.
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Delete all the buffers created in the test.
 * -# Close @p iut_s and @p tst_s sockets.
 *
 * @author Oleg Kravtsov <Oleg.Kravtsov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "bnbvalue/addr_len_inapprop_recvfrom_long"

#include "sockapi-test.h"

int
main(int argc, char *argv[])
{
    rcf_rpc_server    *pco_iut = NULL;
    rcf_rpc_server    *pco_tst = NULL;
    int                srv_s = -1;
    int                iut_s = -1;
    int                tst_s = -1;

    rpc_socket_type       sock_type;

    const struct sockaddr *iut_addr;
    const struct sockaddr *tst_addr;
    int                    sockaddr_len;
    struct sockaddr       *sender_addr = NULL;
    struct sockaddr       *sender_addr_bkp = NULL;
    socklen_t              sender_addr_len;
    socklen_t              sender_addr_len_s;

#define BUF_LEN 10
    unsigned char    tx_buf[BUF_LEN];
    unsigned char    rx_buf[BUF_LEN];
    size_t           buf_len = BUF_LEN;
    ssize_t          len;
    const char      *len_val;

    rpc_socket_domain domain;

    /* Preambule */
    TEST_START;
    TEST_GET_SOCK_TYPE(sock_type);
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);

    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_STRING_PARAM(len_val);

    domain = rpc_socket_domain_by_addr(iut_addr);

    sockaddr_len = sockaddr_get_size_by_domain(domain);
    if (sockaddr_len == 0)
        TEST_FAIL("Cannot get size of sockaddr structure for %s domain",
                  domain_rpc2str(domain));

    if (strcmp(len_val, "big") == 0)
        sender_addr_len = sockaddr_len + rand_range(1, sockaddr_len);
    else if (strcmp(len_val, "large") == 0)
    {
        sender_addr_len = sizeof(struct sockaddr_storage);
        sender_addr_len += rand_range(1, sender_addr_len);
    }
    else
        TEST_FAIL("Incorrect value of 'len_val'");
    sender_addr_len_s = sender_addr_len;

    sender_addr = te_make_buf_by_len(sender_addr_len);
    CHECK_NOT_NULL(sender_addr_bkp = malloc(sender_addr_len));
    memcpy(sender_addr_bkp, sender_addr, sender_addr_len);

    srv_s = rpc_create_and_bind_socket(pco_iut, sock_type, RPC_PROTO_DEF,
                                       TRUE, FALSE, SA(iut_addr));
    if (srv_s < 0)
    {
        TEST_FAIL("Cannot create 'iut_s' socket of type %s from %s domain",
                  domain_rpc2str(domain), socktype_rpc2str(sock_type));
    }

    if (sock_type == RPC_SOCK_STREAM)
    {
        rpc_listen(pco_iut, srv_s, SOCKTS_BACKLOG_DEF);
    }

    tst_s = rpc_socket(pco_tst, domain, sock_type, RPC_PROTO_DEF);
    rpc_bind(pco_tst, tst_s, tst_addr);

    rpc_connect(pco_tst, tst_s, iut_addr);

    if (sock_type == RPC_SOCK_STREAM)
    {
        iut_s = rpc_accept(pco_iut, srv_s, NULL, NULL);
        RPC_CLOSE(pco_iut, srv_s);
    }
    else
    {
        iut_s = srv_s;
    }
    srv_s = -1;

    /* Now we can start our test */
    te_fill_buf(tx_buf, buf_len);
    RPC_SEND(len, pco_tst, tst_s, tx_buf, buf_len, 0);

    te_fill_buf(rx_buf, buf_len);
    len = rpc_recvfrom(pco_iut, iut_s, rx_buf, buf_len, 0,
                       sender_addr, &sender_addr_len);

    if ((size_t)len != buf_len)
    {
        TEST_FAIL("recvfrom() returns %d, but it is expected to return %d",
                  len, (int)buf_len);
    }
    if (sender_addr_len != (socklen_t)sockaddr_len)
    {
        if (sender_addr_len == sender_addr_len_s)
        {
            ERROR("recvfrom() returns %d, and does not update "
                  "peer address length", len);
            TEST_VERDICT("recvfrom() doesn't update "
                         "peer address length");
        }
        else
        {
            TEST_VERDICT("recvfrom() returns success and modifies to %u "
                         "peer address length value", sender_addr_len);
        }
    }
    if (te_sockaddrcmp(sender_addr, sockaddr_len,
                       tst_addr, te_sockaddr_get_size(tst_addr)) != 0)
    {
        TEST_FAIL("Address assigned on 'tst_s' and obtained "
                  "with recvfrom() function are different");
    }
    if (memcmp(((void *)sender_addr) + sockaddr_len,
               ((void *)sender_addr_bkp) + sockaddr_len,
               sender_addr_len - (socklen_t)sockaddr_len) != 0)
    {
        TEST_FAIL("recvfrom() function spoils bytes that "
                  "are out of the length returned by it");
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


