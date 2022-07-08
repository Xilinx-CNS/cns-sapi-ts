/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Socket options
 * 
 * $Id$
 */

/** @page sockopts-broadcast Usage of SO_BROADCAST socket option
 *
 * @objective Check that it is allowed to send broadcast messages from
 *            connectionless socket only if @c SO_BROADCAST socket option
 *            is enabled on it.
 *
 * @type conformance
 *
 * @reference MAN 7 socket
 *
 * @note Broadcasting is supported for only datagram sockets and only on 
 *       networks that support the concept of a broadcast messages.
 * 
 * @param pco_iut           PCO on IUT
 * @param pco_tst           PCO on TESTER
 * @param bcast_addr        Broadcast address assigned on @p pco_iut interface
 *                          connected to the same subnetwork as @p pco_tst
 * 
 * @par Test sequence:
 *
 * -# Create @p iut_s socket of type @c SOCK_DGRAM  on @p pco_iut.
 * -# Create @p tst_s socket of type @c SOCK_DGRAM on @p pco_tst.
 * -# Create a buffer @p tx_buf1 of @p tx_buf1_len bytes.
 * -# Create a buffer @p tx_buf2 of @p tx_buf2_len bytes.
 * -# Create a buffer @p rx_buf of @p tx_buf1_len + @p tx_buf2_len bytes.
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Call @b getsockopt() on @p iut_s socket to get initial value of the
 *    option.
 * -# Check that the function returns @c 0 and the option is disabled.
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Call @b sendto() on @p iut_s to send @p tx_buf1 buffer specifying 
 *    @p iut_bcast_addr as the value of @a address parameter.
 * -# Check that the function returns @c -1 and sets @b errno to @c EACCES.
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Call @b setsockopt() on @p iut_s with @c SO_BROADCAST enabling 
 *    this option.
 * -# Call @b sendto() on @p iut_s to send @p tx_buf2 buffer specifying 
 *    @p iut_bcast_addr as the value of @a address parameter.
 * -# Check that the function returns @p tx_buf2_len.
 * -# Call @b recv(@b tst_s, @p rx_buf, @p tx_buf1_len + @p tx_buf2_len, @a 0).
 * -# Check that the function returns @p tx_buf2_len and fills in first 
 *    @p tx_buf2_len of @p dst_buf buffer with the content of 
 *    @p tx_buf2 buffer, and does not update the rest @p tx_buf1_len 
 *    bytes of the buffer.
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Call @b setsockopt() on @p iut_s with @c SO_BROADCAST disabling
 *    this option.
 * -# Call @b sendto() on @p iut_s to send @p tx_buf1 buffer specifying
 *    @p iut_bcast_addr as the value of @a address parameter.
 * -# Check that the function returns @c -1 and sets @b errno to @c EACCES.
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Delete @p rx_buf, @p tx_buf2, @p tx_buf1 buffers.
 * -# Close @p tst_s, @p iut_s sockets.
 * 
 * @author Oleg Kravtsov <Oleg.Kravtsov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "sockopts/broadcast"

#include "sockapi-test.h"


int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst = NULL;
    int             iut_s = -1;
    int             tst_s = -1;

    const struct sockaddr   *bcast_addr;
    struct sockaddr_storage  tst_wildcard_addr;
    void                    *tx_buf1 = NULL;
    size_t                   tx_buf1_len;
    void                    *tx_buf2 = NULL;
    size_t                   tx_buf2_len;
    void                    *rx_buf = NULL;
    int                      opt_val;
    
    rpc_socket_domain domain;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);

    TEST_GET_ADDR(pco_tst, bcast_addr);
    
    domain = rpc_socket_domain_by_addr(bcast_addr);

    CHECK_NOT_NULL(tx_buf1 = sockts_make_buf_dgram(&tx_buf1_len));
    CHECK_NOT_NULL(tx_buf2 = sockts_make_buf_dgram(&tx_buf2_len));
    rx_buf = te_make_buf_by_len(tx_buf1_len + tx_buf2_len);

    iut_s = rpc_socket(pco_iut, domain, RPC_SOCK_DGRAM, RPC_PROTO_DEF);
    tst_s = rpc_socket(pco_tst, domain, RPC_SOCK_DGRAM, RPC_PROTO_DEF);

    /* 
     * We need to bind on the port used in outgoing broadcast datagrams, so
     * that we just copy the whole bcast_addr, and then set network address
     * to wildcard.
     */
    memcpy(&tst_wildcard_addr, bcast_addr, te_sockaddr_get_size(bcast_addr));
    te_sockaddr_set_wildcard(SA(&tst_wildcard_addr));
    rpc_bind(pco_tst, tst_s, SA(&tst_wildcard_addr));

    rpc_getsockopt(pco_iut, iut_s, RPC_SO_BROADCAST, &opt_val);
    if (opt_val != 0)
    {
        WARN("SO_BROADCAST socket option is enabled by default");

        opt_val = 0;
        rpc_setsockopt(pco_iut, iut_s, RPC_SO_BROADCAST, &opt_val);
    }

    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_sendto(pco_iut, iut_s, tx_buf1, tx_buf1_len, 0, bcast_addr);
    if (rc != -1)
    {
        ERROR("sendto() returns %d sending datagram towards broadcast "
              "address on socket with disabled SO_BROADCAST socket ", rc);
        TEST_VERDICT("sendto() returns positive number sending datagram towards broadcast "
                     "address on socket with disabled SO_BROADCAST socket "
                     "option, but it is expected to return -1");
    }
    CHECK_RPC_ERRNO(pco_iut, RPC_EACCES,
            "sendto() returns -1 sending datagram towards broadcast "
            "address on socket with disabled SO_BROADCAST socket");
    
    /* Enable SO_BROADCAST option on 'iut_s' socket */
    opt_val = 1;
    rpc_setsockopt(pco_iut, iut_s, RPC_SO_BROADCAST, &opt_val);

    /* 
     * Set different value to the 'opt_val' to ensure that 
     * it is updated by getsockopt()
     */
    opt_val = 0;
    rpc_getsockopt(pco_iut, iut_s, RPC_SO_BROADCAST, &opt_val);
    if (opt_val != 1)
    {
        TEST_FAIL("The value of SO_BROADCAST socket option is not updated "
                  "by setsockopt() function");
    }

    rc = rpc_sendto(pco_iut, iut_s, tx_buf2, tx_buf2_len, 0, bcast_addr);
    if (rc != (int)tx_buf2_len)
    {
        VERB("sendto() returns %d sending datagram towards broadcast "
             "address on socket with enabled SO_BROADCAST socket "
             "option, but it is expected to return %d", rc, tx_buf2_len);
        TEST_FAIL("sendto() transmits only some part of datagram towards "
                  "broadcast address on socket with enabled SO_BROADCAST "
                  "socket option");
    }

    rc = rpc_recv(pco_tst, tst_s, rx_buf, tx_buf1_len + tx_buf2_len, 0);
    if (rc != (int)tx_buf2_len)
    {
        VERB("'tst_s' socket is expected to receive %d bytes "
             "of data from 'iut_s', but it receives %d bytes",
             (int)tx_buf2_len, rc);
        TEST_FAIL("'tst_s' socket received only part of data");
    }
    if (memcmp(rx_buf, tx_buf2, tx_buf2_len) != 0)
    {
        VERB("First %d bytes of 'rx_buf' are not the same as "
             "the content of 'tx_buf2' buffer", tx_buf2_len);
        TEST_FAIL("'rx_buf' and 'tx_buf2' are not the same after transmission");
    }

    /* Check that the is no more data to read on 'tst_s' socket */
    RPC_CHECK_READABILITY(pco_tst, tst_s, FALSE);

    /* Disable SO_BROADCAST option on 'iut_s' socket */
    opt_val = 0;
    rpc_setsockopt(pco_iut, iut_s, RPC_SO_BROADCAST, &opt_val);

    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_sendto(pco_iut, iut_s, tx_buf1, tx_buf1_len, 0, bcast_addr);
    if (rc != -1)
    {
        TEST_FAIL("sendto() returns %d sending datagram towards broadcast "
                  "address on socket with disabled SO_BROADCAST socket "
                  "option, but it is expected to return -1", rc);
    }
    CHECK_RPC_ERRNO(pco_iut, RPC_EACCES,
                    "sendto() returns -1 sending datagram towards broadcast "
                    "address on socket with disabled SO_BROADCAST socket");

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    free(tx_buf1);
    free(tx_buf2);
    free(rx_buf);

    TEST_END;
}
 
