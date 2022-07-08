/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Socket options
 *
 * $Id$
 */

/** @page sockopts-bindtodevice_dgram Usage of SO_BINDTODEVICE socket option with socket of type SOCK_DGRAM
 *
 * @objective Check that if a socket is bound to an interface with 
 *            @c SO_BINDTODEVICE socket option, only packets received 
 *            from that particular interface are processed by the socket.
 *
 * @type conformance
 *
 * @reference MAN 7 socket
 *
 * @note To perform this test @p pco_iut should have at least two 
 * network interfaces.
 *
 * @param pco_iut       PCO on IUT
 * @param pco_tst1      PCO on TESTER1
 * @param iut_if1       Name of a network interface on @p pco_iut that 
 *                      connected to the same subnetwork as @p pco_tst1
 * @param pco_tst2      PCO on TESTER2
 * @param iut_if2       Name of a network interface on @p pco_iut that 
 *                      connected to the same subnetwork as @p pco_tst2
 *
 * @htmlonly

  <pre>

  +----------------+   +----- NET 1 ----- { pco_tst1 }
  |        iut_if1+|---+
  | IUT            |
  |        iut_if2+|---+
  +----------------+   +----- NET 2 ----- { pco_tst2 }

  </pre>

  @endhtmlonly
 *
 *
 * @par Test sequence:
 *
 * -# Create datagram sockets: @p iut_s on @p pco_iut,
 *    @p tst1_s on @p pco_tst1, and @p tst2_s on @p pco_tst2.
 * -# Obtain an address @p iut_addr1 of @p iut_if1 interface.
 * -# Obtain an address @p iut_addr2 of @p iut_if2 interface.
 * -# Create buffers: @p tst1_buf of @p tst1_buf_len bytes,
 *    @p tst2_buf of @p tst2_buf_len bytes, and 
 *    @b local_buf of @b tst1_buf_len + @b tst2_buf_len bytes.
      \n @htmlonly &nbsp; @endhtmlonly
 * -# Bind @p iut_s socket to wildcard network address and a particular 
 *    port @p P.
 * -# Check that attempt to get initial value of @c SO_BINDTODEVICE option
 *    fails with @b errno = @c ENOPROTOOPT.
 *    See @ref sockopts_bindtodevice_dgram_1 "note 1".
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Bind @p iut_s socket to @p iut_if1 network interface.
 * -# Send @p tst2_buf buffer from @p tst2_s socket (over "NET 2" network).
 * -# Send @p tst1_buf buffer from @p tst1_s socket (over "NET 1" network).
 * -# Call @b recv(@a iut_s, @a local_buf, 
 *                 @p tst1_buf_len + @p tst2_buf_len, @c 0).
 * -# Check that @b recv() function returns @p tst1_buf_len and fills in 
 *    first @p tst1_buf_len bytes of buffer with data of @p tst1_buf buffer.
 *    Check that the rest @b tst2_buf_len bytes of data is not updated.
 * -# Check that @p iut_s socket is not readable (data sent from @p tst2_s
 *    socket is not accepted by @p iut_s socket).
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Remove @p iut_s device binding.
 * -# Send @p tst2_buf buffer from @p tst2_s socket (over "NET 2" network).
 * -# Send @p tst1_buf buffer from @p tst1_s socket (over "NET 1" network).
 * -# Call @b recv(@p iut_s, @p local_buf, 
 *                 @p tst1_buf_len + @p tst2_buf_len, @c 0).
 * -# Check that @b recv() function returns @p pco_tst2 and fills in first 
 *    @p tst2_buf_len bytes of @p local_buf buffer with data of @p tst2_buf
 *    buffer and the rest @p tst1_buf_len bytes are not updated.
 * -# Call @b recv(@p iut_s, @p local_buf, 
 *                 @p tst1_buf_len + @p tst2_buf_len, @c 0).
 * -# Check that @b recv() function returns @p tst1_buf_len and fills in
 *    first @p tst1_buf_len bytes of buffer with data of @p tst1_buf buffer 
 *    and the rest @p tst2_buf_len bytes are not updated.
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Bind @p iut_s socket to @p iut_if2 network interface.
 * -# Send @p tst2_buf buffer from @p tst2_s socket (over "NET 2" network).
 * -# Send @p tst1_buf buffer from @p tst1_s socket (over "NET 1" network).
 * -# Call @b recv(@p iut_s, @p local_buf, 
 *                 @p tst1_buf_len + @p tst2_buf_len, @c 0).
 * -# Check that @b recvfrom() function returns @p tst2_buf_len and 
 *    fills in first @p tst2_buf_len bytes of buffer with data of 
 *    @p tst2_buf buffer, and the rest @p tst1_buf_len bytes of data is 
 *    not updated.
 * -# Check that @p iut_s socket is not readable (data sent from @p tst1_s
      socket is not accepted by @p iut_s socket).
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Call @b setsockopt() on @b iut_s with @c SO_BINDTODEVICE specifying 
 *    zero as the value of the option length (to remove the socket device 
 *    binding).
 * -# Repeat steps 19 - 24.
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Delete @p local_buf, @p tst2_buf, @p tst1_buf buffers.
 * -# Close @p tst2_s, @p tst1_s, @p iut_s sockets.
 *
 * @note
 * -# @anchor sockopts_bindtodevice_dgram_1
 *    On some systems it is allowed to get the value of @c SO_BINDTODEVICE
 *    socket option, but on Linux it is not supported yet.
 *
 * @author Oleg Kravtsov <Oleg.Kravtsov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "sockopts/bindtodevice_dgram"

#include "sockapi-test.h"
#include "vlan_common.h"

/* Empty string */
#define EMPTY_STRING ""
#define GARBAGE_STRING "BEEFBEEFBEEFBEEF"

int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut  = NULL;
    rcf_rpc_server *pco_tst1 = NULL;
    rcf_rpc_server *pco_tst2 = NULL;
    int             iut_s  = -1;
    int             tst1_s = -1;
    int             tst2_s = -1;

    const struct sockaddr     *iut_addr1;
    const struct if_nameindex *iut_if1;
    const struct sockaddr     *iut_addr2;
    const struct if_nameindex *iut_if2;
    const struct sockaddr     *tst1_addr;
    const struct sockaddr     *tst2_addr;
    struct sockaddr_storage    peer_addr;
    socklen_t                  peer_addrlen = sizeof(peer_addr);
    struct sockaddr_storage    aux_addr;
    socklen_t                  aux_addrlen;
    uint16_t                   iut_port;

    void     *tst1_buf = NULL;
    size_t    tst1_buf_len;
    void     *tst2_buf = NULL;
    size_t    tst2_buf_len;
    void     *local_buf = NULL;
    
    char         opt_val[IFNAMSIZ];
    int          opt_error;
    socklen_t    opt_len;

    peer_name_t peer_names[] = {{(struct sockaddr **)&tst1_addr,
                                 "address on TESTER1 interface"},
                                {(struct sockaddr **)&tst2_addr,
                                 "address on TESTER2 interface"},
                                {NULL, NULL}};
    /* Preambule */
    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst1);
    TEST_GET_PCO(pco_tst2);

    TEST_GET_ADDR(pco_iut, iut_addr1);
    TEST_GET_IF(iut_if1);
    TEST_GET_ADDR(pco_iut, iut_addr2);
    TEST_GET_IF(iut_if2);
    TEST_GET_ADDR(pco_tst1, tst1_addr);
    TEST_GET_ADDR(pco_tst2, tst2_addr);

    assert(sizeof(aux_addr) >= te_sockaddr_get_size(iut_addr1));
    assert(sizeof(aux_addr) >= te_sockaddr_get_size(iut_addr2));

    iut_port = te_sockaddr_get_port(iut_addr1);

    CHECK_NOT_NULL(tst1_buf = sockts_make_buf_dgram(&tst1_buf_len));
    CHECK_NOT_NULL(tst2_buf = sockts_make_buf_dgram(&tst2_buf_len));
    CHECK_NOT_NULL(local_buf = 
            te_make_buf_by_len(tst1_buf_len + tst2_buf_len));

    iut_s = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr1), 
                       RPC_SOCK_DGRAM, RPC_PROTO_DEF);
    tst1_s = rpc_socket(pco_tst1, rpc_socket_domain_by_addr(tst1_addr), 
                        RPC_SOCK_DGRAM, RPC_PROTO_DEF);
    tst2_s = rpc_socket(pco_tst2, rpc_socket_domain_by_addr(tst2_addr), 
                        RPC_SOCK_DGRAM, RPC_PROTO_DEF);

    rpc_bind(pco_tst1, tst1_s, tst1_addr);

    aux_addrlen = te_sockaddr_get_size(iut_addr1);
    memcpy(&aux_addr, iut_addr1, aux_addrlen);
    te_sockaddr_set_port(SA(&aux_addr), iut_port);
    rpc_connect(pco_tst1, tst1_s, SA(&aux_addr));

    rpc_bind(pco_tst2, tst2_s, tst2_addr);
    
    aux_addrlen = te_sockaddr_get_size(iut_addr2);
    memcpy(&aux_addr, iut_addr2, aux_addrlen);
    te_sockaddr_set_port(SA(&aux_addr), iut_port);
    rpc_connect(pco_tst2, tst2_s, SA(&aux_addr));


    /* 
     * Bind @p iut_s socket to wildcard network address and 
     * a particular port @p P;
     */
    aux_addrlen = te_sockaddr_get_size(iut_addr1);
    memcpy(&aux_addr, iut_addr1, te_sockaddr_get_size(iut_addr1));
    te_sockaddr_set_wildcard(SA(&aux_addr));
    rpc_bind(pco_iut, iut_s, SA(&aux_addr));

    /*
     * Fill in opt_val with some garb to be sure that it is 
     * not filled in with zero bytes.
     */
    snprintf(opt_val, sizeof(opt_val), GARBAGE_STRING);
    opt_len = sizeof(opt_val);
    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_getsockopt_gen(pco_iut, iut_s, RPC_SOL_SOCKET,
                            RPC_SO_BINDTODEVICE, NULL, opt_val,
                            &opt_len, opt_len);
    if (rc == -1)
    {
        CHECK_RPC_ERRNO(pco_iut, RPC_ENOPROTOOPT,
                "getsockopt(SOL_SOCKET, SO_BINDTODEVICE) returns -1");

        RING("getsockopt(SOL_SOCKET, SO_BINDTODEVICE) is not supported");
    }
    else if (rc == 0)
    {
        /* 
         * Some systems allow using SO_BINDTODEVICE with 
         * getsockopt() function 
         */
        RING("getsockopt(SOL_SOCKET, SO_BINDTODEVICE) is supported");
        
        /* Check that option_val is an empty string */
        if (opt_len != 0 && strcmp(opt_val, "") != 0)
        {
            TEST_FAIL("getsockopt(SOL_SOCKET, SO_BINDTODEVICE) is "
                      "supported, but on a socket that has not been bound "
                      "to any interface the value of the option is '%s', "
                      "but it is expected to be an empty string", opt_val);
        }
        
        if (opt_len == 0 || opt_len == 1)
        {
            RING("getsockopt(SOL_SOCKET, SO_BINDTODEVICE) is supported "
                 "and the length of the option whose value is an empty "
                 "string is updated to '%d'", opt_len);
        }
        else
        {
            TEST_FAIL("getsockopt(SOL_SOCKET, SO_BINDTODEVICE) is supported "
                      "and the option value on a socket that has not been "
                      "bound to any interface equals to an empty string, "
                      "and it is set option length parameter to %d, but "
                      "it is expected to be 0 or 1");
        }
    }
    else
    {
        TEST_FAIL("getsockopt(SOL_SOCKET, SO_BINDTODEVICE) returns %d, "
                  "but it is expected to return -1 or 0", rc);
    }

    
    /* Major step: Bind the socket to the interface connected to NET1 */
    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_setsockopt_raw(pco_iut, iut_s, RPC_SO_BINDTODEVICE,
                            iut_if1->if_name, (strlen(iut_if1->if_name) + 1));
    if (rc != 0)
    {
        TEST_VERDICT("setsockopt(SO_BINDTODEVICE) failed with errno %s",
                     errno_rpc2str(RPC_ERRNO(pco_iut)));
    }
    TAPI_WAIT_NETWORK;

    RPC_SEND(rc, pco_tst2, tst2_s, tst2_buf, tst2_buf_len, 0);
    MSLEEP(10);
    RPC_SEND(rc, pco_tst1, tst1_s, tst1_buf, tst1_buf_len, 0);
    TAPI_WAIT_NETWORK;
    
    rc = rpc_recvfrom(pco_iut, iut_s, local_buf, tst1_buf_len +
                      tst2_buf_len, 0, SA(&peer_addr), &peer_addrlen);
    
    CHECK_RETURNED_LEN(rc, tst1_buf_len, SA(&peer_addr), tst1_addr,
                       TEST_VERDICT, TEST_VERDICT, peer_names, NULL,
                       NULL, "IUT socket");
    RPC_CHECK_READABILITY(pco_iut, iut_s, FALSE);

    rpc_getsockopt(pco_tst2, tst2_s, RPC_SO_ERROR, &opt_error);
    RING("Attempt to send data to peer bound to another interface "
         "returns error (SO_ERROR) %s", errno_rpc2str(opt_error));
    if (opt_error != 0 && opt_error != RPC_ECONNREFUSED)
    {
        TEST_FAIL("Unexpected error %s occured on 'tst2_s' socket, "
                  "but expected 0 or ECONNREFUSED",
                  errno_rpc2str(opt_error));
    }


    /* Major step: Unbind the socket using an empty string */
#if 1
    /* 
     * On Linux there is a bug that does not allow to have option_len 
     * less than sizeof(int), which is 4.
     */
    memset(opt_val, '\0', sizeof(opt_val));
    opt_len = sizeof(opt_val);
#else
    snprintf(opt_val, sizeof(opt_val), EMPTY_STRING);
    opt_len = strlen(EMPTY_STRING) + 1;
#endif    
    rpc_setsockopt_raw(pco_iut, iut_s, RPC_SO_BINDTODEVICE, opt_val, opt_len);
    TAPI_WAIT_NETWORK;
        
    RPC_SEND(rc, pco_tst1, tst1_s, tst1_buf, tst1_buf_len, 0);
    MSLEEP(10);
    RPC_SEND(rc, pco_tst2, tst2_s, tst2_buf, tst2_buf_len, 0);
    TAPI_WAIT_NETWORK;
    
    rc = rpc_recvfrom(pco_iut, iut_s, local_buf, tst1_buf_len + tst2_buf_len, 0,
                 SA(&peer_addr), &peer_addrlen);
    
    CHECK_RETURNED_LEN(rc, tst1_buf_len, SA(&peer_addr), tst1_addr,
                       TEST_VERDICT, TEST_VERDICT, peer_names, NULL,
                       NULL, "IUT socket");
    /* There is data from 'tst1_s' not read yet */
    RPC_CHECK_READABILITY(pco_iut, iut_s, TRUE);
    
    rc = rpc_recvfrom(pco_iut, iut_s, local_buf, tst1_buf_len + tst2_buf_len, 0,
                 SA(&peer_addr), &peer_addrlen);
    
    CHECK_RETURNED_LEN(rc, tst2_buf_len, SA(&peer_addr), tst2_addr,
                       TEST_VERDICT, TEST_VERDICT, peer_names, NULL,
                       NULL, "IUT socket");
    /* There is no more data left */
    RPC_CHECK_READABILITY(pco_iut, iut_s, FALSE);
    

    /* Major step: Bind the socket to the interface connected to NET2 */
    rpc_setsockopt_raw(pco_iut, iut_s, RPC_SO_BINDTODEVICE,
                       iut_if2->if_name, (strlen(iut_if2->if_name) + 1));
    TAPI_WAIT_NETWORK;

    RPC_SEND(rc, pco_tst2, tst2_s, tst2_buf, tst2_buf_len, 0);
    MSLEEP(10);
    RPC_SEND(rc, pco_tst1, tst1_s, tst1_buf, tst1_buf_len, 0);
    TAPI_WAIT_NETWORK;

    rc = rpc_recvfrom(pco_iut, iut_s, local_buf, tst1_buf_len + tst2_buf_len, 0,
                 SA(&peer_addr), &peer_addrlen);

    CHECK_RETURNED_LEN(rc, tst2_buf_len, SA(&peer_addr), tst2_addr,
                       TEST_VERDICT, TEST_FAIL, peer_names, NULL,
                       NULL, "IUT socket");
    /* There is no more data left: datagrams from 'tst1_s' are droped now */
    RPC_CHECK_READABILITY(pco_iut, iut_s, FALSE);

    opt_len = sizeof(opt_error);
    rpc_getsockopt(pco_tst1, tst1_s, RPC_SO_ERROR, &opt_error);
    RING("Attempt to send data to peer bound to another interface "
         "returns error (SO_ERROR) %s", errno_rpc2str(opt_error));
    if (opt_error != 0 && opt_error != RPC_ECONNREFUSED)
    {
        TEST_FAIL("Unexpected error %s occured on 'tst1_s' socket, "
                  "but expected 0 or ECONNREFUSED",
                  errno_rpc2str(opt_error));
    }


    /* 
     * Major step: Unbind the socket using zero length, it does not matter
     * which value we pass as the option_value parameter.
     */
#if 1
    /*
     * On Linux there is a bug that does not allow to have option_len
     * less than sizeof(int), which is 4.
     */
    memset(opt_val, '\0', sizeof(opt_val));
    opt_len = sizeof(opt_val);
    rpc_setsockopt_raw(pco_iut, iut_s, RPC_SO_BINDTODEVICE, opt_val, opt_len);
#else
    snprintf(opt_val, sizeof(opt_val), GARBAGE_STRING);
    rpc_setsockopt_raw(pco_iut, iut_s, RPC_SO_BINDTODEVICE, opt_val, 0);
#endif
    TAPI_WAIT_NETWORK;

    RPC_SEND(rc, pco_tst2, tst2_s, tst2_buf, tst2_buf_len, 0);
    MSLEEP(10);
    RPC_SEND(rc, pco_tst1, tst1_s, tst1_buf, tst1_buf_len, 0);
    TAPI_WAIT_NETWORK;

    rc = rpc_recvfrom(pco_iut, iut_s, local_buf, tst1_buf_len + tst2_buf_len, 0,
                 SA(&peer_addr), &peer_addrlen);

    CHECK_RETURNED_LEN(rc, tst2_buf_len, SA(&peer_addr), tst2_addr,
                       TEST_VERDICT, TEST_FAIL, peer_names, NULL,
                       NULL, "IUT socket");
    /* There is data from 'tst1_s' not read yet */
    RPC_CHECK_READABILITY(pco_iut, iut_s, TRUE);

    rc = rpc_recvfrom(pco_iut, iut_s, local_buf, tst1_buf_len + tst2_buf_len, 0,
                 SA(&peer_addr), &peer_addrlen);

    CHECK_RETURNED_LEN(rc, tst1_buf_len, SA(&peer_addr), tst1_addr,
                       TEST_VERDICT, TEST_FAIL, peer_names, NULL,
                       NULL, "IUT socket");
    /* There is no more data left */
    RPC_CHECK_READABILITY(pco_iut, iut_s, FALSE);
    
    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut,  iut_s);
    CLEANUP_RPC_CLOSE(pco_tst1, tst1_s);
    CLEANUP_RPC_CLOSE(pco_tst2, tst2_s);
    
    free(tst1_buf);
    free(tst2_buf);
    free(local_buf);

    TEST_END;
}
