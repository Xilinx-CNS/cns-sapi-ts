/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Bad Parameters and Boundary Values
 */

/** @page bnbvalue-func_recvfrom_addr_null_dgram Using NULL pointer as address and its length in recvfrom() function with SOCK_DGRAM sockets
 *
 * @objective Check that @b recvfrom() function correctly handles 
 *            situation with passing @c NULL as the value of @a address
 *            or @a address_len parameters.
 *
 * @type conformance, robustness
 *
 * @reference @ref XNS5 section 8.1
 *
 * @param env       Testing environment:
 *                  - @ref arg_types_env_peer2peer_all_ipv4_ipv6
 *
 * @par Scenario:
 * -# Create @p pco_tst socket of type @c SOCK_DGRAM on @p pco_tst.
 * -# Create @p pco_iut socket of type @c SOCK_DGRAM on @p pco_iut.
 * -# Create @p addr_buf buffer of size @c sizeof(struct sockaddr for
 *    used address family) bytes.
 * -# Create @p tx_buf buffer of @p data_size bytes.
 * -# Create @p rx_buf buffer of @p data_size bytes.
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Not consider @b recvfrom() with not bound @c SOCK_DGRAM socket,
 *    see @ref bnbvalue_func_recvfrom_addr_null_dgram_1 "note 1".
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# @b bind() @p pco_iut socket to a local address.
 * -# @b connect() @p pco_tst socket to @p pco_iut socket.
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Call @b recvfrom(@p pco_iut, @p rx_buf, @p data_size, @c 0,
 *    @c NULL, @c NULL).
 * -# Call @b send(@p pco_tst, @p tx_buf, @p data_size, 0).
 * -# Check that @b recvfrom() returns @p data_size.
 * -# Check that the content of @p tx_buf and @p rx_buf are the same.
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Set @p addr_len to size of an appropriate sockaddr structure
 *    (for @c PF_INET domain it is set to @c sizeof(struct sockaddr_in)).
 * -# Call @b recvfrom(@p pco_iut, @p rx_buf, @p data_size, @c 0, @c NULL,
 *    @p &addr_len) (@c NULL as the value of @a address parameter).
 * -# Call @b send(@p pco_tst, @p tx_buf, @p data_size, 0).
 * -# Check that @b recvfrom() returns @p data_size.
 * -# Check that the content of @p tx_buf and @p rx_buf are the same.
 * -# Check that the value of @p addr_len is not changed.
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Call @b recvfrom(@p pco_iut, @p rx_buf, @p data_size, @c 0, @p addr_buf,
 *    @c NULL) (@c NULL as the value of @a address_len parameter).
 * -# Call @b send(@p pco_tst, @p tx_buf, @p data_size, 0).
 * -# Check that @b recvfrom() returns @c -1 with @c EFAULT errno.
 *    See @ref bnbvalue_func_recvfrom_addr_null_dgram_2 "note 2".
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Delete all the buffers.
 * -# Close @p pco_iut and @p pco_tst sockets.
 *
 * @note
 * -# @anchor bnbvalue_func_recvfrom_addr_null_dgram_1
 *    Calling @b recvfrom() on not bound @c SOCK_DGRAM sockets might
 *    bring deadlock, because it is not defined which network address
 *    and port it is listening on (@b getsockname() on this socket
 *    returns IP address 0.0.0.0 and port 0).
 *    So that this test does not deal with such situation;
 * -# @anchor bnbvalue_func_recvfrom_addr_null_dgram_2
 *    This step is oriented on Linux behaviour, because on FreeBSD
 *    function returns received data and ignore @a from parameter.
 *
 * @author Oleg Kravtsov <Oleg.Kravtsov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "bnbvalue/func_recvfrom_addr_null_dgram"

#include "sockapi-test.h"


int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;         /* pointer to PCO on IUT */
    rcf_rpc_server *pco_tst = NULL;


    const struct sockaddr   *iut_addr = NULL;
    const struct sockaddr   *tst_addr = NULL;
    int                      tst_socket = -1;
    int                      iut_socket = -1;

    unsigned char *addr_buf = NULL;
    unsigned char *addr_buf_cp = NULL;
    ssize_t        af_addr_len;
    tarpc_ssize_t  addr_buf_len;

    void *tx_buf = NULL;
    void *rx_buf = NULL;

    size_t data_size;
    
    rpc_socket_domain domain;

    TEST_START;

    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    
    domain = rpc_socket_domain_by_addr(iut_addr);

    addr_buf_len = sizeof(struct sockaddr_storage);
    addr_buf = malloc(addr_buf_len);
    CHECK_NOT_NULL(addr_buf);
    SA(addr_buf)->sa_family = addr_family_rpc2h(RPC_AF_UNKNOWN);
    addr_buf_cp = malloc(addr_buf_len);
    CHECK_NOT_NULL(addr_buf_cp);
    memcpy(addr_buf_cp, addr_buf, addr_buf_len);
    
    tx_buf = sockts_make_buf_stream(&data_size);
    CHECK_NOT_NULL(tx_buf);
    rx_buf = te_make_buf_by_len(data_size);
    CHECK_NOT_NULL(rx_buf);


    iut_socket = rpc_create_and_bind_socket(pco_iut, RPC_SOCK_DGRAM,
                                            RPC_PROTO_DEF,
                                            TRUE, FALSE, iut_addr);
    tst_socket = rpc_socket(pco_tst, domain,
                            RPC_SOCK_DGRAM, RPC_PROTO_DEF);
    rpc_bind(pco_tst, tst_socket, tst_addr);
    rpc_connect(pco_tst, tst_socket, iut_addr);

    pco_iut->op = RCF_RPC_CALL;
    rc = rpc_recvfrom(pco_iut, iut_socket, rx_buf, data_size, 0, NULL, NULL);

    RPC_SEND(rc, pco_tst, tst_socket, tx_buf, data_size, 0);

    pco_iut->op = RCF_RPC_WAIT;
    rc = rpc_recvfrom(pco_iut, iut_socket, rx_buf, data_size, 0 , NULL, NULL);

    if ((size_t)rc != data_size)
    {
        TEST_FAIL("recvfrom(..., NULL, NULL) called on IUT didn't "
                  "return correct length of the message");
    }
    if (memcmp(rx_buf, tx_buf, data_size) != 0)
    {
        TEST_FAIL("recvfrom(..., NULL, NULL) called on IUT changed "
                  "the buffer");
    }
    te_fill_buf(rx_buf, data_size);

    af_addr_len = sockaddr_get_size_by_domain(domain);

    pco_iut->op = RCF_RPC_CALL;
    rc = rpc_recvfrom(pco_iut, iut_socket, rx_buf, data_size, 0,
                      NULL, (socklen_t *)&af_addr_len);

    RPC_SEND(rc, pco_tst, tst_socket, tx_buf, data_size, 0);

    pco_iut->op = RCF_RPC_WAIT;
    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_recvfrom(pco_iut, iut_socket, rx_buf, data_size, 0,
                      NULL, (socklen_t *)&af_addr_len);

    if ((size_t)rc != data_size)
    {
        TEST_FAIL("recvfrom(...,NULL, &af_addr_len) called on IUT "
                  "didn't return correct length of the message");
    }
    if (memcmp(rx_buf, tx_buf, data_size) != 0)
    {
        TEST_FAIL("recvfrom(..., NULL, &af_addr_len) called on IUT "
                  "changed the buffer");
    }
    if (af_addr_len != sockaddr_get_size_by_domain(domain))
    {
        RING_VERDICT("recvfrom() called on IUT with NULL addr_buf pointer"
                     " and nonzero af_addr_len value"
                     " changed fromlen value to %d", af_addr_len);
    }
    te_fill_buf(rx_buf, data_size);

    af_addr_len = addr_buf_len;
    pco_iut->op = RCF_RPC_CALL;
    /* TODO it is better to use macros */
    rc = rpc_recvfrom_gen(pco_iut, iut_socket, rx_buf, data_size, 0,
                          SA(addr_buf), NULL, data_size, af_addr_len);
    if (rc != 0)
    {
        TEST_FAIL("rpc_recvfrom(..., addr_buf, NULL) call failed");
    }

    RPC_SEND(rc, pco_tst, tst_socket, tx_buf, data_size, 0);

    pco_iut->op = RCF_RPC_WAIT;
    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_recvfrom_gen(pco_iut, iut_socket, rx_buf, data_size, 0,
                          SA(addr_buf), NULL, data_size, af_addr_len);

    if (rc != -1)
    {
        RING_VERDICT("recvfrom() called on IUT with zero length of addr_buf"
                     " didn't fail as expected");
    }
    else if (RPC_ERRNO(pco_iut) != RPC_EFAULT)
    {
        RING_VERDICT("recvfrom() called on IUT with zero length of addr_buf"
                     " failed as expected with errno %s",
                     errno_rpc2str(RPC_ERRNO(pco_iut)));
    }

    TEST_SUCCESS;

cleanup:

    free(rx_buf);
    free(tx_buf);
    free(addr_buf);

    CLEANUP_RPC_CLOSE(pco_iut, iut_socket);
    CLEANUP_RPC_CLOSE(pco_tst, tst_socket);

    TEST_END;
}
