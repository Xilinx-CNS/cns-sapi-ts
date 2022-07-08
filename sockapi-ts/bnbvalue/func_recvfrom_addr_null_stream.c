/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Bad Parameters and Boundary Values
 */


/** @page bnbvalue-func_recvfrom_addr_null_stream Using NULL pointer as address and its length in recvfrom() function with SOCK_STREAM sockets
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
 * -# Create @p pco_tst socket of type @c SOCK_STREAM on @p pco_tst.
 * -# Create @p pco_iut socket of type @c SOCK_STREAM on @p pco_iut.
 * -# @b bind() @p pco_tst socket to a local address.
 * -# Call @b listen() on @p pco_tst socket.
 * -# Create @p addr_buf buffer of size @c sizeof(struct sockaddr for
 *    used address family) bytes.
 * -# Create @p tx_buf buffer of @p data_size bytes.
 * -# Create @p rx_buf buffer of @p data_size bytes.
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Call @b recvfrom() on @p pco_iut socket passing @c NULL as the value
 *    of @a address parameter and size of an appropriate sockaddr
 *    structure as the value of @a address_len parameter.
 * -# Check that the function immediately returns @c -1 and sets
 *    @b errno to @c ENOTCONN.
 *    See @ref bnbvalue_func_recvfrom_addr_null_stream_1 "note 1".
 * -# Call @b recvfrom() on @p pco_iut socket passing @c NULL as the value
 *    of @a address_len parameter and some not @c NULL pointer as the
 *    value of @a address parameter.
 * -# Check that the function immediately returns @c -1 and sets
 *    @b errno to @c ENOTCONN.
 *    See @ref bnbvalue_func_recvfrom_addr_null_stream_1 "note 1".
 * -# Call @b recvfrom() on @p pco_iut socket passing @c NULL as the value
 *    of @a address_len parameter and @c NULL pointer as the value of
 *    @a address parameter.
 * -# Check that the function immediately returns @c -1 and sets
 *    @b errno to @c ENOTCONN.
 *    See @ref bnbvalue_func_recvfrom_addr_null_stream_1 "note 1".
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# @b connect() @p pco_iut socket to @p pco_tst socket.
 * -# Call @b accept() on @p pco_tst socket obtaining a new @p accepted socket.
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Set @p af_addr_len to size of an appropriate sockaddr structure
 *    (for @c PF_INET domain it is set to @c sizeof(struct sockaddr_in)).
 * -# Call @b recvfrom(@p pco_iut, @p rx_buf, @p data_size, @c 0, @c NULL,
 *    @p &af_addr_len) (@c NULL as the value of @a address parameter).
 * -# Call @b send(@p accepted, @p tx_buf, @p data_size, 0).
 * -# Check that @b recvfrom() returns @p data_size.
 * -# Check that the content of @p tx_buf and @p rx_buf are the same.
 * -# Check that the value of @p af_addr_len is not changed.
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Call @b recvfrom(@p pco_iut, @p rx_buf, @p data_size, @c 0,
 *    @c NULL, @c NULL).
 * -# Call @b send(@p accepted, @p tx_buf, @p data_size, 0).
 * -# Check that @b recvfrom() returns @p data_size.
 * -# Check that the content of @p tx_buf and @p rx_buf are the same.
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Call @b recvfrom(@p pco_iut, @p rx_buf, @p data_size, @c 0, @p addr_buf,
 *    @c NULL) (@c NULL as the value of @a address_len parameter).
 * -# Call @b send(@p accepted, @p tx_buf, @p data_size, 0).
 * -# Check that @b recvfrom() returns @p data_size.
 * -# Check that the content of @p tx_buf and @p rx_buf are the same.
 * -# Check that @p addr_buf is not changed.
 *    See @ref bnbvalue_func_recvfrom_addr_null_stream_2 "note 2".
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Delete all the buffers.
 * -# Close @p accepted, @p pco_iut and @p pco_tst sockets.
 *
 * @note
 * -# @anchor bnbvalue_func_recvfrom_addr_null_stream_1
 *    This step is oriented on FreeBSD and Linux behaviour, but it is
 *    not obvious what should be checked first whether the state of the
 *    connection point (connected or not) or validity of the parameters;
 * -# @anchor bnbvalue_func_recvfrom_addr_null_stream_2
 *    This step is oriented on FreeBSD behaviour, because on Linux
 *    function returns @c -1 and sets @b errno to @c EFAULT.
 *
 * @author Oleg Kravtsov <Oleg.Kravtsov@oktetlabs.ru>
 */

#define TE_TEST_NAME "bnbvalue/func_recvfrom_addr_null_stream"
#include "sockapi-test.h"

int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;  
    rcf_rpc_server *pco_tst = NULL;


    const struct sockaddr   *iut_addr = NULL;
    const struct sockaddr   *tst_addr = NULL;
    struct sockaddr_storage  addr;
    socklen_t                addrlen;
    int                      tst_socket = -1;
    int                      iut_socket = -1;
    int                      accepted_socket = -1;

    unsigned char *addr_buf = NULL;
    unsigned char *addr_buf_cp = NULL;
    int            af_addr_len;
    tarpc_ssize_t  addr_buf_len;

    unsigned char *tx_buf = NULL;
    unsigned char *tx_buf_cp = NULL;

    unsigned char *rx_buf = NULL;
    unsigned char *rx_buf_cp = NULL;

    size_t data_size;

    char buffer[] = "Test";
    size_t buffer_size = sizeof(buffer);
    
    int expected_errno;
    
    rpc_socket_domain domain;
        

    TEST_START;

    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    
    domain = rpc_socket_domain_by_addr(iut_addr);

    tst_socket = rpc_socket(pco_tst, domain,
                            RPC_SOCK_STREAM, RPC_PROTO_DEF);
    iut_socket = rpc_socket(pco_iut, domain,
                            RPC_SOCK_STREAM, RPC_PROTO_DEF);

    rpc_bind(pco_tst, tst_socket, tst_addr);
    rpc_listen(pco_tst, tst_socket, SOCKTS_BACKLOG_DEF);

    addr_buf_len = rpc_get_sizeof(pco_iut, "struct sockaddr_storage");
    addr_buf = te_make_buf_by_len(addr_buf_len);
    CHECK_NOT_NULL(addr_buf);
    SA(addr_buf)->sa_family = addr_family_rpc2h(RPC_AF_UNKNOWN);
    addr_buf_cp = malloc(addr_buf_len);
    CHECK_NOT_NULL(addr_buf_cp);
    memcpy(addr_buf_cp, addr_buf, addr_buf_len);
    
    tx_buf = sockts_make_buf_stream(&data_size);
    CHECK_NOT_NULL(tx_buf);
    rx_buf = te_make_buf_by_len(data_size);
    CHECK_NOT_NULL(rx_buf);
    rx_buf_cp = malloc(data_size);
    CHECK_NOT_NULL(rx_buf_cp);
    tx_buf_cp = malloc(data_size);
    CHECK_NOT_NULL(tx_buf_cp);

    expected_errno = RPC_ENOTCONN;

    addrlen = sizeof(addr);
    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_recvfrom(pco_iut, iut_socket, buffer, buffer_size, 0,
                      NULL, &addrlen);
    if (rc != -1)
    {
        TEST_VERDICT("recvfrom(..., NULL, socklen_t fromlen) called on IUT "
                     "returned %d instead of -1");
    }

    CHECK_RPC_ERRNO(pco_iut, expected_errno,
                    "recvfrom(..., NULL, socklen_t fromlen) called on IUT "
                    "returned -1");

    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_recvfrom_gen(pco_iut, iut_socket, buffer, buffer_size, 0,
                          SA(&addr), NULL, buffer_size, sizeof(addr));
    if (rc != -1)
    {
        TEST_VERDICT("recvfrom(..., not_NULL, NULL) called on IUT "
                     "returned %d instead of -1");
    }

    CHECK_RPC_ERRNO(pco_iut, expected_errno,
                    "recvfrom(..., not_NULL, NULL) called on IUT "
                    "returned -1");

    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_recvfrom(pco_iut, iut_socket, buffer, buffer_size, 0, NULL, NULL);
    if (rc != -1)
    {
        TEST_VERDICT("recvfrom(..., NULL, NULL) called on IUT "
                     "returned %d instead of -1");
    }

    CHECK_RPC_ERRNO(pco_iut, expected_errno,
                    "recvfrom(..., NULL, NULL) called on IUT "
                    "returned -1");

    rpc_connect(pco_iut, iut_socket, tst_addr);

    addrlen = sizeof(addr);
    accepted_socket = rpc_accept(pco_tst, tst_socket, SA(&addr), &addrlen);

    af_addr_len = sockaddr_get_size_by_domain(domain);
    memcpy(rx_buf_cp, rx_buf, data_size);
    memcpy(tx_buf_cp, tx_buf, data_size);

    pco_iut->op = RCF_RPC_CALL;
    rc = rpc_recvfrom(pco_iut, iut_socket, rx_buf, data_size, 0,
                 NULL, (socklen_t *)&af_addr_len);

    RPC_SEND(rc, pco_tst, accepted_socket, tx_buf, data_size, 0);

    pco_iut->op = RCF_RPC_WAIT;
    rc = rpc_recvfrom(pco_iut, iut_socket, rx_buf, data_size, 0,
                 NULL, (socklen_t *)&af_addr_len);

    if ((size_t)rc != data_size)
    {
        TEST_VERDICT("recvfrom(...,NULL, &af_addr_len) called on IUT "
                     "didn't return correct length of the message");
    }
    if (memcmp(rx_buf, tx_buf, data_size) != 0)
    {
        TEST_VERDICT("recvfrom(..., NULL, &af_addr_len) called on IUT "
                     "changed the buffer");
    }
    if (af_addr_len != sockaddr_get_size_by_domain(domain))
    {
        RING_VERDICT("recvfrom() called on IUT with NULL addr_buf pointer "
                     "and nonzero af_addr_len "
                     "changed fromlen value to %d", af_addr_len);
    }

    pco_iut->op = RCF_RPC_CALL;
    rc = rpc_recvfrom(pco_iut, iut_socket, rx_buf, data_size, 0, NULL, NULL);

    RPC_SEND(rc, pco_tst, accepted_socket, tx_buf, data_size, 0);

    pco_iut->op = RCF_RPC_WAIT;
    rc = rpc_recvfrom(pco_iut, iut_socket, rx_buf, data_size, 0 , NULL, NULL);

    if ((size_t)rc != data_size)
    {
        TEST_VERDICT("recvfrom(...,NULL, NULL) called on IUT didn't "
                     "return correct length of the message");
    }
    if (memcmp(rx_buf, tx_buf, data_size) != 0)
    {
        TEST_VERDICT("recvfrom(..., NULL, NULL) called on IUT changed "
                     "the buffer");
    }

    af_addr_len = addr_buf_len;
    pco_iut->op = RCF_RPC_CALL;
    rpc_recvfrom_gen(pco_iut, iut_socket, rx_buf, data_size, 0,
                     SA(addr_buf), NULL, data_size, af_addr_len);

    RPC_SEND(rc, pco_tst, accepted_socket, tx_buf, data_size, 0);
    
    pco_iut->op = RCF_RPC_WAIT;
    rc = rpc_recvfrom_gen(pco_iut, iut_socket, rx_buf, data_size, 0,
                          SA(addr_buf), NULL, data_size, af_addr_len);
    if ((size_t)rc != data_size)
    {
        TEST_VERDICT("recvfrom(..., addr_buf, NULL) called on IUT didn't "
                     "return correct length of the message");
    }
    if (memcmp(rx_buf, tx_buf, data_size) != 0)
    {
        TEST_VERDICT("recvfrom(..., addr_buf, NULL) called on IUT changed "
                     "the buffer");
    }
    if (memcmp(addr_buf, addr_buf_cp, af_addr_len) != 0)
    {
        ERROR("Control:%Tm[[16].[2]]\nCurrent:%Tm[[16].[2]]",
              addr_buf_cp, af_addr_len, addr_buf, af_addr_len);
        TEST_VERDICT("recvfrom(..., addr_buf, NULL) called on IUT changed "
                     "'address' value");
    }

    TEST_SUCCESS;

cleanup:

    free(rx_buf);
    free(tx_buf);
    free(rx_buf_cp);
    free(tx_buf_cp);
    free(addr_buf);
    free(addr_buf_cp);

    CLEANUP_RPC_CLOSE(pco_iut, iut_socket);
    CLEANUP_RPC_CLOSE(pco_tst, tst_socket);
    CLEANUP_RPC_CLOSE(pco_tst, accepted_socket);

    TEST_END;
}
