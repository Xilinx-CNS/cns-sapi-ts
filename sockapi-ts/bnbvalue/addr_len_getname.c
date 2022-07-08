/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Bad Parameters and Boundary Values
 */

/** @page bnbvalue-addr_len_getname Using inappropriate address length value in getsockname() and getpeername() functions
 *
 * @objective Check that @b getsockname() and getpeername() functions allow 
 *            to pass an arbitrary value in @a address_len parameter:
 *                - In case the buffer is shorter than an appropriate
 *                  sockaddr structure it fills in only the number of bytes
 *                  specified;
 *                - In case the buffer is longer it fills in no more than
 *                  the size of address structure of a particular domain.
 *                .
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
 * @param func      Tested function:
 *                  - getsockname
 *                  - getpeername
 * @param addr_buf_size Address buffer size used in the test:
 *                      - 0
 *                      - short: shorter then address size;
 *                      - long: longer then address size.
 *
 * @par Scenario:
 * -# Create @p addr_buf buffer whose size depends on the value of
 *    @p addr_buf_size parameter (for "short" it should be shorter than
 *    size of sockaddr structure for used address family, for "long" it 
 *    should be longer).
 * -# Create @p sample_addr_buf buffer of size of an appropriate sockaddr
 *    structure for used protocol domain.
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Create @c SOCK_STREAM connection between @p pco_iut and @p pco_tst.
 *    As a result two sockets appear @p iut_s and @p tst_s.
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Set @p len to the length of @p sample_addr_buf buffer.
 * -# Call @b getsockname(@p tst_s, @p sample_addr_buf, @p &len)
 *    if @p func parameter is @b setpeername(), or call 
 *    @b setpeername(@p tst_s, @p sample_addr_buf, @p &len) if 
 *    @p func parameter is @b getsockname().
 * -# Set @p len to the length of @p addr_buf buffer.
 * -# Call @p func(@p iut_s, @p addr_buf, @p &len).
 * -# Check that the function returns @c 0.
 * -# Check the value of @p len:
 *        - If @p addr_buf_size parameter equals to "long", 
 *          check that the value of @p len is set to the size of an 
 *          appropriate sockaddr structure for used protocol domain;
 *        - If @p addr_buf_size parameter equals to "short" or "0", 
 *          check that the value of @p len is not updated and equals to
 *          the length of @p addr_buf buffer.
 * -# Check that the first @p len bytes of @p addr_buf and 
 *    @p sample_addr_buf are the same.
 * -# If @p addr_buf_size parameter equals to "long", check that bytes that
 *    are out of size of an appropriate sockaddr structure are not updated.
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Delete @p addr_buf and @p sample_addr_buf buffers.
 * -# Close @p iut_s and @p tst_s sockets.
 *
 * @author Oleg Kravtsov <Oleg.Kravtsov@oktetlabs.ru>
 */

#define TE_TEST_NAME "bnbvalue/addr_len_getname"
#include "sockapi-test.h"

typedef int (*getnamefunc_t)(rcf_rpc_server *handle, int s, 
                             struct sockaddr *name, socklen_t *namelen);

typedef int (*getnamefunc_gen_t)(rcf_rpc_server *handle, int s, 
                                 struct sockaddr *name,
                                 socklen_t *namelen, socklen_t rnamelen);

int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst = NULL;

    rpc_socket_type        sock_type;
    const char            *func;
    sapi_buf_size          addr_buf_size;

    const struct sockaddr *iut_addr;
    const struct sockaddr *tst_addr;
    int                    iut_s = -1;
    int                    tst_s = -1;

    socklen_t              sockaddr_size;
    void                  *addr_buf = NULL;
    socklen_t              addr_buf_len;
    socklen_t              addr_buf_rlen;
    void                  *addr_buf_bkp = NULL;
    void                  *sample_addr_buf = NULL;
    socklen_t              sample_addr_buf_len;
    socklen_t              len;    

    getnamefunc_gen_t      tested_func;
    getnamefunc_t          pair_func;

    rpc_socket_domain domain;

    /*
     * Preambule.
     */
    TEST_START;
    TEST_GET_SOCK_TYPE(sock_type);
    TEST_GET_STRING_PARAM(func);
    TEST_GET_BUFF_SIZE(addr_buf_size);
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);

    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    
    domain = rpc_socket_domain_by_addr(iut_addr);

    if (strcmp(func, "getsockname") == 0)
    {
        tested_func = rpc_getsockname_gen;
        pair_func = rpc_getpeername;
    }
    else if (strcmp(func, "getpeername") == 0)
    {
        tested_func = rpc_getpeername_gen;
        pair_func = rpc_getsockname;
    }
    else
    {
        TEST_FAIL("'func' parameter is allowed to be "
                  "'getsockname' or 'getpeername'");
    }

    sockaddr_size = sockaddr_get_size_by_domain(domain);

    switch (addr_buf_size)
    {
        case SIZE_ZERO:
            addr_buf_len = 0;
            break;

        case SIZE_SHORT:
            addr_buf_len =
                sockaddr_size - rand_range(4, sockaddr_size - 1);
            break;

        case SIZE_EXACT:
            addr_buf_len = sockaddr_size;
            break;

        case SIZE_LONG:
            addr_buf_len = sockaddr_size + rand_range(1, sockaddr_size);
            break;

        default:
            TEST_FAIL("Unknown buffer size type %u", addr_buf_size);
    }

    addr_buf_rlen = MAX(sockaddr_size, addr_buf_len);

    CHECK_NOT_NULL(addr_buf = malloc(addr_buf_rlen));

    /* Fill in 'addr_buf' with some values and prepare its backup */
    memset(addr_buf, rand_range(0, 1024), addr_buf_rlen);

    CHECK_NOT_NULL(addr_buf_bkp = malloc(addr_buf_rlen));
    memcpy(addr_buf_bkp, addr_buf, addr_buf_rlen);

    /* Prepare 'sample_addr_buf' buffer */
    CHECK_NOT_NULL(sample_addr_buf = malloc(sockaddr_size));
    sample_addr_buf_len = sockaddr_size;


    GEN_CONNECTION(pco_iut, pco_tst, sock_type, RPC_PROTO_DEF,
                   iut_addr, tst_addr, &iut_s, &tst_s);

    rc = pair_func(pco_tst, tst_s, SA(sample_addr_buf), &sample_addr_buf_len);
    if (rc != 0)
    {
        TEST_FAIL("Cannot fill in 'sample_addr_buf' on 'pco_tst'");
    }

    RPC_AWAIT_IUT_ERROR(pco_iut);
    len = addr_buf_len;
    rc = tested_func(pco_iut, iut_s, SA(addr_buf), &len, addr_buf_rlen);
    if (rc != 0)
    {
        TEST_VERDICT("%s() on 'iut_s' socket returns %d with errno %s "
                     "instead of 0", func, rc,
                     errno_rpc2str(RPC_ERRNO(pco_iut)));
    }

    if (addr_buf_size == SIZE_EXACT || addr_buf_size == SIZE_LONG)
    {
        if (len != sockaddr_size)
        {
            TEST_FAIL("%s() successfully completes, but does not update "
                      "'address_len' field with correct length of address "
                      "from %s domain. Value passed to the function was "
                      "%s, returned %d, expected: %d", func,
                      domain_rpc2str(domain),
                      (addr_buf_len < len) ? "shorter" :
                          (addr_buf_len > len) ? "longer" : "exact",
                      len, sockaddr_size);
        }
    }
    else
    {
        if (len != addr_buf_len)
        {
            TEST_VERDICT("%s() successfully completes, but updates "
                         "'address_len' field to %d although the length "
                         "passed to the function was %s", func, len,
                         (addr_buf_len < len) ? "shorter" : "longer");
        }
    }

    if (te_sockaddrncmp(SA(sample_addr_buf), sample_addr_buf_len,
                        SA(addr_buf), len) != 0)
    {
        TEST_VERDICT("%s address of 'tst_s' socket %s and %s address of "
                     "'iut_s' socket %s are different",
                     ((strcmp(func, "getpeername") == 0) ? "Local" : "Peer"),
                     te_sockaddr2str(SA(sample_addr_buf)),
                     ((strcmp(func, "getpeername") == 0) ? "peer" : "local"),
                     te_sockaddr2str(SA(addr_buf)));
    }

    if (addr_buf_size == SIZE_LONG)
    {
        /*
         * Check that bytes that are out of address buffer length
         * are not updated.
         */
        if (memcmp(addr_buf + sockaddr_size, addr_buf_bkp + sockaddr_size,
                   addr_buf_len - sockaddr_size) != 0)
        {
            TEST_VERDICT("%s() updates bytes of 'address' that are out of "
                         "the length returned by the function", func);
        }
    }
 
    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    free(addr_buf);
    free(addr_buf_bkp);
    free(sample_addr_buf);

    TEST_END;
}
