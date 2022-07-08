/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Bad Parameters and Boundary Values
 */

/** @page bnbvalue-addr_len_accept Passing address buffer whose size is different from the size of address structure of a particular domain to accept() function
 *
 * @objective Check that @b accept() and @b accept4() functions allow to pass
 *            arbitrary address length and process it correctly
 *
 * @type conformance, robustness
 *
 * @reference @ref XNS5 section 8.1
 *
 * @param addr_buf_size Address buffer size used in the test:
 *                      - @b 0 : buffer size is equal to 0
 *                      - @b short : buffer size is random
 *                      from 1 to actual address size - 1
 *                      - @b long : buffer size is random
 *                      from actual address size + 1 to twice longer
 *                      - @b exact : buffer size is equal to
 *                      actual address size
 * @param pco_iut       PCO on IUT
 * @param pco_tst       PCO on TESTER
 * @param func          Function used to accept connection:
 *                      - @b accept()
 *                      - @b accept4()
 * @param func_flag     Only for func=accept4. Possible flags:
 *                      - @b default
 *                      - @b nonblock
 *                      - @b cloexec
 *
 * @par Scenario:
 *
 * @author Oleg Kravtsov <Oleg.Kravtsov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "bnbvalue/addr_len_accept"

#include "sockapi-test.h"
#include "sockapi-ts_tcp.h"


int
main(int argc, char *argv[])
{
    rcf_rpc_server        *pco_iut = NULL;
    rcf_rpc_server        *pco_tst = NULL;
    sapi_buf_size          addr_buf_size;
    const struct sockaddr *iut_addr;
    int                    iut_s = -1;
    int                    tst_s = -1;
    int                    acc_s = -1;

    socklen_t              sockaddr_size;
    void                  *peer_addr_buf = NULL;
    socklen_t              peer_addr_buf_len;
    socklen_t              peer_addr_buf_rlen;
    void                  *peer_addr_buf_bkp = NULL;
    void                  *tst_addr_buf = NULL;
    socklen_t              tst_addr_buf_len;

    socklen_t              len;
    const char            *func;
    int                    func_flag;

    rpc_socket_domain      domain;

    /*
     * Preambule.
     */
    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_BUFF_SIZE(addr_buf_size);
    TEST_GET_STRING_PARAM(func);
    TEST_GET_ADDR(pco_iut, iut_addr);
    SOCKTS_GET_SOCK_FLAGS(func_flag);

    TEST_STEP("Allocate @b peer_addr_buf, choosing its length "
	      "according to @p addr_buf_size parameter");
    domain = rpc_socket_domain_by_addr(iut_addr);
    sockaddr_size = rpc_get_sizeof(pco_iut,
        addr_family_sockaddr_str(addr_family_h2rpc(iut_addr->sa_family)));

    switch (addr_buf_size)
    {
        case SIZE_ZERO:
            peer_addr_buf_len = 0;
            break;
        
        case SIZE_SHORT:
            peer_addr_buf_len = rand_range(1, sockaddr_size - 1);
            break;
            
        case SIZE_EXACT:
            peer_addr_buf_len = sockaddr_size;
            break;
            
        case SIZE_LONG:
            peer_addr_buf_len = sockaddr_size +
                                rand_range(1, sockaddr_size);
            break;

        default:
            TEST_FAIL("Unknown buffer size type %u", addr_buf_size);
    }

    peer_addr_buf_rlen = MAX(sockaddr_size, peer_addr_buf_len);

    /* Fill in 'peer_addr_buf' with some values and prepare its backup */
    peer_addr_buf = te_make_buf_by_len(peer_addr_buf_rlen);
    CHECK_NOT_NULL(peer_addr_buf_bkp = malloc(peer_addr_buf_rlen));
    memcpy(peer_addr_buf_bkp, peer_addr_buf, peer_addr_buf_rlen);

    /* Prepare 'tst_addr_buf' buffer */
    TEST_STEP("Create @b tst_addr_buf buffer of size of an appropriate "
	      "sockaddr structure");
    CHECK_NOT_NULL(tst_addr_buf = malloc(sockaddr_size));
    tst_addr_buf_len = sockaddr_size;

    /*
     * Create a connection between 'pco_tst' and 'pco_iut'.
     */

    TEST_STEP("Create @b iut_s and @b tst_s sockets of type @c SOCK_STREAM");

    iut_s = rpc_socket(pco_iut, domain, RPC_SOCK_STREAM, RPC_PROTO_DEF);
    tst_s = rpc_socket(pco_tst, domain, RPC_SOCK_STREAM, RPC_PROTO_DEF);

    TEST_STEP("@b bind() @b iut_s to @p iut_addr");
    rpc_bind(pco_iut, iut_s, iut_addr);
    TEST_STEP("Call @b listen() on @b iut_s socket");
    rpc_listen(pco_iut, iut_s, SOCKTS_BACKLOG_DEF);
    TEST_STEP("@b connect() @b tst_s socket to @p iut_addr");
    rpc_connect(pco_tst, tst_s, iut_addr);
    TEST_STEP("Call @b getsockname() on @b tst_s socket specifying @b tst_addr_buf as "
              "a location for the local address");
    rpc_getsockname(pco_tst, tst_s, SA(tst_addr_buf), &tst_addr_buf_len);

    TEST_STEP("Set @b len to the length of @b peer_addr_buf buffer");
    len = peer_addr_buf_len;

    RPC_AWAIT_IUT_ERROR(pco_iut);

    TEST_STEP("Call @p func on @b iut_s to obtain accepted socket @b acc_s, "
	      "passing @b peer_addr_buf as address location "
	      "and pointer to @b len as address length location");
    if (strcmp(func, "accept") == 0)
    {
        acc_s = rpc_accept_gen(pco_iut, iut_s, SA(peer_addr_buf), &len,
                               peer_addr_buf_rlen);
    }
    else if (strcmp(func, "accept4") == 0)
    {
	acc_s = rpc_accept4_gen(pco_iut, iut_s, SA(peer_addr_buf), &len,
			       peer_addr_buf_rlen, func_flag);
    }
    else
    {
        TEST_FAIL("Unknown function is testing");
        goto cleanup;
    }

    TEST_STEP("Check that @p func succeeded.");
    if (acc_s == -1)
    {
        TEST_VERDICT("%s() returns (-1) and errno is set to %s",
                     func, errno_rpc2str(RPC_ERRNO(pco_iut)));
    }

    TEST_STEP("Check the value of @b len");
    if (addr_buf_size == SIZE_EXACT || addr_buf_size == SIZE_LONG)
    {
        TEST_SUBSTEP("If @p addr_buf_size parameter equals to @c long or @c exact, "
	             "check that the value of @b len is set to the size of an "
		     "appropriate sockaddr structure");
        if (len != sockaddr_size)
        {
            TEST_VERDICT("%s() successfully completes, but does not "
                         "update 'address_len' field with correct length "
                         "of address from %s domain. Value passed to "
                         "the function was %s, returned %d, expected: %d",
                         func, domain_rpc2str(domain),
                         (peer_addr_buf_len < len) ? "shorter" :
                         (peer_addr_buf_len > len) ? "longer" : "exact",
                         len, sockaddr_size);
        }
    }
    else
    {
        TEST_SUBSTEP("If @p addr_buf_size parameter equals to @c short or @c 0, "
		     "check that the value of @b len is not updated and equals to "
		     "the length of @b peer_addr_buf buffer");
        if (len != peer_addr_buf_len)
        {
            TEST_VERDICT("%s() successfully completes, but updates "
                         "'address_len' field to %d although the length "
                         "passed to the function was %s", func, len,
                         (peer_addr_buf_len == 0) ? "zero" :
                         (peer_addr_buf_len < len) ? "shorter" : "longer");
        }
    }

    TEST_STEP("Check that the first @b len bytes of @b tst_addr_buf and "
	      "@b peer_addr_buf are the same");
    if (te_sockaddrncmp(SA(tst_addr_buf), tst_addr_buf_len,
                        SA(peer_addr_buf), len) != 0)
    {
        TEST_VERDICT("Local address of 'tst_s' socket %s and peer address of "
                     "'acc_s' socket %s returned by %s() are different.",
                     te_sockaddr2str(SA(tst_addr_buf)),
                     te_sockaddr2str(SA(peer_addr_buf)), func);
    }

    TEST_STEP("If @p addr_buf_size parameter equals to @c long, check that bytes that "
	      "are out of size of an appropriate sockaddr structure are not updated");
    if (addr_buf_size == SIZE_LONG)
    {
        /*
         * Check that bytes that are out of address buffer length
         * are not updated.
         */
        if (memcmp(peer_addr_buf + sockaddr_size,
                   peer_addr_buf_bkp + sockaddr_size,
                   peer_addr_buf_len - sockaddr_size) != 0)
        {
            TEST_VERDICT("%s() updates bytes of 'address' that are "
                         "out of the length returned by the function", func);
        }
    }

    TEST_STEP("If @p func_flag is @c nonblock or @c cloexec, check "
	      "file descriptor status flags reported by @b fcntl()");
    CHECK_RC(sockts_check_sock_flags(pco_iut, acc_s, func_flag));

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    CLEANUP_RPC_CLOSE(pco_iut, acc_s);

    free(peer_addr_buf);
    free(peer_addr_buf_bkp);
    free(tst_addr_buf);

    TEST_END;
}
