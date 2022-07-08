/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Bad Parameters and Boundary Values
 */

/** @page bnbvalue-func_getname Inappropriate usage of getsockname() and getpeername() functions
 *
 * @objective Check that @b getsockname() and @b getpeername() functions
 *            correctly work when they are called for not bound/connected
 *            sockets.
 *
 * @type conformance, robustness
 *
 * @reference @ref XNS5 section 8.1
 *
 * @param domain    Domain used for the test (@c PF_INET, or smth.)
 * @param type      Type of socket used in the test
 * @param pco_iut   PCO on IUT
 *
 * @par Scenario:
 * -# Create @p pco_iut socket from @p domain domain of type @p type 
 *    on @b pco_iut;
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Call @b getsockname() on @p pco_iut socket;
 * -# Check that the function returns @c 0 and fills in @a address
 *    structure as follows:
 *        - @a sa_family - address family corresponding to @p domain domain;
 *        - @a xxx_port - @c 0;
 *        - @a xxx_addr - wildcard address.
 *        .
 * -# Call @b getpeername() on @p pco_iut socket;
 * -# Check that function returns @c -1 and sets @b errno to @c ENOTCONN;
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Close @p pco_iut socket.
 *
 * @author Oleg Kravtsov <Oleg.Kravtsov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "bnbvalue/func_getname"

#include "sockapi-test.h"


int
main(int argc, char *argv[])
{
    rpc_socket_type         sock_type;
    rcf_rpc_server         *pco_iut = NULL;

    int                     iut_s = -1;
    struct sockaddr_storage name;
    socklen_t               namelen;

    te_bool                 failed = FALSE;
    
    rpc_socket_domain domain;


    TEST_START;

    /* Preambule */
    TEST_GET_SOCK_TYPE(sock_type);
    TEST_GET_PCO(pco_iut);
    TEST_GET_DOMAIN(domain);


    /* Scenario */
    iut_s = rpc_socket(pco_iut, domain, sock_type, RPC_PROTO_DEF);

    namelen = sizeof(name);
    
    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_getsockname(pco_iut, iut_s, SA(&name), &namelen);
    if (rc == -1)
    {
        int err = RPC_ERRNO(pco_iut);

        if (err == RPC_EINVAL)
        {    
            ERROR_VERDICT("getsockname() returns (-1) and "
                          "errno is set to EINVAL");
            failed = TRUE;        
        }
        else
            TEST_FAIL("getsockname() return (-1) but "
                      "errno is not EINVAL");
    }
    else
    {
        if (addr_family_h2rpc(name.ss_family) != sockts_domain2family(domain))
        {
            TEST_FAIL("getsockname() on not bound/connected socket returned "
                      "incorrect address family");
        }
        if (te_sockaddr_get_port(SA(&name)) != 0)
        {
            TEST_FAIL("getsockname() on not bound/connected socket returned "
                      "non-zero port");
        }
        if (!te_sockaddr_is_wildcard(SA(&name)))
        {
            TEST_FAIL("getsockname() on not bound/connected socket returned "
                      "non-wildcard network address port");
        }
    }

    namelen = sizeof(name);
    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_getpeername(pco_iut, iut_s, SA(&name), &namelen);
    if (rc != -1)
    {
         TEST_FAIL("getpeername() called  on IUT returns %d "
                   "instead of -1", rc);
    }

    CHECK_RPC_ERRNO(pco_iut, RPC_ENOTCONN,
                    "getpeername() called on IUT returns -1");

    if (failed)
        TEST_STOP;

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);

    TEST_END;
}
