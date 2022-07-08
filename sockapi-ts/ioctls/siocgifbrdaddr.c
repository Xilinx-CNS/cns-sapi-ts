/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * IOCTL Requests
 * 
 * $Id$
 */

/** @page ioctls-siocgifbrdaddr Usage of SIOCGIFBRDADDR request
 *
 * @objective Check that @c SIOCGIFBRDADDR request returns broadcast address
 *            of the interface requested.
 *
 * @type conformance
 *
 * @reference @ref STEVENS section 16.6
 *
 * @param sock_type     Type of socket used in the test
 * @param pco_iut       PCO on IUT
 * @param iut_if        An interface name/index on @p pco_iut
 *
 * @par Test sequence:
 * -# Create @p iut_s socket of type @c SOCK_DGRAM from @c PF_INET domain
 *    on @p pco_iut;
 * -# Fill in @p ifreq_var variable of type @c struct @c ifreq 
 *    structure as follows:
 *        - @c ifr_name: name of @p iut_if interface;
 *        .
 * -# Call @b ioctl(@p iut_s, @c SIOCGIFBRDADDR, @p &ifconf_var);
 * -# Check that the function returns @c 0;
 * -# Save @a ifr_broadaddr field of @c ifreq structure to @p if_broadaddr
 *    variable;
 * -# Call @b ioctl(@p iut_s, @c SIOCGIFADDR, @p &ifconf_var);
 * -# Save @a ifr_addr field of @c ifreq structure to @p if_addr
 *    variable;
 * -# Call @b ioctl(@p iut_s, @c SIOCGIFNETMASK, @p &ifconf_var);
 * -# Save @a ifr_netmask field of @c ifreq structure to @p if_netmask
 *    variable;
 * -# Check that @c (~ @p if_netmask) @c | @p if_addr is the same as 
 *    @p if_broadaddr. See @ref ioctls_siocgifconf_1 "note 1";
 * -# Close @p iut_s socket;
 *
 * @note
 * @anchor ioctls_siocgifconf_1
 * It is not a strict rule that broadcast address of the interface has to
 * confom the equation provided, because it might be possible to assign 
 * any unicast network address as broadcast on the interface, as Linux does.
 * On FreeBSD there is no way to get network mask with @b ioctl().
 * 
 * @author Oleg Kravtsov <Oleg.Kravtsov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "ioctls/siocgifbrdaddr"

#include "sockapi-test.h"


int
main(int argc, char *argv[])
{
    rcf_rpc_server            *pco_iut = NULL;
    int                        iut_s = -1;
    rpc_socket_type            sock_type;
    const struct if_nameindex *iut_if;
    struct ifreq               req;
    struct sockaddr            if_broadaddr;
    struct sockaddr            if_addr;
    struct sockaddr            if_netmask;
    
    
    /* Preambule */
    TEST_START;
    TEST_GET_SOCK_TYPE(sock_type);
    TEST_GET_PCO(pco_iut);
    TEST_GET_IF(iut_if);

    iut_s = rpc_socket(pco_iut, RPC_PF_INET, sock_type, RPC_PROTO_DEF);

    memset(&req, 0, sizeof(req));
    strncpy(req.ifr_name, iut_if->if_name, sizeof(req.ifr_name));

#define CHECK_AND_COPY(var_) \
    do {                                                                 \
        memcpy(&if_ ## var_, &(req.ifr_ ## var_), sizeof(if_ ## var_));  \
                                                                         \
        if (if_ ## var_.sa_family != AF_INET)                            \
        {                                                                \
            TEST_FAIL("'sa_family' field of 'ifr_" #var_ "' is not "     \
                      "filled in with AF_INET, but with %s (%d)",        \
                      addr_family_rpc2str(addr_family_h2rpc(             \
                              if_ ##var_.sa_family)),                    \
                      if_ ##var_.sa_family);                             \
        }                                                                \
        if (SIN(&(if_ ##var_))->sin_port != 0)                           \
        {                                                                \
            TEST_FAIL("'sin_port' field of 'ifr_" #var_                  \
                      "' is not set to zero");                           \
        }                                                                \
    } while (0)
    
    rpc_ioctl(pco_iut, iut_s, RPC_SIOCGIFBRDADDR, &req);
    CHECK_AND_COPY(broadaddr);
    
    rpc_ioctl(pco_iut, iut_s, RPC_SIOCGIFADDR, &req);
    CHECK_AND_COPY(addr);
    
    rpc_ioctl(pco_iut, iut_s, RPC_SIOCGIFNETMASK, &req);
    CHECK_AND_COPY(netmask);

#undef CHECK_AND_COPY
    
    if ((SIN(&if_addr)->sin_addr.s_addr |
         (~SIN(&if_netmask)->sin_addr.s_addr)) != 
        SIN(&if_broadaddr)->sin_addr.s_addr)
    {
        TEST_FAIL("correlation between broadcast address, "
                  "interface address and network mask is not valid");
    }

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);

    TEST_END;
}

