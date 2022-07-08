/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * IOCTL Requests
 * 
 * $Id: siocgifnameindex.c 29885 2006-07-06 08:51:56Z arybchik $
 */

/** @page ioctls-siocgifnameindex Usage of SIOCGIFNAME/SIOCGIFINDEX requests
 *
 * @objective Check that @c SIOCGIFNAME/SIOCGIFINDEX requests provide 
 *            co-mapping between interface's name and index.
 *
 * @type conformance
 *
 * @reference @ref STEVENS section 16.6
 *
 * @param sock_type     Type of socket used in the test
 * @param pco_iut       PCO on IUT
 * @param iut_if        One of interfaces on @p pco_iut
 * @param ioctl         ioctl to test (SIOCGIFNAME or SIOCGIFINDEX)
 *
 * @par Test sequence:
 * -# Create @p iut_s socket of type @p sock_type from @c PF_INET domain
 *    on @p pco_iut;
 * -# Fill in ifreq_var variable of type @c struct @c ifreq structure as
 *    follows:
 *        - If we test SIOCGIFNAME, fill @a ifr_ifindex with index of 
 *          @p iut_if interface;
 *        - If we test SIOCGIFINDEX, fill @a ifr_name with name of
 *          @p iut_if interface;
 *        .
 * -# Call @b ioctl() with second argument corresponding to @p ioctl;
 * -# Check that the function returns @c 0;
 * -# Check that @p ifreq_var variable filled in as follows:
 *        - @a ifr_name: name of @p iut_if interface;
 *        - @a ifr_ifindex: index of @p iut_if interface;
 *        .
 * -# Close @p iut_s socket;
 *
 * @author Nikita Rastegaev <Nikita.Rastegaev@oktetlabs.ru>
 */

#define TE_TEST_NAME  "ioctls/siocgifname"

#include "sockapi-test.h"
#include "conf_api.h"

int
main(int argc, char *argv[])
{
    rcf_rpc_server            *pco_iut = NULL;
    int                        iut_s = -1;
    rpc_socket_type            sock_type;
    const struct if_nameindex *iut_if;
    struct ifreq               ifreq_var;
    const char                *ioctl;
    int                        request;

    /* Preambule */
    TEST_START;
    TEST_GET_SOCK_TYPE(sock_type);
    TEST_GET_PCO(pco_iut);
    
    TEST_GET_IF(iut_if);
    TEST_GET_STRING_PARAM(ioctl);

    if (strcmp(ioctl, "SIOCGIFNAME") == 0)
        request = RPC_SIOCGIFNAME;
    else if (strcmp(ioctl, "SIOCGIFINDEX") == 0)
        request = RPC_SIOCGIFINDEX;
    else
        TEST_FAIL("Unexpected value of ioctl parameter, %s", ioctl);

    iut_s = rpc_socket(pco_iut, RPC_PF_INET, sock_type, RPC_PROTO_DEF);

    memset(&ifreq_var, 0, sizeof(ifreq_var));
    
    if (request == RPC_SIOCGIFNAME)
        ifreq_var.ifr_ifindex = iut_if->if_index;
    else
        strncpy(ifreq_var.ifr_name, iut_if->if_name, 
                            sizeof(ifreq_var.ifr_name));
        
    rpc_ioctl(pco_iut, iut_s, request, &ifreq_var);

    if (strcmp(ifreq_var.ifr_name, iut_if->if_name) != 0)
        TEST_VERDICT("SIOCGIFINDEX returned interface name %s "
                     "instead of %s", ifreq_var.ifr_name, iut_if->if_name);
    if (ifreq_var.ifr_ifindex != (int)iut_if->if_index)
        TEST_VERDICT("SIOCGIFINDEX returned interface index %u "
                     "instead of %u", ifreq_var.ifr_ifindex, 
                                      iut_if->if_index);

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);

    TEST_END;
}

