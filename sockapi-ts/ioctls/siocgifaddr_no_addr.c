/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * IOCTL Requests
 * 
 * $Id$
 */

/** @page ioctls-siocgifaddr_no_addr Usage of SIOCGIFADDR-like requests for interface without address
 *
 * @objective Check that @c SIOCGIFADDR, @c SIOCGIFBRDADDR and
 *            @c SIOCGIFNETADDR requests return @c -1 and set errno
 *            @c EADDRNOTAVAIL when there are no addresses on the
 *            interface.
 *
 * @param sock_type     Type of socket used in the test
 * @param pco_iut       PCO on IUT
 * @param iut_if        One of interfaces on @p pco_iut
 * @param req           @c SIOCGIFADDR, @c SIOCGIFBRDADDR and
 *                      @c SIOCGIFNETADDR
 *
 * @par Test sequence:
 * -# Delete all IP addresses from @p iut_if interface;
 * -# Create @p sock_type socket;
 * -# Call @b ioctl(@p req) on @p iut_if interface;
 * -# Check that it returns @c -1 and errno is set to @c EADDRNOTAVAIL
 *    or returns @c 0 and address is @c INADDR_ANY;
 * -# Close @p iut_s socket;
 *
 * @author Yurij Plotnikov <Yurij.Plotnikov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "ioctls/siocgifaddr_no_addr"

#include "sockapi-test.h"
#include "conf_api.h"
#include "tapi_cfg_base.h"

int
main(int argc, char *argv[])
{
    rcf_rpc_server            *pco_iut = NULL;
    int                        iut_s = -1;
    rpc_socket_type            sock_type;
    const struct if_nameindex *iut_if;
    struct ifreq               ifreq_var;

    struct sockaddr_in         dummy_addr;

    rpc_ioctl_code             req;

    TEST_START;
    TEST_GET_SOCK_TYPE(sock_type);
    TEST_GET_PCO(pco_iut);
    
    TEST_GET_IF(iut_if);

    TEST_GET_IOCTL_REQ(req);

    /* Delete all IP addresses */
    dummy_addr.sin_family = AF_INET;
    dummy_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    CHECK_RC(tapi_cfg_del_if_ip4_addresses(pco_iut->ta, iut_if->if_name,
                                           SA(&dummy_addr)));

    iut_s = rpc_socket(pco_iut, RPC_PF_INET, sock_type, RPC_PROTO_DEF);
    
    memset(&ifreq_var, 0, sizeof(ifreq_var));
    strncpy(ifreq_var.ifr_name, iut_if->if_name, sizeof(ifreq_var.ifr_name));
    
    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_ioctl(pco_iut, iut_s, req, &ifreq_var);
    if (rc == 0)
    {
        if (ntohl(SIN(&ifreq_var.ifr_addr)->sin_addr.s_addr) !=
            INADDR_ANY)
        {
            TEST_VERDICT("No addresses are assigned to interface, "
                         "ioctl() returns 0 and address/netmask/"
                         "broadcast contains something strange");
        }
        RING_VERDICT("No addresses are assigned to interface, ioctl() "
                     "returns 0 and address/netmask/broadcast is "
                     "unspecified");
    }
    else
    {
        CHECK_RPC_ERRNO(pco_iut, RPC_EADDRNOTAVAIL,
                        "No addresses are assigned to interface, "
                        "ioctl() returns -1, but");
    }

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);

    TEST_END;
}
