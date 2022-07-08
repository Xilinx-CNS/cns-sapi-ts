/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * IOCTL Requests
 * 
 * $Id$
 */

/** @page ioctls-siocif_ifr_name_nonexist Usage of SIOCSIF... and SIOCGIF requests with non-existing interface name
 *
 * @objective Check that @b ioctl() with @c SIOCSIF... and @c SIOCGIF
 *            requests reports an error when it is passed with non-existing
 *            interface name as the value of @a ifr_name field of @c ifreq
 *            structure.
 *
 * @type conformance
 *
 * @reference @ref STEVENS section 16.6
 *
 * @param sock_type     Type of socket used in the test
 * @param pco_iut       PCO on IUT
 * @param req           ioctl request used in the test
 *
 * @par Test sequence:
 * -# Create @p iut_s socket of type @p sock_type from @c PF_INET domain
 *    on @p pco_iut;
 * -# Fill in @a ifr_name field of @p ifreq_var variable of type @c struct 
 *    @c ifreq structure with zero length string.
 * -# Call @b ioctl(@p iut_s, @p req, @p ifreq_var);
 * -# Check that the function returns @c -1 and sets @b errno to
 *    @c ENODEV or @c ENXIO;
 * -# Close @p iut_s socket;
 *
 * @author Oleg Kravtsov <Oleg.Kravtsov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "ioctls/siocif_ifr_name_nonexist"

#include "sockapi-test.h"

int
main(int argc, char *argv[])
{
    rcf_rpc_server            *pco_iut = NULL;
    int                        iut_s = -1;
    rpc_socket_type            sock_type;
    const struct if_nameindex *iut_if;
    struct ifreq               ifreq_var;
    rpc_ioctl_code             req;
    rpc_ioctl_code             get_req = RPC_SIOUNKNOWN;


    /* Preambule */
    TEST_START;
    TEST_GET_SOCK_TYPE(sock_type);
    TEST_GET_PCO(pco_iut);
    TEST_GET_IF(iut_if);
    TEST_GET_IOCTL_REQ(req);

    switch (req)
    {
#define REQ_CASE(req_) \
        case RPC_SIOCSIF ## req_:           \
            get_req = RPC_SIOCGIF ## req_;  \
            break;                          \
                                            \
        case RPC_SIOCGIF ## req_:           \
            break
    
        REQ_CASE(FLAGS);
        REQ_CASE(ADDR);
        REQ_CASE(NETMASK);
        REQ_CASE(BRDADDR);
        REQ_CASE(DSTADDR);
        REQ_CASE(MTU);
        
        case RPC_SIOCGIFHWADDR:
            break;

        default:
            TEST_FAIL("ioctl() request other than "
                      "SIOCGIFFLAGS, SIOCSIFFLAGS, "
                      "SIOCGIFADDR, SIOCSIFADDR, "
                      "SIOCGIFNETMASK, SIOCSIFNETMASK, "
                      "SIOCGIFBRDADDR, SIOCSIFBRDADDR, "
                      "SIOCGIFDSTADDR, SIOCSIFDSTADDR, "
                      "SIOCGIFHWADDR, SIOCGIFMTU, SIOCSIFMTU "
                      "is not supported");
    }

    memset(&ifreq_var, 0, sizeof(ifreq_var));

    iut_s = rpc_socket(pco_iut, RPC_PF_INET, sock_type, RPC_PROTO_DEF);

    if (get_req != RPC_SIOUNKNOWN)
    {
        /* 
         * We are dealing with SET request, so that first 
         * obtain the value and then issue SET request with zero length
         * interface name.
         */
        strncpy(ifreq_var.ifr_name, iut_if->if_name,
                sizeof(ifreq_var.ifr_name));

        /* Get the initial value */
        RPC_AWAIT_IUT_ERROR(pco_iut);
        rc = rpc_ioctl(pco_iut, iut_s, get_req, &ifreq_var);
        if (rc != 0)
        {
            TEST_VERDICT("ioctl(%s) failed with errno %s",
                         ioctl_rpc2str(get_req),
                         errno_rpc2str(RPC_ERRNO(pco_iut)));
        }

        memset(&(ifreq_var.ifr_name), 0, sizeof(ifreq_var.ifr_name));
    }

    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_ioctl(pco_iut, iut_s, req, &ifreq_var);
    if (rc != -1)
    {
        TEST_FAIL("ioctl(%s) called with zero length interface name "
                  "returns %d instead of -1", ioctl_rpc2str(req), rc);
    }
    if (RPC_ERRNO(pco_iut) == RPC_ENODEV ||
        RPC_ERRNO(pco_iut) == RPC_ENXIO)
    {
        RING_VERDICT("ioctl(%s) called with zero length interface name "
                     "returns -1 with errno %s", ioctl_rpc2str(req),
                     errno_rpc2str(RPC_ERRNO(pco_iut)));
    }
    else
    {
        TEST_VERDICT("ioctl(%s) called with zero length interface name "
                     "returns -1 with unexpected errno %s",
                     ioctl_rpc2str(req),
                     errno_rpc2str(RPC_ERRNO(pco_iut)));
    }

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);

    TEST_END;
}

