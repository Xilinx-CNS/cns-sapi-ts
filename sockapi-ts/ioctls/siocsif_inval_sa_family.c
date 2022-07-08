/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * IOCTL Requests
 * 
 * $Id$
 */

/** @page ioctls-siocsif_inval_sa_family Usage of SIOCSIF... requests with incorrect sa_family field
 *
 * @objective Check that @b ioctl() varifies the value of @a sa_family field
 *            in @c sockaddr structure passed in @c ifreq structure for 
 *            @c SIOCSIF... requests deal with network address,
 *            such as @c SIOCSIFNETMASK, @c SIOCSIFBRDADDR, @c SIOCSIFDSTADDR,
 *            @c SIOCSIFADDR.
 *
 * @type conformance
 *
 * @reference @ref STEVENS section 16.6
 *
 * @param sock_type     Type of socket used in the test
 * @param pco_iut       PCO on IUT
 * @param iut_if        One of @p pco_iut interfaces
 * @param set_req       ioctl request used in the test (@c SIOCSIFNETMASK, 
 *                      @c SIOCSIFBRDADDR, @c SIOCSIFDSTADDR, or
 *                      @c SIOCSIFADDR)
 * @param af            Any value different from @c AF_INET
 *
 * @par Test sequence:
 * -# Create @p iut_s socket of type @p sock_type from @c PF_INET domain
 *    on @p pco_iut;
 * -# Fill in @p ifreq_var variable of type @c struct @c ifreq
 *    structure as follows:
 *        - @a ifr_name: name of @p iut_if interface;
 *        - @a ifr_addr.sa_family: @p af
 *        .
 * -# Call @b ioctl(@p iut_s, @p set_req, @p ifreq_var);
 * -# Check that the function returns @c -1 and sets @b errno to
 *    @c EINVAL or @c EAFNOSUPPORT;
 * -# Close @p iut_s socket;
 *
 * @author Oleg Kravtsov <Oleg.Kravtsov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "ioctls/siocsif_inval_sa_family"

#include "sockapi-test.h"
#include "tapi_cfg.h"


int
main(int argc, char *argv[])
{
    rcf_rpc_server            *pco_iut = NULL;
    int                        iut_s = -1;
    rpc_socket_type            sock_type;
    const struct if_nameindex *iut_if;
    struct ifreq               ifreq_var;
    struct ifreq               ifreq_init;
    rpc_ioctl_code             set_req;
    rpc_ioctl_code             get_req;
    rpc_socket_addr_family     af;


    /* Preambule */
    TEST_START;
    TEST_GET_SOCK_TYPE(sock_type);
    TEST_GET_PCO(pco_iut);
    TEST_GET_IF(iut_if);
    TEST_GET_IOCTL_REQ(set_req);
    TEST_GET_ADDR_FAMILY(af);

    memset(&ifreq_var, 0, sizeof(ifreq_var));
    memset(&ifreq_init, 0, sizeof(ifreq_init));

    if (af == RPC_AF_INET)
    {
        TEST_FAIL("'af' parameter cannot be AF_INET");
    }

    switch (set_req)
    {
#define REQ_CASE(req_, req_field_) \
        case RPC_SIOCSIF ## req_:                    \
            get_req = RPC_SIOCGIF ## req_;           \
            ifreq_var.ifr_ ## req_field_.sa_family = \
                addr_family_rpc2h(af);               \
            break

        REQ_CASE(NETMASK, netmask);
        REQ_CASE(BRDADDR, broadaddr);
        REQ_CASE(DSTADDR, dstaddr);
        REQ_CASE(ADDR, addr);

#undef REQ_CASE

        default:
            TEST_FAIL("ioctl() request other than SIOCSIFNETMASK, "
                      "SIOCSIFBRDADDR, SIOCSIFDSTADDR, SIOCSIFADDR "
                      "is not supported");
    }

    iut_s = rpc_socket(pco_iut, RPC_PF_INET, sock_type, RPC_PROTO_DEF);

    strncpy(ifreq_init.ifr_name, iut_if->if_name, sizeof(ifreq_init.ifr_name));

    /* Get the initial value */
    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_ioctl(pco_iut, iut_s, get_req, &ifreq_init);
    if (rc != 0)
    {
        TEST_VERDICT("ioctl(%s) failed with errno %s",
                     ioctl_rpc2str(get_req),
                     errno_rpc2str(RPC_ERRNO(pco_iut)));
    }

    strncpy(ifreq_var.ifr_name, iut_if->if_name, sizeof(ifreq_var.ifr_name));
    memcpy(ifreq_var.ifr_addr.sa_data, ifreq_init.ifr_addr.sa_data,
           sizeof(ifreq_var.ifr_addr.sa_data));
    
    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_ioctl(pco_iut, iut_s, set_req, &ifreq_var);
    if (rc != -1)
    {
        TEST_FAIL("ioctl(%s) called with %s 'sa_family' field of "
                  "sockaddr structure returns %d instead of -1", 
                  ioctl_rpc2str(set_req), addr_family_rpc2str(af), rc);
    }
    if (RPC_ERRNO(pco_iut) == RPC_EINVAL ||
        RPC_ERRNO(pco_iut) == RPC_EAFNOSUPPORT)
    {
        RING_VERDICT("ioctl(%s) called with %s 'sa_family' field of "
                     "sockaddr structure returned -1 with errno %s",
                     ioctl_rpc2str(set_req), addr_family_rpc2str(af),
                     errno_rpc2str(RPC_ERRNO(pco_iut)));
    }
    else
    {
        TEST_VERDICT("ioctl(%s) called with %s 'sa_family' field of "
                     "sockaddr structure returned -1 with unexpected "
                     "errno %s",
                     ioctl_rpc2str(set_req), addr_family_rpc2str(af),
                     errno_rpc2str(RPC_ERRNO(pco_iut)));
    }

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);

    TEST_END;
}

