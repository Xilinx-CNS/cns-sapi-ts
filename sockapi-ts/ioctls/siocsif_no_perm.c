/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * IOCTL Requests
 * 
 * $Id$
 */

/** @page ioctls-siocsif_no_perm Usage of SIOCSIF... requests with non priveleged permissions
 *
 * @objective Check that @b ioctl() checks permission of the process on
 *            processing @c SIOCSIF... requests.
 *
 * @type conformance
 *
 * @reference @ref STEVENS section 16.6
 *
 * @param sock_type     Type of socket used in the test
 * @param pco_iut       PCO on IUT
 * @param iut_if        One of @p pco_iut interfaces
 * @param set_req       ioctl request used in the test
 *
 * @par Test sequence:
 * -# Create @p iut_s socket of type @p sock_type from @c PF_INET domain
 *    on @p pco_iut;
 * -# Change permissions of @p pco_iut to non privileged level;
 * -# Fill in @a ifr_name field of @p ifreq_var variable of type @c struct 
 *    @c ifreq structure with name of @p iut_if interface. Fill in an
 *    appropriate request-specific field of the structure with some valid
 *    value;
 * -# Call @b ioctl(@p iut_s, @p set_req, @p ifreq_var);
 * -# Check that the function returns @c -1 and sets @b errno to
 *    @c EPERM or @c EACCES;
 * -# Close @p iut_s socket;
 *
 * @author Oleg Kravtsov <Oleg.Kravtsov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "ioctls/siocsif_no_perm"

#include "sockapi-test.h"


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


    /* Preambule */
    TEST_START;
    TEST_GET_SOCK_TYPE(sock_type);
    TEST_GET_PCO(pco_iut);
    TEST_GET_IF(iut_if);
    TEST_GET_IOCTL_REQ(set_req);

    memset(&ifreq_var, 0, sizeof(ifreq_var));
    memset(&ifreq_init, 0, sizeof(ifreq_init));

    switch (set_req)
    {
#define REQ_CASE(req_) \
        case RPC_SIOCSIF ## req_:                    \
            get_req = RPC_SIOCGIF ## req_;           \
            break

        REQ_CASE(NETMASK);
        REQ_CASE(BRDADDR);
        REQ_CASE(DSTADDR);
        REQ_CASE(ADDR);
        REQ_CASE(MTU);
        REQ_CASE(FLAGS);

#undef REQ_CASE

        default:
            TEST_FAIL("ioctl() request other than SIOCSIFNETMASK, "
                      "SIOCSIFBRDADDR, SIOCSIFDSTADDR, SIOCSIFADDR, "
                      "SIOCSIFMTU, SIOCSIFFLAGS is not supported");
    }

    /* Change permissions on 'pco_iut' to non-priveleged */
    rpc_setuid(pco_iut, getuid());

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
        TEST_FAIL("ioctl(%s) called with non-priveleged permissions "
                  "returns %d instead of -1", 
                  ioctl_rpc2str(set_req), rc);
    }
    if (RPC_ERRNO(pco_iut) == RPC_EACCES ||
        RPC_ERRNO(pco_iut) == RPC_EPERM)
    {
        RING_VERDICT("ioctl(%s) called with non-priveleged permissions "
                     "returned -1 with errno %s", ioctl_rpc2str(set_req),
                     errno_rpc2str(RPC_ERRNO(pco_iut)));
    }
    else
    {
        TEST_VERDICT("ioctl(%s) called with non-priveleged permissions "
                     "returned -1 with unexpected errno %s",
                     ioctl_rpc2str(set_req),
                     errno_rpc2str(RPC_ERRNO(pco_iut)));
    }

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);

    if (pco_iut != NULL && rcf_rpc_server_restart(pco_iut) != 0)
    {
        ERROR("Failed to restart pco_iut");
        result = EXIT_FAILURE;
    }

    TEST_END;
}

