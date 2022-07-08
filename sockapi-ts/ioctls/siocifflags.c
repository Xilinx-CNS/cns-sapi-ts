/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * IOCTL Requests
 * 
 * $Id$
 */

/** @page ioctls-siocifflags Usage of SIOCGIFFLAGS and SIOCSIFFLAGS requests
 *
 * @objective Check that @c SIOCGIFFLAGS request returns 
 *            flags associated with specified interface.
 *
 * @type conformance
 *
 * @reference @ref STEVENS section 16.6
 *
 * @param sock_type     Type of socket used in the test
 * @param pco_iut       PCO on IUT
 * @param iut_if        One of interfaces on @p pco_iut
 *
 * @par Test sequence:
 * -# Create @p iut_s socket of type @p sock_type from @c PF_INET domain
 *    on @p pco_iut;
 * -# Fill in ifreq_var variable of type @c struct @c ifreq structure
 *    as follows:
 *        - @a ifr_name: name of @p iut_if interface;
 *        .
 * -# Call @b ioctl(@p iut_s, @c SIOCGIFFLAGS, @p ifreq_var);
 * -# Check that the function returns @c 0;
 * -# If @a ifr_flags field of @p ifreq_var variable contains @c IFF_DEBUG
 *    flag, then reset it, otherwise set it in the field;
 * -# Call @b ioctl(@p iut_s, @c SIOCSIFFLAGS, @p ifreq_var);
 * -# Check that the function returns @c 0;
 * -# Call @b ioctl(@p iut_s, @c SIOCGIFFLAGS, @p ifreq_var);
 * -# Check that @c IFF_DEBUG flag is set/reset in @a ifr_flags field of 
 *    @p ifreq_var variable;
 * -# Restore the original set of flags;
 * -# Close @p iut_s socket;
 *
 * @author Oleg Kravtsov <Oleg.Kravtsov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "ioctls/siocifflags"

#include "sockapi-test.h"

int
main(int argc, char *argv[])
{
    rcf_rpc_server            *pco_iut = NULL;
    int                        iut_s = -1;
    rpc_socket_type            sock_type;
    const struct if_nameindex *iut_if;
    struct ifreq               ifreq_var;
    short int                  init_flags;
    short int                  new_flags;
    te_bool                    flags_updated = FALSE;
    

    /* Preambule */
    TEST_START;
    TEST_GET_SOCK_TYPE(sock_type);
    TEST_GET_PCO(pco_iut);
    
    TEST_GET_IF(iut_if);

    
    iut_s = rpc_socket(pco_iut, RPC_PF_INET, sock_type, RPC_PROTO_DEF);

    memset(&ifreq_var, 0, sizeof(ifreq_var));
    strncpy(ifreq_var.ifr_name, iut_if->if_name, sizeof(ifreq_var.ifr_name));
    rpc_ioctl(pco_iut, iut_s, RPC_SIOCGIFFLAGS, &ifreq_var);

    new_flags = init_flags = ifreq_var.ifr_flags;
    if (init_flags & IFF_DEBUG)
    {
        /* Reset IFF_DEBUG flag */
        new_flags &= (~IFF_DEBUG);
    }
    else
    {
        /* Set IFF_DEBUG flag */
        new_flags |= IFF_DEBUG;
    }

    ifreq_var.ifr_flags = new_flags;
    rpc_ioctl(pco_iut, iut_s, RPC_SIOCSIFFLAGS, &ifreq_var);
    flags_updated = TRUE;
    
    /* Get updated value */
    memset(&ifreq_var, 0, sizeof(ifreq_var));
    strncpy(ifreq_var.ifr_name, iut_if->if_name, sizeof(ifreq_var.ifr_name));
    rpc_ioctl(pco_iut, iut_s, RPC_SIOCGIFFLAGS, &ifreq_var);

    if (ifreq_var.ifr_flags != new_flags)
    {
        TEST_FAIL("ioctl(SIOCGIFFLAGS) does not update interface flags");
    }

    TEST_SUCCESS;

cleanup:

    if (flags_updated)
    {
        memset(&ifreq_var, 0, sizeof(ifreq_var));
        strncpy(ifreq_var.ifr_name, iut_if->if_name,
                sizeof(ifreq_var.ifr_name));
        ifreq_var.ifr_flags = init_flags;
        rpc_ioctl(pco_iut, iut_s, RPC_SIOCSIFFLAGS, &ifreq_var);
    }
    
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);

    TEST_END;
}

