/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * IOCTL Requests
 * 
 * $Id$
 */

/** @page ioctls-siocifmtu Usage of SIOCGIFMTU and SIOCSIFMTU requests
 *
 * @objective Check that @c SIOCGIFMTU request returns MTU of specified
 *            interface, and @c SIOCSIFMTU sets a new MTU value.
 *
 * @type conformance
 *
 * @reference @ref STEVENS section 16.6
 *
 * @param sock_type     Type of socket used in the test
 * @param pco_iut       PCO on IUT
 * @param iut_if        One of @p pco_iut interfaces
 *
 * @par Test sequence:
 * -# Create @p iut_s socket of type @p sock_type from @c PF_INET domain
 *    on @p pco_iut;
 * -# Fill in @p ifreq_var variable of type @c struct @c ifreq
 *    structure as follows:
 *        - @a ifr_name: name of @p iut_if interface;
 *        .
 * -# Call @b ioctl(@p iut_s, @c SIOCGIFMTU, @p ifreq_var);
 * -# Check that the function returns @c 0;
 * -# Fill in @p ifreq_var variable of type @c struct @c ifreq
 *    structure as follows:
 *        - @a ifr_name: name of @p iut_if interface;
 *        - @a ifr_mtu: some value that is different from obtained -
 *          @p new_mtu;
 *        .
 * -# Call @b ioctl(@p iut_s, @c SIOCSIFMTU, @p ifreq_var);
 * -# Check that the function returns @c 0;
 * -# Call @b ioctl(@p iut_s, @c SIOCGIFMTU, @p ifreq_var);
 * -# Check that the function returns @c and updates @a ifr_mtu field of 
 *    @c ifreq structure with @p new_mtu;
 * -# Restore the initial value of MTU on the interface;
 * -# Close @p iut_s socket;
 *
 * @author Oleg Kravtsov <Oleg.Kravtsov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "ioctls/siocifmtu"

#include "sockapi-test.h"
#include "tapi_cfg.h"
#include "tapi_cfg_base.h"

int
main(int argc, char *argv[])
{
    rcf_rpc_server            *pco_iut = NULL;
    int                        iut_s = -1;
    rpc_socket_type            sock_type;
    const struct if_nameindex *iut_if;
    struct ifreq               ifreq_var;
    int                        init_mtu;
    int                        new_mtu;
    te_bool                    mtu_updated = FALSE;


    /* Preambule */
    TEST_START;
    TEST_GET_SOCK_TYPE(sock_type);
    TEST_GET_PCO(pco_iut);
    TEST_GET_IF(iut_if);

    
    iut_s = rpc_socket(pco_iut, RPC_PF_INET, sock_type, RPC_PROTO_DEF);

    CHECK_RC(cfg_get_instance_fmt(NULL, &init_mtu,
                                  "/agent:%s/interface:%s/mtu:",
                                  pco_iut->ta, iut_if->if_name));

    memset(&ifreq_var, 0, sizeof(ifreq_var));
    strncpy(ifreq_var.ifr_name, iut_if->if_name, sizeof(ifreq_var.ifr_name));

    rpc_ioctl(pco_iut, iut_s, RPC_SIOCGIFMTU, &ifreq_var);
    if (ifreq_var.ifr_mtu != init_mtu)
    {
        TEST_VERDICT("Interface MTU obtained with ioctl(SIOCGIFMTU) is "
                     "different from MTU assigned on the interface");
    }

    /* 
     * If MTU is set to value less than 1280, Linux disables IPv6 on the
     * interface and does not enable when MTU becomes greater or equal
     * to 1280.
     */
    if (init_mtu > 1280)
        new_mtu = rand_range(1280, init_mtu - 1);
    else
        new_mtu = rand_range(600, init_mtu - 1);

    ifreq_var.ifr_mtu = new_mtu;
    rpc_ioctl(pco_iut, iut_s, RPC_SIOCSIFMTU, &ifreq_var);
    mtu_updated = TRUE;
    
    /* Try to get the updated value */
    memset(&ifreq_var, 0, sizeof(ifreq_var));
    strncpy(ifreq_var.ifr_name, iut_if->if_name, sizeof(ifreq_var.ifr_name));
    rpc_ioctl(pco_iut, iut_s, RPC_SIOCGIFMTU, &ifreq_var);
    
    if (ifreq_var.ifr_mtu != new_mtu)
    {
        TEST_FAIL("ioctl(SIOCSIFMTU) does not update interface MTU");
    }

    TEST_SUCCESS;

cleanup:

    if (mtu_updated)
    {
        strncpy(ifreq_var.ifr_name, iut_if->if_name,
                sizeof(ifreq_var.ifr_name));
        ifreq_var.ifr_mtu = init_mtu;
        rpc_ioctl(pco_iut, iut_s, RPC_SIOCSIFMTU, &ifreq_var);
        CLEANUP_CHECK_RC(tapi_cfg_base_if_down(pco_iut->ta,
                                               iut_if->if_name));
        CLEANUP_CHECK_RC(tapi_cfg_base_if_up(pco_iut->ta,
                                             iut_if->if_name));
        CFG_WAIT_CHANGES;
    }

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);

    TEST_END;
}

