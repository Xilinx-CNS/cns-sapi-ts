/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * IOCTL Requests
 * 
 * $Id$
 */

/** @page ioctls-siocifnetmask Usage of SIOCGIFNETMASK and SIOCSIFNETMASK requests
 *
 * @objective Check that @c SIOCGIFNETMASK request returns 
 *            network mask of specified interface, and @c SIOCSIFNETMASK
 *            updates network mask of specified interface.
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
 * -# Fill in @p ifreq_var variable of type @c struct @c ifreq structure
 *    as follows:
 *        - @a ifr_name: name of @p iut_if interface;
 *        .
 * -# Call @b ioctl(@p iut_s, @c SIOCGIFNETMASK, @p ifreq_var);
 * -# Check that the function returns @c 0;
 * -# Update @a ifr_netmask field of @p ifreq_var variable with a new value 
 *    (add an additional bit to the mask) - @p netmask_new;
 * -# Call @b ioctl(@p iut_s, @c SIOCSIFNETMASK, @p ifreq_var);
 * -# Check that the function returns @c 0;
 * -# Call @b ioctl(@p iut_s, @c SIOCGIFNETMASK, @p ifreq_var);
 * -# Check that the function returns @c 0 and updates @a ifr_netmask field
 *    of @p ifreq_var variable with @p nenmask_new value;
 * -# Restore the initial value of network mask on the interface;
 * -# Close @p iut_s socket;
 *
 * @author Oleg Kravtsov <Oleg.Kravtsov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "ioctls/siocifnetmask"

#include "sockapi-test.h"
#include "tapi_cfg_base.h"


int
main(int argc, char *argv[])
{
    rcf_rpc_server            *pco_iut = NULL;
    int                        iut_s = -1;
    rpc_socket_type            sock_type;
    const struct if_nameindex *iut_if;
    struct ifreq               ifreq_var;
    uint32_t                   netmask;
    struct sockaddr            init_netmask;
    struct sockaddr            new_netmask;
    te_bool                    netmask_updated = FALSE;
    uint32_t                   bit_val;
    int                        i;


    /* Preambule */
    TEST_START;
    TEST_GET_SOCK_TYPE(sock_type);
    TEST_GET_PCO(pco_iut);
    TEST_GET_IF(iut_if);

    /* 
     * Change configuration - delete all addresses except one on
     * 'iut_if' interfaces. Since ioctl with (SIOCGxxx)/(SIOCSxxx)
     * is incompatible with netlink (RTM_GETADDR)/(RTM_NEWADDR) 
     * messages output, it is the only chance for test to pass.
     */
    CHECK_RC(tapi_cfg_del_if_ip4_addresses(pco_iut->ta,
                                           iut_if->if_name, NULL));

    iut_s = rpc_socket(pco_iut, RPC_PF_INET, sock_type, RPC_PROTO_DEF);

    memset(&ifreq_var, 0, sizeof(ifreq_var));
    strncpy(ifreq_var.ifr_name, iut_if->if_name, sizeof(ifreq_var.ifr_name));

    rpc_ioctl(pco_iut, iut_s, RPC_SIOCGIFNETMASK, &ifreq_var);
    
    memcpy(&init_netmask, &(ifreq_var.ifr_netmask), sizeof(init_netmask));
    
    /* Prepare a new netmask value */
    memcpy(&new_netmask, &init_netmask, sizeof(new_netmask));
    
    /* Check the value returned */
    if (ifreq_var.ifr_netmask.sa_family != AF_INET)
    {
        TEST_FAIL("SIOCGIFNETMASK ioctl() request does not set "
                  "'ifr_netmask.sa_family' field to AF_INET");
    }
    if (SIN(&(ifreq_var.ifr_netmask))->sin_port != 0)
    {
        WARN("SIOCGIFNETMASK ioctl() request does not set sin_port "
             "part of struct 'sockaddr_in' to zero");
    }
    
    netmask = ntohl(SIN(&(ifreq_var.ifr_netmask))->sin_addr.s_addr);

    bit_val = 1;
    for (i = (sizeof(netmask) * 8) - 1; i >= 0; i--)
    {
        if (bit_val == 0)
        {
            if (netmask & (1 << i))
            {
                TEST_FAIL("Incorrect netmask value returned by "
                          "ioctl(SIOCGIFNETMASK)");
            }
        }
        else if (!(netmask & (bit_val << i)))
        {
            if (bit_val)
            {
                /* reset bit_val - we've reached zero bits */
                bit_val = 0;
                SIN(&new_netmask)->sin_addr.s_addr = 
                    htonl(ntohl(SIN(&new_netmask)->sin_addr.s_addr) | 
                            (1 << i));
            }
            else
            {
                TEST_FAIL("Incorrect netmask value returned by "
                          "ioctl(SIOCGIFNETMASK)");
            }
        }
    }
    
    memcpy(&(ifreq_var.ifr_netmask), &new_netmask, sizeof(struct sockaddr));
    rpc_ioctl(pco_iut, iut_s, RPC_SIOCSIFNETMASK, &ifreq_var);
    netmask_updated = TRUE;
    
    /* Try to get the updated value */
    memset(&ifreq_var, 0, sizeof(ifreq_var));
    strncpy(ifreq_var.ifr_name, iut_if->if_name, sizeof(ifreq_var.ifr_name));
    rpc_ioctl(pco_iut, iut_s, RPC_SIOCGIFNETMASK, &ifreq_var);

    if (te_sockaddrcmp(&(ifreq_var.ifr_netmask), sizeof(ifreq_var.ifr_netmask),
                       &new_netmask, sizeof(new_netmask)) != 0)
    {
        TEST_FAIL("ioctl(SIOCSIFNETMASK) does not update interface netmask");
    }

    TEST_SUCCESS;

cleanup:

    if (netmask_updated)
    {
        strncpy(ifreq_var.ifr_name, iut_if->if_name,
                sizeof(ifreq_var.ifr_name));
        memcpy(&(ifreq_var.ifr_netmask), &init_netmask, sizeof(init_netmask));
        rpc_ioctl(pco_iut, iut_s, RPC_SIOCSIFNETMASK, &ifreq_var);
    }

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);

    TEST_END;
}

