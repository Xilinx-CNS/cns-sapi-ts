/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * IOCTL Requests
 * 
 * $Id$
 */

/** @page ioctls-siocgifaddr Usage of SIOCGIFADDR request
 *
 * @objective Check that @c SIOCGIFADDR request returns 
 *            primary address of specified interface.
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
 * -# Fill in ifreq_var variable of type @c struct @c ifreq structure as
 *    follows:
 *        - @a ifr_name: name of @p iut_if interface;
 *        .
 * -# Call @b ioctl(@p iut_s, @c SIOCGIFADDR, @p ifreq_var);
 * -# Check that the function returns @c 0;
 * -# Check that @p ifreq_var variable filled in as follows:
 *        - @a ifr_name: name of @p iut_if interface;
 *        - @a ifr_addr: primary network address on @p iut_if interface;
 *        .
 * -# Close @p iut_s socket;
 *
 * @author Oleg Kravtsov <Oleg.Kravtsov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "ioctls/siocgifaddr"

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
    unsigned int               num;
    cfg_handle                *handles = NULL;
    char                      *addr_str;
    in_addr_t                  addr;
    unsigned int               i;


    /* Preambule */
    TEST_START;
    TEST_GET_SOCK_TYPE(sock_type);
    TEST_GET_PCO(pco_iut);
    
    TEST_GET_IF(iut_if);

    /*
     * 'sockaddr' structure that we expect to obtain with SIOCGIFADDR
     * ioctl request (zero port and primary network address)
     */
    CHECK_RC(cfg_find_pattern_fmt(&num, &handles, 
                                  "/agent:%s/interface:%s/net_addr:*",
                                  pco_iut->ta, iut_if->if_name));


    iut_s = rpc_socket(pco_iut, RPC_PF_INET, sock_type, RPC_PROTO_DEF);

    memset(&ifreq_var, 0, sizeof(ifreq_var));
    strncpy(ifreq_var.ifr_name, iut_if->if_name, sizeof(ifreq_var.ifr_name));
    rpc_ioctl(pco_iut, iut_s, RPC_SIOCGIFADDR, &ifreq_var);

    if (ifreq_var.ifr_addr.sa_family != AF_INET)
    {
        TEST_FAIL("SIOCGIFADDR ioctl() request does not set "
                  "'ifr_addr.sa_family' field to AF_INET");
    }
    if (SIN(&(ifreq_var.ifr_addr))->sin_port != 0)
    {
        WARN("SIOCGIFADDR ioctl() request does not set sin_port "
             "part of struct 'sockaddr_in' to zero");
    }

    for (i = 0; i < num; i++)
    {
        CHECK_RC(cfg_get_inst_name(handles[i], &addr_str));
        addr = inet_addr(addr_str);
        
        if (memcmp(&addr, &(SIN(&(ifreq_var.ifr_addr))->sin_addr),
                   sizeof(addr)) == 0)
        {
            free(addr_str);
            break;
        }
        free(addr_str);
    }
    if (i == num)
    {
        TEST_FAIL("Address obtained with SIOCGIFADDR ioctl() request "
                  "is different from expected");
    }

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);

    free(handles);

    TEST_END;
}

