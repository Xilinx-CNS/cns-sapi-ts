/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Multicasting in IP
 *
 * $Id$
 */

/** @page multicast-mcast_on_tcp Multicast-related options on TCP socket.
 *
 * @objective Check that multicast-related options are not applicable
 *            to TCP sockets.
 *
 * @type Conformance.
 *
 * @param pco_iut         PCO on IUT
 * @param mcast_addr      Multicast IP address
 * @param iut_addr        Address on IUT
 * @param iut_if          Interface on IUT
 * @param opt_name        Name of multicast-related socket option
 * @param sock_func       Socket creation function
 *
 * @par Scenario:
 *
 * -# Create a stream socket @p iut_s on @p pco_iut.
 * -# Try to set @p opt_name value. Check that its result is correct.
 *    (Correct results have been obtained by an experiment).
 * -# Try to get @p opt_name value. Check that its result is correct.
 * -# If @c IP_ADD_MEMBERSHIP options was specified, do the same things
 *    with @c IP_DROP_MEMBERSHIP option.
 * -# Close @p iut_s.
 *
 * @author Ivan Soloducha <Ivan.Soloducha@oktetlabs.ru>
 */

#define TE_TEST_NAME  "multicast/mcast_on_tcp"

#include "sockapi-test.h"

int
main(int argc, char *argv[])
{
    rcf_rpc_server        *pco_iut = NULL;
    int                    iut_s = -1;
    rpc_sockopt            opt_name;
    const struct sockaddr *iut_addr = NULL;
    const struct sockaddr *mcast_addr = NULL;
    struct tarpc_mreqn     mreq;
    uint32_t               value;
    void                  *argument;
    te_bool                have_ip_mreqn = FALSE;
    const char            *operation = NULL;
    struct group_req       gr_req;

    const struct if_nameindex  *iut_if = NULL;

    sockts_socket_func  sock_func;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_SOCKOPT(opt_name);
    TEST_GET_ADDR_NO_PORT(mcast_addr);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_IF(iut_if);
    TEST_GET_STRING_PARAM(operation);
    SOCKTS_GET_SOCK_FUNC(sock_func);

    RPC_AWAIT_IUT_ERROR(pco_iut);
    have_ip_mreqn = (rpc_get_sizeof(pco_iut, "struct ip_mreqn") > 0);

    iut_s = sockts_socket(sock_func, pco_iut, RPC_AF_INET,
                          RPC_SOCK_STREAM, RPC_IPPROTO_TCP);

    switch(opt_name)
    {
        case RPC_IP_ADD_MEMBERSHIP:
        case RPC_IP_DROP_MEMBERSHIP:
        case RPC_IP_MULTICAST_IF:
        {
            mreq.type = have_ip_mreqn?
                         OPT_MREQN : ((opt_name == RPC_IP_MULTICAST_IF)?
                             OPT_IPADDR : OPT_MREQ);
            memcpy(&mreq.multiaddr, te_sockaddr_get_netaddr(mcast_addr),
                   sizeof(struct in_addr));
            memcpy(&mreq.address, te_sockaddr_get_netaddr(iut_addr),
                   sizeof(struct in_addr));
            mreq.ifindex = iut_if->if_index;

            argument = &mreq;
            break;
        }

        case RPC_MCAST_JOIN_GROUP:
        case RPC_MCAST_LEAVE_GROUP:
        {
            memset(&gr_req, 0, sizeof(gr_req));
            memcpy(&gr_req.gr_group, mcast_addr, sizeof(struct sockaddr));
            gr_req.gr_interface = iut_if->if_index;
            argument = &gr_req;
            break;
        }

        case RPC_IP_MULTICAST_TTL:
        {
            value = IP_DEFAULT_MULTICAST_TTL;
            argument = &value;
            break;
        }
        
        case RPC_IP_MULTICAST_LOOP:
        {
            value = IP_DEFAULT_MULTICAST_LOOP;
            argument = &value;
            break;
        }

        default:
        {
            TEST_FAIL("Unknown or non-multicast socket option specified");
        }
    }

    RPC_AWAIT_IUT_ERROR(pco_iut);
    if (strcmp(operation, "Set") == 0)
    {
        rc = rpc_setsockopt(pco_iut, iut_s, opt_name, argument);
    }
    else if (strcmp(operation, "Get") == 0)
    {       
        rc = rpc_getsockopt(pco_iut, iut_s, opt_name, argument);
    }
    else
    {
        TEST_FAIL("Unknown operation: %s", operation);
    }

    if (rc == 0)
    {
        TEST_VERDICT("%sting %s on TCP socket unexpectedly passed", operation,
                     sockopt_rpc2str(opt_name));
    }
    else
    {
        rpc_errno iut_errno = RPC_ERRNO(pco_iut);

        /* For solaris we have ENOPROTOOPT,
         * for linux kernel >=2.6.24 -- EPROTO
         * (for linux <=2.6.18 -- various incorrect behaviour).
         * Both ENOPROTOOPT & EPROTO are reasonable, so accept them. */
        if (iut_errno != RPC_ENOPROTOOPT && iut_errno != RPC_EPROTO)
        {
            TEST_VERDICT("Unexpected errno %r instead of ENOPROTOOPT",
                         iut_errno);
        }
    }
   
    TEST_SUCCESS;

cleanup:    
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    TEST_END;
}
