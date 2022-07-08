/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Socket options
 * 
 * $Id$
 */

/** @page multicast-ip_drop_membership_inval Inappropriate usage of IP_DROP_MEMBERSHIP socket option
 *
 * @objective  The test checks the following:
 *            - @c IP_DROP_MEMBERSHIP socket option can not be used with 
 *              @b getsockopt() function;
 *            - it is not allowed to leave a unicast address;
 *            - leaving not joined multicast address fails;
 *            - leaving to a multicast group fails if specified network 
 *              address of a local interface is not assigned to any
 *              interfaces in the system.
 *
 * @type conformance
 *
 * @reference @ref STEVENS, section 19.5
 *
 * @param pco_iut       PCO on IUT
 * @param mcast_addr    Multicast IP address
 * @param iut_ifname1   Network interface on @p pco_iut
 * @param iut_ifname2   Network interface on @p pco_iut
 * @param sock_func     Socket creation function
 *
 * @par Test sequence:
 * -# Create datagram socket @p iut_s on @p pco_iut.
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Try to call @b getsockopt() for @c IP_DROP_MEMBERSHIP socket option
 *    on @p iut_s. Check that it fails with @c ENOPROTOOPT error.
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Call @b setsockopt() with @c IP_DROP_MEMBERSHIP socket option on 
 *    @p pco_iut socket passing @c ip_mreqn structure:
 *    - @a imr_address: one of local address assigned to the system;
 *    - @a imr_multiaddr: some unicast address.
 * -# Check that it fails with @c EADDRNOTAVAIL or @c EINVAL (for Solaris)
 *    error.
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Call @b setsockopt() with @c IP_DROP_MEMBERSHIP socket option on 
 *    @p pco_iut socket passing @c ip_mreqn structure:
 *    - @a imr_address: some IP address that is not assigned to any
 *           @p pco_iut interface;
 *    - @a imr_multiaddr: some multicast address.
 * -# Check that the function returns @c -1 and sets @b errno to 
 *    @c EADDRNOTAVAIL.
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Call @b setsockopt() with @c IP_DROP_MEMBERSHIP socket option on 
 *    @p pco_iut socket passing @c ip_mreqn structure:
 *    - @a imr_address: one of local address assigned to the system;
 *    - @a imr_multiaddr: @p mcast_addr.
 * -# Check that the function returns @c -1 and sets @b errno to 
 *    @c EADDRNOTAVAIL.
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Call @b setsockopt() function with @c IP_ADD_MEMBERSHIP socket option
 *    on @p pco_iut socket joining it to @p mcast_addr multicast group on 
 *    @p iut_ifname1 interface.
 * -# Call @b setsockopt() with @c IP_DROP_MEMBERSHIP socket option on 
 *    @p pco_iut socket passing @c ip_mreqn structure:
 *    - @a imr_address: address of @p iut_ifname2 interface;
 *    - @a imr_multiaddr: @p mcast_addr.
 * -# Check that the function returns @c -1 and sets @b errno to 
 *    @c EADDRNOTAVAIL.
 * -# Call @b setsockopt() function with @c IP_DROP_MEMBERSHIP socket option
 *    on @p pco_iut socket leaving @p mcast_addr multicast group on 
 *    @p iut_ifname1 interface.
 * -# Check that the function returns @c 0.
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Close @p pco_iut socket.
 * 
 * @author Oleg Kravtsov <Oleg.Kravtsov@oktetlabs.ru>
 * @author Konstantin Abramenko <Konstantin.Abramenko@oktetlabs.ru>
 */

#define TE_TEST_NAME  "multicast/ip_drop_membership_inval"

#include "sockapi-test.h"


int
main(int argc, char *argv[])
{
    rcf_rpc_server              *pco_iut = NULL;

    struct tarpc_mreqn           mreq;

    int                          iut_s = -1;

    const struct if_nameindex   *iut_ifname = NULL;
    const struct sockaddr       *iut_addr1 = NULL;
    const struct sockaddr       *iut_addr2 = NULL;
    const struct sockaddr       *na_addr = NULL;
    const struct sockaddr       *mcast_addr = NULL;

    te_bool                      have_ip_mreqn = FALSE;

    sockts_socket_func           sock_func;
    
    TEST_START;
    TEST_GET_PCO(pco_iut);
    
    TEST_GET_ADDR(pco_iut, na_addr);
    TEST_GET_ADDR(pco_iut, iut_addr1);
    TEST_GET_ADDR(pco_iut, iut_addr2);
    TEST_GET_ADDR(pco_iut, mcast_addr);
    TEST_GET_IF(iut_ifname);
    SOCKTS_GET_SOCK_FUNC(sock_func);

    RPC_AWAIT_IUT_ERROR(pco_iut);
    have_ip_mreqn = (rpc_get_sizeof(pco_iut, "struct ip_mreqn") != -1);

    iut_s = sockts_socket(sock_func, pco_iut, RPC_PF_INET,
                          RPC_SOCK_DGRAM, RPC_PROTO_DEF);

    /*
     * Try to get socket option. This is performed only if IUT
     * has ip_mreqn structure because getsockopt() RPC implementation uses it.
     */
    if (have_ip_mreqn)
    {
        memset(&mreq, 0, sizeof(mreq));
        mreq.type = OPT_MREQN;
        RPC_AWAIT_IUT_ERROR(pco_iut);
        rc = rpc_getsockopt(pco_iut, iut_s, RPC_IP_DROP_MEMBERSHIP, &mreq);
        if (rc != -1)
        {
            TEST_VERDICT("Unexpected rc %d from getsockopt(iut_s, "
                         "IP_DROP_MEMBERSHIP)", rc);
        }
        else
        {
            int err = RPC_ERRNO(pco_iut);
                                    
            if (err!= RPC_ENOPROTOOPT)
            {
                RING_VERDICT("Unexpected errno %r from "
                             "getsockopt(iut_s, IP_DROP_MEMBERSHIP)", err);
            }
        }
    }
  
    /*
     * Try to leave multicast group with non-multicast address
     */
    FILL_TARPC_MREQN(mreq, na_addr, iut_addr1, iut_ifname->if_index);
    if (!have_ip_mreqn)
        mreq.type = OPT_MREQ;

    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_setsockopt(pco_iut, iut_s, RPC_IP_DROP_MEMBERSHIP, &mreq);
    if (rc != -1)
    {
        TEST_FAIL("Unexpected rc %d from setsockopt(iut_s, IP_DROP_MEMBERSHIP)",
                  rc);
    }
    else
    {
        int err = RPC_ERRNO(pco_iut);
                                   
        if (err != RPC_EADDRNOTAVAIL && err != RPC_EINVAL)
        {
            TEST_FAIL("Unexpected errno %r from "
                      "setsockopt(iut_s, IP_DROP_MEMBERSHIP)", err);
        }
    }

    /*
     * Try to leave multicast group on non-existent interface
     */
    FILL_TARPC_MREQN(mreq, mcast_addr, na_addr, iut_ifname->if_index);
    if (!have_ip_mreqn)
        mreq.type = OPT_MREQ;

    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_setsockopt(pco_iut, iut_s, RPC_IP_DROP_MEMBERSHIP, &mreq);
    if (rc != -1)
    {
        TEST_FAIL("Unexpected rc %d from setsockopt(iut_s, IP_DROP_MEMBERSHIP)",
                  rc);
    }
    else
    {
        int err = RPC_ERRNO(pco_iut);
                                   
        if (err != RPC_EADDRNOTAVAIL)
        {
            RING_VERDICT("Unexpected errno %r from "
                         "setsockopt(iut_s, IP_DROP_MEMBERSHIP) "
                         "for absent interface", err);
        }
    } 

    /*
     * Try to drop non-existent multicast group
     */
    FILL_TARPC_MREQN(mreq, mcast_addr, iut_addr1, 0);
    if (!have_ip_mreqn)
        mreq.type = OPT_MREQ;

    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_setsockopt(pco_iut, iut_s, RPC_IP_DROP_MEMBERSHIP, &mreq);
    if (rc != -1)
    {
        TEST_FAIL("Unexpected rc %d from setsockopt(iut_s, IP_DROP_MEMBERSHIP)",
                  rc);
    }
    else
    {
        int err = RPC_ERRNO(pco_iut);
                                   
        if (err != RPC_EADDRNOTAVAIL)
        {
            RING_VERDICT("Unexpected errno %r from "
                         "setsockopt(iut_s, IP_DROP_MEMBERSHIP) "
                         "for non-joined group", err); 
        }
    } 

    /*
     * Set option with unicast IP address as multicast 
     */
    FILL_TARPC_MREQN(mreq, mcast_addr, iut_addr1, 0);
    if (!have_ip_mreqn)
        mreq.type = OPT_MREQ;
    {
        struct sockaddr_in iut_addr_to_bind;
        
        memcpy(&iut_addr_to_bind, mcast_addr, te_sockaddr_get_size(mcast_addr));
        te_sockaddr_set_wildcard(SA(&iut_addr_to_bind));

        rpc_bind(pco_iut, iut_s, SA(&iut_addr_to_bind));
    }

    rpc_setsockopt(pco_iut, iut_s, RPC_IP_ADD_MEMBERSHIP, &mreq);

    /*
     * Try to drop multicast group on wrong local address
     */
    FILL_TARPC_MREQN(mreq, mcast_addr, iut_addr2, 0);
    if (!have_ip_mreqn)
        mreq.type = OPT_MREQ;

    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_setsockopt(pco_iut, iut_s, RPC_IP_DROP_MEMBERSHIP,
                        &mreq);
    if (rc != -1)
    {
        TEST_FAIL("Unexpected rc %d from setsockopt(iut_s, IP_DROP_MEMBERSHIP)",
                  rc);
    }
    else
    {
        int err = RPC_ERRNO(pco_iut);
                                   
        if (err != RPC_EADDRNOTAVAIL)
        {
            TEST_FAIL("Unexpected errno %r from "
                      "setsockopt(iut_s, IP_DROP_MEMBERSHIP)", err); 
        }
    } 

    /*
     * Drop set above multicast group on iface1
     */
    FILL_TARPC_MREQN(mreq, mcast_addr, iut_addr1, 0);
    if (!have_ip_mreqn)
        mreq.type = OPT_MREQ;

    rpc_setsockopt(pco_iut, iut_s, RPC_IP_DROP_MEMBERSHIP, &mreq);

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);

    TEST_END;
}

