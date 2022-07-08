/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Socket options
 * 
 * $Id$
 */

/** @page multicast-ip_add_membership_inval Inappropriate usage of IP_ADD_MEMBERSHIP socket option 
 *
 * @objective The test checks the following:
 *            - @c IP_ADD_MEMBERSHIP socket option can not be used with 
 *              @b getsockopt() function;
 *            - it is not allowed to join a unicast address;
 *            - joining to a multicast group fails if specified network 
 *              address of a local interface is not assigned to any
 *              interfaces in the system.
 *            .
 *
 * @type conformance
 *
 * @reference @ref STEVENS, section 19.5
 *
 * @param pco_iut       PCO on IUT
 * @param iut_ifname    Name of a network interface on @p pco_iut
 * @param iut_addr      IP address, assigned to @p iut_ifname
 * @param mcast_addr    Multicast IP address
 * @param na_addr       Unicast IP address, not assigned to @p iut_ifname
 * @param sock_func     Socket creation function
 *
 * @par Test sequence:
 * -# Create @p pco_iut socket from @c PF_INET domain of type @c SOCK_DGRAM
 *    on @p pco_iut.
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Call @b getsockopt() with @c IP_ADD_MEMBERSHIP socket option on 
 *    @p pco_iut socket.
 * -# Check that the function returns @c -1 and sets @b errno to 
 *    @c ENOPROTOOPT.
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Call @b setsockopt() with @c IP_ADD_MEMBERSHIP socket option on 
 *    @p pco_iut socket passing IP address @p na_addr as the value of 
 *    @a imr_interface field of @c ip_mreqn structure and @p mcast_addr 
 *    as the value of @a imr_multiaddr field of this structure.
 * -# Check that the function returns @c -1 and log the value of @b errno.
 *    See @ref sockopts_ip_add_membership_inval_1 "note 1";
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Call @b setsockopt() with @c IP_ADD_MEMBERSHIP socket option on 
 *    @p pco_iut socket passing a @p iut_addr as the value of 
 *    @a imr_interface field of @c ip_mreqn structure and some unicast 
 *    address as the value of @a imr_multiaddr field of @c ip_mreqn
 *    structure.
 * -# Check that the function returns @c -1 and sets @b errno to @c EINVAL;
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Close @p pco_iut socket.
 * 
 * @note
 * -# @anchor sockopts_ip_add_membership_inval_1
 *    Linux sets @b errno to @c ENODEV, but on FreeBSD it is set to 
 *    @c EADDRNOTAVAIL
 *
 * @author Oleg Kravtsov <Oleg.Kravtsov@oktetlabs.ru>
 * @author Konstantin Abramenko <Konstantin.Abramenko@oktetlabs.ru>
 */

#define TE_TEST_NAME  "multicast/ip_add_membership_inval"

#include "sockapi-test.h"


int
main(int argc, char *argv[])
{
    rcf_rpc_server              *pco_iut = NULL;

    struct tarpc_mreqn           mreq;
    socklen_t                    req_len;
    struct group_req             gr_req;

    int                          iut_s = -1;

    const struct if_nameindex   *iut_ifname = NULL;
    const struct sockaddr       *iut_addr = NULL;
    const struct sockaddr       *na_addr = NULL;
    const struct sockaddr       *mcast_addr = NULL;

    te_bool                      have_ip_mreqn = FALSE;

    const char                  *struct_to_use;
    rpc_sockopt                  opt;

    sockts_socket_func  sock_func;

    TEST_START;
    TEST_GET_PCO(pco_iut);

    TEST_GET_ADDR(pco_iut, na_addr);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_iut, mcast_addr);
    TEST_GET_IF(iut_ifname);
    TEST_GET_STRING_PARAM(struct_to_use);
    SOCKTS_GET_SOCK_FUNC(sock_func);

    RPC_AWAIT_IUT_ERROR(pco_iut);
    have_ip_mreqn = (rpc_get_sizeof(pco_iut, "struct ip_mreqn") != -1);

    req_len = (strcmp(struct_to_use, "ip_mreq") == 0) ? sizeof(mreq) :
                sizeof(struct group_req);

    iut_s = sockts_socket(sock_func, pco_iut, RPC_PF_INET,
                          RPC_SOCK_DGRAM, RPC_PROTO_DEF);

    /*
     * Try to get socket option
     */
    opt = (strcmp(struct_to_use, "ip_mreq") == 0) ? RPC_IP_ADD_MEMBERSHIP :
                                                    RPC_MCAST_JOIN_GROUP;
    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_getsockopt_raw(pco_iut, iut_s, opt,
                            (strcmp(struct_to_use, "ip_mreq") == 0) ?
                                (void *)&mreq : (void *)&gr_req,
                            &req_len);
    if (rc != -1)
    {
        TEST_FAIL("Unexpected rc %d from getsockopt"
                  "(iut_s, %s)", rc, sockopt_rpc2str(opt));
    }
    else
    {
        int err = RPC_ERRNO(pco_iut);

        if (err!= RPC_ENOPROTOOPT)
        {
            TEST_FAIL("Unexpected errno %X from "
                      "getsockopt(iut_s, %s)", err,
                      sockopt_rpc2str(opt));
        }
    }

    /*
     * Set option with alien IP address as interface.
     */
    if (opt == RPC_IP_ADD_MEMBERSHIP)
    {
        memset(&mreq, 0, sizeof(mreq));
        mreq.type = have_ip_mreqn ? OPT_MREQN : OPT_MREQ;
        mreq.multiaddr = SIN(mcast_addr)->sin_addr.s_addr;
        mreq.address = SIN(na_addr)->sin_addr.s_addr;

        RPC_AWAIT_IUT_ERROR(pco_iut);
        rc = rpc_setsockopt(pco_iut, iut_s, RPC_IP_ADD_MEMBERSHIP, &mreq);

        if (rc != -1)
        {
            TEST_FAIL("Unexpected rc %d from "
                      "setsockopt(iut_s, IP_ADD_MEMBERSHIP)", rc);
        }
        else
        {
            int err = RPC_ERRNO(pco_iut);

            if (err != RPC_ENODEV && err != RPC_EADDRNOTAVAIL)
            {
                RING_VERDICT("Unexpected errno %r from "
                             "setsockopt(iut_s, IP_ADD_MEMBERSHIP) "
                             "for alien local address", err);
            }
        }
    }

    /*
     * Set option with unicast IP address as multicast 
     */
    if (opt == RPC_IP_ADD_MEMBERSHIP)
    {
        memset(&mreq, 0, sizeof(mreq));
        mreq.type = have_ip_mreqn? OPT_MREQN : OPT_MREQ;
        mreq.address = SIN(iut_addr)->sin_addr.s_addr;
        mreq.multiaddr = SIN(na_addr)->sin_addr.s_addr;
    }
    else
    {
        memset(&gr_req, 0, sizeof(gr_req));
        memcpy(&gr_req.gr_group, na_addr, sizeof(struct sockaddr));
        gr_req.gr_interface = iut_ifname->if_index;
    }

    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_setsockopt(pco_iut, iut_s, opt,
                        (strcmp(struct_to_use, "ip_mreq") == 0) ?
                            (void *)&mreq : (void *)&gr_req);

    if (rc != -1)
    {
        TEST_FAIL("Unexpected rc %d from "
                  "setsockopt(iut_s, %s)", rc,
                  sockopt_rpc2str(opt));
    }
    else
    {
        int err = RPC_ERRNO(pco_iut);

        if (err != RPC_EINVAL)
        {
            TEST_VERDICT("Unexpected errno %r from "
                         "setsockopt(iut_s, %s)", err,
                         sockopt_rpc2str(opt));
        }
    }
    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);

    TEST_END;
}
