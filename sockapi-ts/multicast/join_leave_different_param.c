/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Multicasting in IP
 *
 * $Id$
 */

/** @page multicast-join_leave_different_param Joining group and leaving it with slightly changed parameters.
 *
 * @objective Check that multicast group can be leaved only
 *            with same parameters as it was joined.
 * 
 * @type Conformance.
 *
 * @param pco_tst           PCO on Tester
 * @param pco_iut           PCO on IUT
 * @param iut_if1           
 * @param iut_if2           IUT interfaces
 * @param iut_addr1         IUT address assigned to @p iut_if1
 * @param iut_addr2         IUT address assigned to @p iut_if2
 * @param mcast_addr        Multicast address
 * @param change_address    Whether to change imr_address
 * @param change_ifindex    Whether to change imr_ifindex
 * @param sock_func         Socket creation function
 *
 * @par Scenario:
 * -# Open datagram socket: @p iut_s on @p pco_iut.
 * -# Adjoin it to multicast group @p mcast_addr on interface @p iut_if1
 *    with local address @p iut_addr1.
 * -# Try to leave the group with parameter:
 *     -# If @p change_address = @c TRUE, use @p iut_addr2
 *        instead of @p iut_addr1.
 *     -# if @p change_ifindex = @c TRUE, use @p iut_if2
 *        instead of @p iut_if1.
 *     -# if @p zero_other is TRUE - make oposite parameter zero
 * -# If it succeeds, test is failed.
 * -# Leave @p mcast_addr group on @p iut_s with correct parameters.
 * -# Close @p iut_s.
 *                 
 * @author Ivan Soloducha <Ivan.Soloducha@oktetlabs.ru>
 */
#define TE_TEST_NAME "multicast/join_leave_different_param"

#include "sockapi-test.h"

int
main(int argc, char *argv[])
{
    rpc_socket_domain          domain;
    rcf_rpc_server            *pco_iut = NULL;
    const struct sockaddr     *iut_addr1 = NULL;
    const struct sockaddr     *iut_addr2 = NULL;
    const struct sockaddr     *mcast_addr = NULL;
    int                        iut_s = -1;
    const struct if_nameindex *iut_if1 = NULL;
    const struct if_nameindex *iut_if2 = NULL;
    te_bool                    change_address;
    te_bool                    change_ifindex;

    struct tarpc_mreqn         mreq;
    te_bool                    have_ip_mreqn;
    te_bool                    zero_other;
    struct group_req           gr_req;

    const char                *struct_to_use;

    rpc_sockopt                opt_add;
    rpc_sockopt                opt_drop;
    void                      *opt_val;

    sockts_socket_func  sock_func;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_ADDR(pco_iut, iut_addr1);
    TEST_GET_ADDR(pco_iut, iut_addr2);
    TEST_GET_ADDR(pco_iut, mcast_addr);
    TEST_GET_IF(iut_if1);
    TEST_GET_IF(iut_if2);
    TEST_GET_BOOL_PARAM(change_ifindex);
    TEST_GET_BOOL_PARAM(change_address);
    TEST_GET_BOOL_PARAM(zero_other);
    TEST_GET_STRING_PARAM(struct_to_use);
    SOCKTS_GET_SOCK_FUNC(sock_func);

    domain = rpc_socket_domain_by_addr(iut_addr1);
    if (strcmp(struct_to_use, "mreq") == 0)
    {
        opt_add = RPC_IP_ADD_MEMBERSHIP;
        opt_drop = RPC_IP_DROP_MEMBERSHIP;
        opt_val = &mreq;

        RPC_AWAIT_IUT_ERROR(pco_iut);
        have_ip_mreqn = (rpc_get_sizeof(pco_iut, "struct ip_mreqn") != -1);

        FILL_TARPC_MREQN(mreq, mcast_addr, iut_addr1, iut_if1->if_index);

        if (!have_ip_mreqn)
            mreq.type = OPT_MREQ;
    }
    else
    {
        opt_add = RPC_MCAST_JOIN_GROUP;
        opt_drop = RPC_MCAST_LEAVE_GROUP;
        opt_val = &gr_req;

        memset(&gr_req, 0, sizeof(gr_req));
        memcpy(&gr_req.gr_group, mcast_addr, sizeof(struct sockaddr));
        gr_req.gr_interface = iut_if1->if_index;
    }

    iut_s = sockts_socket(sock_func, pco_iut, domain,
                          RPC_SOCK_DGRAM, RPC_IPPROTO_UDP);

    rpc_setsockopt(pco_iut, iut_s, opt_add, opt_val);

    RPC_AWAIT_IUT_ERROR(pco_iut);

    if (change_address)
    {
        memcpy(&mreq.address, te_sockaddr_get_netaddr(iut_addr2),
               sizeof(struct in_addr));
        if (zero_other)
            mreq.ifindex = 0;
    }

    if (change_ifindex)
    {
        if (strcmp(struct_to_use, "mreq") == 0)
            mreq.ifindex = iut_if2->if_index;
        else
            gr_req.gr_interface = iut_if2->if_index;
        if (zero_other)
            /*
             * may be zeroing should be done via INADDR_ANY, but
             * in 10 other tests nobody does that
             */
            memset(&mreq.address, 0, sizeof(mreq.address));
    }

    if (!change_ifindex && !change_address)
    {
        WARN("Either 'change_address' or 'change_ifindex' must be TRUE,"
             " otherwise test has no use.");
        rc = -1;
    }
    else
    {
        RPC_AWAIT_IUT_ERROR(pco_iut);
        rc = rpc_setsockopt(pco_iut, iut_s, opt_drop, opt_val);
    }

    if (rc != -1)
    {
        TEST_VERDICT("Leaving group with incorrect parameters succeeded");
    }
    else
    {
        int err = RPC_ERRNO(pco_iut);

        if (err != RPC_EADDRNOTAVAIL)
        {
            TEST_FAIL("Unexpected errno %X from setsockopt()", err);
        }
    }

    if (strcmp(struct_to_use, "mreq") == 0)
    {
        FILL_TARPC_MREQN(mreq, mcast_addr, iut_addr1, iut_if1->if_index);

        if (!have_ip_mreqn)
            mreq.type = OPT_MREQ;
    }
    else
        gr_req.gr_interface = iut_if1->if_index;

    rpc_setsockopt(pco_iut, iut_s, opt_drop, opt_val);

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    TEST_END;
}
