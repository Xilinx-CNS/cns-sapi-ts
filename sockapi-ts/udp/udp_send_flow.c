/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * UDP tests
 *
 * $Id$
 */

/** @page udp-udp_send_flow  Send datagrams flow
 *
 * @objective  Send datagrams flow with various write functions
 *
 * @type conformance
 *
 * @param pco_iut       PCO on IUT
 * @param pco_tst1      PCO on TESTER Agt_B
 * @param pco_tst2      PCO on TESTER Agt_C
 * @param func          Function to send data flow
 * @param length_min    Minimum datagram langth
 * @param length_max    Maximum datagram langth
 * @param mtu           MTU value
 * @param epsilon       Actual set MTU = @p mtu - @p epsilon
 * @param total         Minimum transmitted data amount
 * @param change_route  Change route to send datagram to TST interface
 *
 * @par Test sequence:
 *
 * @author Andrey Dmitrov <Andrey.Dmitrov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "udp/udp_send_flow"

#include "sockapi-test.h"

/* Theoretical maximum datagram size. */
#define MAX_DGRAM 65507

/**
 * Set a specific route for the address @p dst_addr.
 * 
 * @param rpcs      RPC server
 * @param dst_addr  Destination address
 * @param src_if    Interface name
 */
static void
change_traffic_route(rcf_rpc_server *rpcs,
                     const struct sockaddr *dst_addr,
                     const struct if_nameindex *src_if)
{
    cfg_handle rt_handle;
    size_t route_prefix;

    route_prefix = te_netaddr_get_size(addr_family_rpc2h(
        sockts_domain2family(rpc_socket_domain_by_addr(dst_addr)))) * 8;

    CHECK_RC(tapi_cfg_add_route(rpcs->ta, SA(dst_addr)->sa_family, 
            te_sockaddr_get_netaddr(dst_addr), route_prefix,
            NULL, src_if->if_name, NULL,
            0, 0, 0, 0, 0, 0, &rt_handle));
}

int
main(int argc, char *argv[])
{
    rcf_rpc_server         *pco_iut = NULL;
    rcf_rpc_server         *pco_tst1 = NULL;
    rcf_rpc_server         *pco_tst2 = NULL;
    rcf_rpc_server         *pco_tst = NULL;
    const struct sockaddr *iut_addr1;
    const struct sockaddr *tst_addr;
    const struct sockaddr *tst1_addr;
    const struct sockaddr *tst2_addr;
    const struct if_nameindex *iut_if;
    const struct if_nameindex *iut_if1;
    const struct if_nameindex *iut_if2;
    const struct if_nameindex *tst_if;
    const struct if_nameindex *tst1_if;
    const struct if_nameindex *tst2_if;
    rpc_send_f   func;
    te_bool      change_route;
    char        *sndbuf = NULL;
    char        *rcvbuf = NULL;
    cfg_handle   ah = CFG_HANDLE_INVALID;

    int epsilon;
    int length_min;
    int length_max;
    int length_max_rcv;
    int total;
    int mtu;
    int iut_s = -1;
    int tst_s = -1;
    int sent = 0;
    int len;
    int offt;

    te_bool verdict_printed = FALSE;

    te_saved_mtus   iut_mtus = LIST_HEAD_INITIALIZER(iut_mtus);
    te_saved_mtus   tst_mtus = LIST_HEAD_INITIALIZER(tst_mtus);

    tarpc_timeval   tv = {1, 0};
    int             tst_recv_fails = 0;

    rpc_socket_domain domain;

    TEST_START;
    TEST_GET_BOOL_PARAM(change_route);

    TEST_GET_PCO(pco_iut);

    if (change_route)
    {
        TEST_GET_PCO(pco_tst1);
        TEST_GET_PCO(pco_tst2);
        TEST_GET_ADDR(pco_iut, iut_addr1);
        TEST_GET_ADDR(pco_tst1, tst1_addr);
        TEST_GET_ADDR(pco_tst2, tst2_addr);
        TEST_GET_IF(iut_if1);
        TEST_GET_IF(iut_if2);
        TEST_GET_IF(tst1_if);
        TEST_GET_IF(tst2_if);

        pco_tst = pco_tst2;
        tst_addr = tst1_addr;
        iut_if = iut_if1;
        tst_if = tst1_if;
    }
    else
    {
        TEST_GET_PCO(pco_tst);
        TEST_GET_ADDR(pco_tst, tst_addr);
        TEST_GET_IF(iut_if);
        TEST_GET_IF(tst_if);
    }

    TEST_GET_INT_PARAM(mtu);
    TEST_GET_INT_PARAM(epsilon);
    TEST_GET_INT_PARAM(total);
    TEST_GET_INT_PARAM(length_min);
    TEST_GET_INT_PARAM(length_max);
    TEST_GET_SEND_FUNC(func);

    if (length_min > length_max)
        TEST_FAIL("length_min must not be greater than length_max");
    if (length_min < 0)
        TEST_FAIL("length_min must not be less than 0");

    TEST_STEP("Set requested MTU.");
    if (mtu != 0)
    {
        mtu -= epsilon;
        CHECK_RC(tapi_set_if_mtu_smart2(pco_iut->ta, iut_if->if_name,
                                        mtu, &iut_mtus));
        CHECK_RC(tapi_set_if_mtu_smart2(pco_tst->ta, tst_if->if_name,
                                        mtu, &tst_mtus));
        CFG_WAIT_CHANGES;
    }
    CHECK_RC(tapi_cfg_base_if_get_mtu_u(pco_iut->ta, iut_if->if_name, &mtu));

    domain = rpc_socket_domain_by_addr(tst_addr);

    iut_s = rpc_socket(pco_iut, domain, RPC_SOCK_DGRAM, RPC_PROTO_DEF);
    tst_s = rpc_socket(pco_tst, domain, RPC_SOCK_DGRAM, RPC_PROTO_DEF);
    rpc_connect(pco_iut, iut_s, tst_addr);

    /* Set tester receiving timeout to 1 second. */
    rpc_setsockopt(pco_tst, tst_s, RPC_SO_RCVTIMEO, &tv);

    if (change_route)
    {
        CHECK_RC(tapi_cfg_save_del_if_addresses(pco_tst2->ta,
                                                tst2_if->if_name,
                                                tst2_addr, FALSE,
                                                NULL, NULL, NULL, NULL,
                                                domain_rpc2h(domain)));
        /* Add  IP address to interface with /24 (IPv4) of /48 (IPv6) prefix*/
        CHECK_RC(tapi_cfg_base_if_add_net_addr(pco_tst2->ta, tst2_if->if_name,
                                               tst1_addr,
                                               domain == RPC_PF_INET ? 24 : 48,
                                               FALSE, &ah));
        change_traffic_route(pco_iut, tst1_addr, iut_if2);
        CFG_WAIT_CHANGES;
    }

    rpc_bind(pco_tst, tst_s, tst_addr);

    sndbuf = te_make_buf_by_len(length_max);
    length_max_rcv = length_max + 100;
    rcvbuf = te_make_buf_by_len(length_max_rcv);

    TEST_STEP("Send one-byte datagram to provoke ARP resolution.");
    rpc_write(pco_iut, iut_s, sndbuf, 1);
    rpc_read(pco_tst, tst_s, rcvbuf, 1);
    TAPI_WAIT_NETWORK;

    TEST_STEP("The frsit datagram can be lost if the datagram length is greater "
              "than MTU size or route is changed. So the pilot datagram is sent and "
              "handled in the special way.");
    if (length_max > MAX_DGRAM)
        RPC_AWAIT_IUT_ERROR(pco_iut);
    else
        RPC_AWAIT_ERROR(pco_iut);
    rc = func(pco_iut, iut_s, sndbuf, length_max, 0);
    if (length_max > MAX_DGRAM)
    {
        if (rc != -1)
            TEST_VERDICT("RPC call was unexpectedly succeeded");
        if (RPC_ERRNO(pco_iut) != RPC_EMSGSIZE)
            TEST_VERDICT("RPC call failed with unexpected errno %r",
                         RPC_ERRNO(pco_iut));
        TEST_SUCCESS;
    }
    else if (rc < 0)
    {
        TEST_VERDICT("The first call of RPC function to send data flow failed "
                     "with errno %r", RPC_ERRNO(pco_iut));
    }

    TAPI_WAIT_NETWORK;
    RPC_AWAIT_IUT_ERROR(pco_tst);
    rc = rpc_recv(pco_tst, tst_s, rcvbuf, length_max_rcv,
                  RPC_MSG_DONTWAIT);
    if (rc < 0 && RPC_ERRNO(pco_tst) != RPC_EAGAIN)
        TEST_VERDICT("Tester failed to receive the first datagram with "
                     "unexpected errno %r", RPC_ERRNO(pco_tst));

    TEST_STEP("Send data flow from IUT. Total data amount is equal to @p total.");
    while (sent < total)
    {
        len = rand_range(length_min, length_max);
        offt = rand_range(0, length_max - len);

        rc = func(pco_iut, iut_s, sndbuf + offt, len, 0);
        if (rc != len)
            TEST_FAIL("Failed to send a data packet");

        /*
         * Sometimes tester can fail to reassemble
         * a heavily-fragmented datagram. So in case of EAGAIN error
         * continue test execution.
         */
        RPC_AWAIT_ERROR(pco_tst);
        rc = rpc_recv(pco_tst, tst_s, rcvbuf, length_max_rcv, 0);
        if (rc < 0 && RPC_ERRNO(pco_tst) == RPC_EAGAIN)
        {
            /*
             * Tester must not fail when receiving non-fragmented
             * datagrams sent via SFC link.
             */
            if (len < mtu && !change_route)
            {
                if (!verdict_printed)
                {
                    RING_VERDICT("Tester failed to receive datagram");
                    verdict_printed = TRUE;
                }
            }
            else
            {
                ++tst_recv_fails;
                ERROR("Datagram has been lost.");
            }
        }
        else if (rc != len || memcmp(sndbuf + offt, rcvbuf, len) != 0)
        {
            TEST_FAIL("Received packet differs from the sent one.");
        }

        sent += len;
    }

    if (tst_recv_fails > 0)
        ERROR("Number of lost datagrams: %d", tst_recv_fails);

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    CLEANUP_CHECK_RC(tapi_set_if_mtu_smart2_rollback(&iut_mtus));
    CLEANUP_CHECK_RC(tapi_set_if_mtu_smart2_rollback(&tst_mtus));

    free(sndbuf);
    free(rcvbuf);

    TEST_END;
}
