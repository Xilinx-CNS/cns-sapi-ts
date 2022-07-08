/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Send a UDP packet to a destination with unresolvable ARP.
 */

/**
 * @page arp-udp_send_unavailable_arp Send a UDP packet to a destination with unresolvable ARP.
 *
 * @objective Check that the sending packet with unresolvable ARP is OK.
 *
 * @param env      Testing environment:
 *      - @ref arg_types_env_peer2peer
 *      - @ref arg_types_env_peer2peer_ipv6
 * @param bind     Call bind or not:
 *      - @c TRUE
 *      - @c FALSE
 * @param func     Sending function to test:
 *      - @c send
 *      - @c sendto
 * @param mtu      MTU used:
 *      - 1500
 *      - 8000
 * @param pkt_size Size of a UDP packet:
 *      - 128
 *      - 7000
 *      - 64000
 * @param is_recverr Set IP_RECVERR/IPV6_RECVERR option to socket
 *                   or not.
 *
 * @par Scenario:
 *
 * @author Artemii Morozov <Artemii.Morozov@oktetlabs.ru>
 */

#define TE_TEST_NAME "arp/udp_send_unavailable_arp"

#include "sockapi-test.h"

/**
 * Time in seconds until the ARP state is failed.
 * This value was obtained empirically.
 * 1s,2s,3s it is too small. 4 seconds is enough,
 * but it's better to add an extra second.
 */
#define TIME_ARP_FAILED 5

int
main(int argc, char *argv[])
{
    rcf_rpc_server            *pco_iut = NULL;
    rcf_rpc_server            *pco_tst = NULL;
    const struct sockaddr     *iut_addr = NULL;
    const struct sockaddr     *tst_fake_addr = NULL;
    const struct if_nameindex *iut_if = NULL;
    const char                *func = NULL;
    int                        mtu;
    int                        pkt_size;
    te_bool                    bind;
    te_bool                    is_recverr;

    te_saved_mtus iut_mtus = LIST_HEAD_INITIALIZER(iut_mtus);

    int   iut_s;
    void *tx_buf = NULL;
    int   optval;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_fake_addr);
    TEST_GET_IF(iut_if);
    TEST_GET_BOOL_PARAM(bind);
    TEST_GET_STRING_PARAM(func);
    TEST_GET_INT_PARAM(mtu);
    TEST_GET_INT_PARAM(pkt_size);
    TEST_GET_BOOL_PARAM(is_recverr);

    TEST_STEP("Set @p mtu on @p iut_if.");
    CHECK_RC(tapi_set_if_mtu_smart2(pco_iut->ta, iut_if->if_name,
                                    mtu, &iut_mtus));
    CFG_WAIT_CHANGES;

    TEST_STEP("Create on IUT @c SOCK_DGRAM socket.");
    iut_s = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr),
                       RPC_SOCK_DGRAM, RPC_PROTO_DEF);

    TEST_STEP("If @p bind is @c TRUE bind() @b iut_s to @p iut_addr.");
    if (bind)
        rpc_bind(pco_iut, iut_s, iut_addr);

    tx_buf = te_make_buf_by_len(pkt_size);

    if (is_recverr)
    {
        TEST_STEP("If @p is_recverr is @c TRUE set @c IP_RECVERR or @c IPV6_RECVERR "
                  "option for @b iut_s");
        rpc_setsockopt_int(pco_iut, iut_s, iut_addr->sa_family == AF_INET ?
                           RPC_IP_RECVERR : RPC_IPV6_RECVERR, 1);
    }

    TEST_STEP("If @p func is @c send call connect() and send() to "
              "@p tst_fake_addr; if @p func is @c sendto call sendto() to @p "
              "tst_fake_addr.");
    if (strcmp(func, "send") == 0)
    {
        rpc_connect(pco_iut, iut_s, tst_fake_addr);
        rpc_send(pco_iut, iut_s, tx_buf, pkt_size, 0);
    }
    else if (strcmp(func, "sendto") == 0)
    {
        rpc_sendto(pco_iut, iut_s, tx_buf, pkt_size, 0, tst_fake_addr);
    }
    else
    {
        TEST_FAIL("Parameter @p func is %s, but expected \"send\" or \"sendto\" only",
                  func);
    }

    TEST_STEP("Wait until the ARP state is failed.");
    VSLEEP(TIME_ARP_FAILED, "Wait until the ARP state is failed.");

    TEST_STEP("Call @b getsockopt() on @b iut_s socket with @c SO_ERROR "
              "option and check the result.");
    rpc_getsockopt(pco_iut, iut_s, RPC_SO_ERROR, &optval);

    if (is_recverr)
    {
        if (optval != RPC_EHOSTUNREACH)
        {
            TEST_VERDICT("getsockopt(SO_ERROR) returns unexpected errno: %r "
                         "instead of EHOSTUNREACH", optval);
        }
    }
    else
    {
        if (optval != RPC_EOK)
        {
            TEST_VERDICT("getsockopt(SO_ERROR) returns unexpected errno: %r, "
                         "instead of EOK", optval);
        }
    }

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    free(tx_buf);
    CLEANUP_CHECK_RC(tapi_set_if_mtu_smart2_rollback(&iut_mtus));

    TEST_END;
}
