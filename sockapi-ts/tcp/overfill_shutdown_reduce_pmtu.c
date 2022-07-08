/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * TCP protocol special cases
 */

/**
 * @page tcp-overfill_shutdown_reduce_pmtu Overfill send buffer, shutdown connection, reduce MTU, receive all data on peer
 *
 * @objective Check what happens when after overfilling send buffer
 *            shutdown(@c SHUT_RDWR) is called on IUT socket, then
 *            MTU on IUT link is reduced, then peer socket on
 *            Tester tries to read all the data.
 *
 * @param env       Testing environment:
 *                  - @ref arg_types_env_peer2peer
 *                  - @ref arg_types_env_peer2peer_ipv6
 *
 * @par Scenario:
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME "tcp/overfill_shutdown_reduce_pmtu"

#include "sockapi-test.h"

/* How long to receive data on Tester, in seconds */
#define TIMEOUT_GET_DATA    5
/* Minimum allowed MTU for IPv6 */
#define MIN_IPV6_MTU        1280

int
main(int argc, char *argv[])
{
    rcf_rpc_server     *pco_iut = NULL;
    rcf_rpc_server     *pco_tst = NULL;

    const struct sockaddr  *iut_addr = NULL;
    const struct sockaddr  *tst_addr = NULL;

    const struct if_nameindex   *iut_if = NULL;
    const struct if_nameindex   *tst_if = NULL;

    int             iut_s = -1;
    int             tst_s = -1;

    uint64_t        sent;
    uint64_t        received;
    int             init_mtu;
    int             new_mtu;
    te_saved_mtus   iut_mtus = LIST_HEAD_INITIALIZER(iut_mtus);
    te_saved_mtus   tst_mtus = LIST_HEAD_INITIALIZER(tst_mtus);

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_IF(iut_if);
    TEST_GET_IF(tst_if);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);

    TEST_STEP("Establish TCP connection.");
    GEN_CONNECTION(pco_iut, pco_tst, RPC_SOCK_STREAM, RPC_IPPROTO_TCP,
                   iut_addr, tst_addr, &iut_s, &tst_s);

    TEST_STEP("Get initial value of MTU with @c IP_MTU socket option.");
    rpc_getsockopt(pco_iut, iut_s, RPC_IP_MTU, &init_mtu);

    TEST_STEP("Send data from IUT socket until send buffer is overfilled.");
    rpc_overfill_buffers(pco_iut, iut_s, &sent);

    TEST_STEP("Call @b shutdown(@c SHUT_RDWR) on the IUT socket.");
    rpc_shutdown(pco_iut, iut_s, RPC_SHUT_RDWR);

    TEST_STEP("Reduce MTU on the IUT link.");
    new_mtu = MAX(init_mtu / 2, MIN_IPV6_MTU);
    if (new_mtu >= init_mtu)
        TEST_FAIL("Failed to choose smaller MTU");
    CHECK_RC(tapi_set_if_mtu_smart2(pco_iut->ta, iut_if->if_name,
                                    new_mtu, &iut_mtus));
    CHECK_RC(tapi_set_if_mtu_smart2(pco_tst->ta, tst_if->if_name,
                                    new_mtu, &tst_mtus));
    CFG_WAIT_CHANGES;

    TEST_STEP("Try to receive all the data on Tester, check that the "
              "same number of bytes is received as that which was sent.");

    RPC_AWAIT_ERROR(pco_tst);
    rc = rpc_simple_receiver(pco_tst, tst_s,
                             TIMEOUT_GET_DATA,
                             &received);
    if (rc < 0)
    {
        TEST_VERDICT("rpc_simple_receiver() failed with errno %r",
                     RPC_ERRNO(pco_tst));
    }
    if (received != sent)
    {
        ERROR("Sent %" TE_PRINTF_64 "u bytes, received %"
              TE_PRINTF_64 "u bytes",
              sent, received);
        TEST_VERDICT("Number of received bytes did not match number of "
                     "sent bytes");
    }

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    CLEANUP_CHECK_RC(tapi_set_if_mtu_smart2_rollback(&iut_mtus));
    CLEANUP_CHECK_RC(tapi_set_if_mtu_smart2_rollback(&tst_mtus));

    TEST_END;
}
