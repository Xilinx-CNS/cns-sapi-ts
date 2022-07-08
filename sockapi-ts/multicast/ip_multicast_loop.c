/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Multicasting in IP
 */

/** @page multicast-ip_multicast_loop Multicast loopback usage
 *
 * @objective Check multicast loopback usecases, including different
 *            processes, shared stack, different values of related
 *            EF_* variables.
 *
 * @note This source is used for ip_multicast_loop_ef and ip_multicast_loop
 *       tests. The first one tests EF_MULTICAST_LOOP_OFF,
 *       EF_MCAST_RECV_HW_LOOP and EF_MCAST_SEND options combinations, it
 *       does not change IP_MULTICAST_LOOP option. The second test
 *       ip_multicast_loop is aimed to check IP_MULTICAST_LOOP option. Its
 *       behavior is tested with different values of EF_MCAST_SEND env
 *       variable.
 *
 * @type conformance
 *
 * @param env                       Testing environment:
 *                                  - @ref arg_types_env_peer2peer_mcast
 * @param sockets_map               Determines how to distribute receiver
 *                                  sockets among processes in relation to
 *                                  the transmitter socket:
 *                                  - @c one_proc
 *                                  - @c receivers_in_second_proc
 *                                  - @c one_receiver_in_another_proc
 *                                  - @c receivers_in_different_proc
 * @param share_stack               Whether to share stack between processes
 * @param ef_multicast_loop_off     Use @c EF_MULTICAST_LOOP_OFF instead of
 *                                  @c EF_MCAST_SEND if it is @c TRUE
 * @param ip_multicast_loop         @c IP_MULTICAST_LOOP option value:
 *                                  - @c -1 (not set)
 *                                  - @c 0 (disabled)
 *                                  - @c 1 (enabled)
 * @param ef_mcast_recv_hw_loop_p1  If @c FALSE, set @c EF_MCAST_RECV_HW_LOOP
 *                                  to @c 0 for the process #1
 * @param ef_mcast_recv_hw_loop_p2  If @c FALSE, set @c EF_MCAST_RECV_HW_LOOP
 *                                  to @c 0 for the process #2
 * @param ef_mcast_recv_hw_loop_p3  If @c FALSE, set @c EF_MCAST_RECV_HW_LOOP
 *                                  to @c 0 for the process #3
 * @param method                    Determines how to join/leave a multicast
 *                                  group:
 *                                  - @c add_drop (@c IP_ADD_MEMBERSHIP,
 *                                    @c IP_DROP_MEMBERSHIP options)
 * @param sock_func                 Socket creation function:
 *                                  - @b socket()
 *                                  - @b onload_socket_unicast_nonaccel()
 * @param mtu                       MTU size for IUT interface:
 *                                  - @c 0 (do not change)
 *                                  - @c 1300
 *                                  - @c 3000
 * @param pkt_len                   Sent packet length:
 *                                  - @c 512
 *                                  - @c 1500
 *                                  - @c 2500
 *                                  - @c 3500
 *
 * @par Scenario:
 *
 * @author Andrey Dmitrov <Andrey.Dmitrov@oktetlabs.ru>
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME  "multicast/ip_multicast_loop"

#include "sockapi-test.h"
#include "multicast.h"
#include "mcast_lib.h"
#include "onload.h"

#define MAX_PACKET_SIZE 10000

/**
 * Enumeration for process-sockets combinations cases.
 */
typedef enum {
    SM_ONE_PROC = 0,   /**< All sockets in one process */
    SM_ANOTHER_PROC,   /**< One receiver socket in the same process as
                            transmitter, second in another */
    SM_SEC_PROC_BOTH,  /**< Both receiver sockets in another process */
    SM_THREE_PROC,     /**< Each socket in separate process */
} sockets_mapping_type;

#define SOCKETS_MAP  \
    { "one_proc", SM_ONE_PROC },                         \
    { "receivers_in_second_proc", SM_SEC_PROC_BOTH },    \
    { "one_receiver_in_another_proc", SM_ANOTHER_PROC }, \
    { "receivers_in_different_proc", SM_THREE_PROC }

/**
 * Check whether receiving multicast packet is expected for a given
 * receiver.
 *
 * @param onload_run          Whether the test is run on Onload and related
 *                            features should have effect.
 * @param ip_multicast_loop   Whether IP_MULTICAST_LOOP socket option was
 *                            enabled on sender socket.
 * @param same_stack          Whether receiver is in the same Onload stack
 *                            as sender.
 * @param recv_hw_loop        Whether hardware multicast loopback Onload
 *                            feature is enabled.
 * @param ef_mcast_send       Value of EF_MCAST_SEND variable on the
 *                            sender.
 *
 * @return TRUE if receiving is expected, FALSE otherwise.
 */
static te_bool
get_expectation(te_bool onload_run, te_bool ip_multicast_loop,
                te_bool same_stack, te_bool recv_hw_loop,
                int ef_mcast_send)
{
    /* On pure Linux IP_MULTICAST_LOOP should determine everything */
    if (!onload_run)
        return ip_multicast_loop;

    /* Multicast loopback is completely disabled */
    if (ef_mcast_send <= 0)
        return FALSE;

    if (same_stack)
    {
        if (!ip_multicast_loop)
            return FALSE;

        /* 2 means "to other stacks only" */
        if (ef_mcast_send == 2)
            return FALSE;
    }
    else
    {
        /* 1 means "to the same stack only" */
        if (ef_mcast_send == 1)
            return FALSE;

        if (!recv_hw_loop)
            return FALSE;
    }

    return TRUE;
}

/**
 * Check whether hardware multicast loopback is enabled. It is enabled
 * when EF_MCAST_RECV_HW_LOOP is not set to zero at least for one of
 * receivers.
 *
 * @param rpcs1       RPC server of the first receiver.
 * @param rpcs2       RPC server of the second receiver.
 * @param processes   Array of all three IUT processes
 *                    (last 1-2 may be NULL).
 * @param hw_recv1    Whether EF_MCAST_RECV_HW_LOOP is set to zero
 *                    for the first process.
 * @param hw_recv2    Whether EF_MCAST_RECV_HW_LOOP is set to zero
 *                    for the second process.
 * @param hw_recv3    Whether EF_MCAST_RECV_HW_LOOP is set to zero
 *                    for the third process.
 *
 * @return TRUE if hardware multicast loopback is enabled, FALSE otherwise.
 */
static te_bool
get_hw_recv_state(rcf_rpc_server *rpcs1,
                  rcf_rpc_server *rpcs2,
                  rcf_rpc_server **processes,
                  te_bool hw_recv1,
                  te_bool hw_recv2,
                  te_bool hw_recv3)
{
    te_bool hw_recv[] = { hw_recv1, hw_recv2, hw_recv3 };
    int i;

    for (i = 0; i < (int)TE_ARRAY_LEN(hw_recv); i++)
    {
        if ((rpcs1 == processes[i] || rpcs2 == processes[i]) &&
            hw_recv[i])
        {
            return TRUE;
        }
    }

    return FALSE;
}

int
main(int argc, char *argv[])
{
    rcf_rpc_server  *pco_iut = NULL;

    rcf_rpc_server  *pco_iut1  = NULL;
    rcf_rpc_server  *pco_iut2  = NULL;
    rcf_rpc_server  *pco_iut3  = NULL;
    mcast_listener_t listener  = CSAP_INVALID_HANDLE;

    const struct if_nameindex *iut_if     = NULL;
    const struct sockaddr     *iut_addr   = NULL;
    const struct sockaddr     *mcast_addr = NULL;
    tarpc_joining_method       method;
    sockets_mapping_type       sockets_map;
    int                        ef_mcast_send;
    te_bool                    ef_mcast_recv_hw_loop_p1 = TRUE;
    te_bool                    ef_mcast_recv_hw_loop_p2 = TRUE;
    te_bool                    ef_mcast_recv_hw_loop_p3 = TRUE;
    te_bool                    ef_multicast_loop_off    = FALSE;
    int                        ip_multicast_loop        = -1;
    te_bool                    share_stack              = FALSE;
    sockts_socket_func         sock_func;

    cmp_results_type res[2];
    char    sendbuf[MAX_PACKET_SIZE];
    int     tx_s = -1;
    int     rx_s1 = -1;
    int     rx_s2 = -1;

    int mtu;
    int pkt_len;

    rcf_rpc_server *pco_iut_proc[3] = {NULL, };
    int proc_count = 0;
    te_bool recv_hw_enabled = FALSE;
    te_bool onload_run;
    int i;

    te_saved_mtus iut_mtus = LIST_HEAD_INITIALIZER(iut_mtus);

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_IF(iut_if);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_iut, mcast_addr);
    TEST_GET_MCAST_METHOD(method);
    TEST_GET_BOOL_PARAM(ef_mcast_recv_hw_loop_p1);
    TEST_GET_BOOL_PARAM(ef_mcast_recv_hw_loop_p2);
    TEST_GET_BOOL_PARAM(ef_mcast_recv_hw_loop_p3);
    TEST_GET_ENUM_PARAM(sockets_map, SOCKETS_MAP);
    TEST_GET_INT_PARAM(ip_multicast_loop);
    TEST_GET_BOOL_PARAM(ef_multicast_loop_off);
    TEST_GET_BOOL_PARAM(share_stack);
    SOCKTS_GET_SOCK_FUNC(sock_func);
    TEST_GET_INT_PARAM(mtu);
    TEST_GET_INT_PARAM(pkt_len);

    if (mtu > 0)
    {
        TEST_STEP("If @p mtu is not zero, set MTU on @p iut_if to "
                  "the provided value.");
        CHECK_RC(tapi_set_if_mtu_smart2(pco_iut->ta, iut_if->if_name,
                                        mtu, &iut_mtus));
        CFG_WAIT_CHANGES;
    }

    onload_run = tapi_onload_run();

    TEST_STEP("Create one or more processes on IUT according to "
              "@p sockets_map. Assign @b pco_iut1 (RPC server for "
              "the sender socket), @b pco_iut2 (RPC server for the "
              "first receiver) and @b pco_iut3 (RPC server for the second "
              "receiver) to the same or different processes as required "
              "by @p sockets_map.");

    CHECK_RC(rcf_rpc_server_create(pco_iut->ta, "pco_iut1", &pco_iut1));
    pco_iut_proc[proc_count++] = pco_iut1;
    if (sockets_map != SM_ONE_PROC)
    {
        CHECK_RC(rcf_rpc_server_create(pco_iut->ta, "pco_iut2",
                                       &pco_iut2));
        pco_iut_proc[proc_count++] = pco_iut2;
    }
    if (sockets_map == SM_THREE_PROC)
    {
        CHECK_RC(rcf_rpc_server_create(pco_iut->ta, "pco_iut3",
                                       &pco_iut3));
        pco_iut_proc[proc_count++] = pco_iut3;
    }

    switch (sockets_map)
    {
        case SM_ONE_PROC:
            pco_iut2 = pco_iut3 = pco_iut1;
            break;

        case SM_ANOTHER_PROC:
            pco_iut3 = pco_iut1;
            break;

        case SM_SEC_PROC_BOTH:
            pco_iut3 = pco_iut2;
            break;

        case SM_THREE_PROC:
            break;

        default:
            TEST_FAIL("Unknown sockets_map value");
    }

    if (share_stack)
    {
        TEST_STEP("Set @c EF_NAME to the same string for each IUT process "
                  "if @p share_stack is @c TRUE.");
        rpc_setenv(pco_iut_proc[0], "EF_NAME", "st", 1);
        if (pco_iut_proc[1] != NULL)
            rpc_setenv(pco_iut_proc[1], "EF_NAME", "st", 1);
        if (pco_iut_proc[2] != NULL)
            rpc_setenv(pco_iut_proc[2], "EF_NAME", "st", 1);
    }

    rc = rpc_getenv_int(pco_iut1, "EF_MCAST_SEND", &ef_mcast_send);
    if (rc == -1)
        ef_mcast_send = -1;

    if (ef_mcast_send > -1)
    {
        TEST_STEP("If @p ef_mcast_send is set: ");
        if (ef_multicast_loop_off &&
            (ef_mcast_send < 2))
        {
            TEST_SUBSTEP("If @p ef_multicast_loop_off is @c TRUE, "
                         "unset @c EF_MCAST_SEND and"
                         "set @c EF_MULTICAST_LOOP_OFF on the first "
                         "IUT process to @c 0 if @p ef_mcast_send is "
                         "not zero, and to @c 1 otherwise.");

            rpc_unsetenv(pco_iut1, "EF_MCAST_SEND");

            rpc_setenv(pco_iut1, "EF_MULTICAST_LOOP_OFF",
                       (ef_mcast_send != 0 ? "0" : "1"), 1);
        }
    }

    TEST_STEP("Set EF_MCAST_RECV_HW_LOOP to @c 0 on IUT process(es) "
              "if required by @p ef_mcast_recv_hw_loop_p1, "
              "@p ef_mcast_recv_hw_loop_p2 and "
              "@p ef_mcast_recv_hw_loop_p3.");

    if (!ef_mcast_recv_hw_loop_p1)
        rpc_setenv(pco_iut_proc[0], "EF_MCAST_RECV_HW_LOOP", "0", 1);
    if (!ef_mcast_recv_hw_loop_p2)
        rpc_setenv(pco_iut_proc[1], "EF_MCAST_RECV_HW_LOOP", "0", 1);
    if (!ef_mcast_recv_hw_loop_p3)
        rpc_setenv(pco_iut_proc[2], "EF_MCAST_RECV_HW_LOOP", "0", 1);

    /*
     * We should set Onload library only after configuring all the
     * environment variables, so that the library picks expected
     * values during initialization.
     */
    if (pco_iut->nv_lib != NULL)
    {
        CHECK_RC(rcf_rpc_setlibname(pco_iut1, pco_iut->nv_lib));
        CHECK_RC(rcf_rpc_setlibname(pco_iut2, pco_iut->nv_lib));
        CHECK_RC(rcf_rpc_setlibname(pco_iut3, pco_iut->nv_lib));
    }

    TEST_STEP("Create transmitter socket on @b pco_iut1, bind it and set "
              "@c IP_MULTICAST_IF option.");
    tx_s = rpc_socket(pco_iut1, rpc_socket_domain_by_addr(mcast_addr),
                      RPC_SOCK_DGRAM, RPC_IPPROTO_UDP);
    rpc_bind(pco_iut1, tx_s, iut_addr);
    set_ip_multicast_if(pco_iut1, tx_s, iut_addr);

    if (ip_multicast_loop >= 0)
    {
        TEST_STEP("If @p ip_multicast_loop is non-negative, set "
                  "@c IP_MULTICAST_LOOP on the transmitter socket "
                  "to the provided value.");
        rpc_setsockopt_int(pco_iut1, tx_s, RPC_IP_MULTICAST_LOOP,
                           ip_multicast_loop);
    }

    TEST_STEP("Create two sockets on @b pco_iut2 and @b pco_iut3, bind "
              "them and join to the multicast group to receive "
              "packets.");

    rx_s1 = create_joined_socket_ext(sock_func, pco_iut2, iut_if,
                                     mcast_addr, mcast_addr,
                                     method);

    rx_s2 = create_joined_socket_ext(sock_func, pco_iut3, iut_if,
                                     mcast_addr, mcast_addr,
                                     method);

    TEST_STEP("Create CSAP on IUT to check whether multicast packets "
              "are accelerated.");
    listener = mcast_listener_init(pco_iut1, iut_if, mcast_addr, NULL, 0);
    mcast_listen_start(pco_iut1, listener);

    TEST_STEP("Send multicast packet from @b pco_iut1.");
    te_fill_buf(sendbuf, pkt_len);
    rpc_sendto(pco_iut1, tx_s, sendbuf, pkt_len, 0, mcast_addr);

    TEST_STEP("Get readability for the second receiver socket before "
              "trying to read the packet from the first one.");
    RPC_GET_READABILITY(res[1].got, pco_iut3, rx_s2, TAPI_WAIT_NETWORK_DELAY);

    TEST_STEP("Try to read and check the packet from the first receiver "
              "socket.");
    res[0].got = read_check_pkt(pco_iut2, rx_s1, sendbuf, pkt_len);

    TEST_STEP("Try to read and check the packet from the second receiver "
              "socket. Check that its readability state did not change "
              "after trying to read data from the first receiver.");

    rc = read_check_pkt(pco_iut3, rx_s2, sendbuf, pkt_len);
    if (res[1].got != rc)
    {
        TEST_VERDICT("The second receiver socket unexpectedly became "
                     "%sreadable after reading a packet from the "
                     "first socket", (res[1].got ? "un" : ""));
    }

    TEST_STEP("Check that CSAP on IUT detects packets only in case of "
              "pure Linux run.");
    if (mcast_listen_stop(pco_iut1, listener, NULL) != 0)
    {
        if (onload_run)
        {
            RING_VERDICT("System detects multicast packets, acceleration "
                         "is not achieved");
        }
    }
    else
    {
        if (!onload_run)
            RING_VERDICT("Multicast packets were not detected by CSAP");
    }

    recv_hw_enabled = get_hw_recv_state(pco_iut2, pco_iut3,
                                        pco_iut_proc,
                                        ef_mcast_recv_hw_loop_p1,
                                        ef_mcast_recv_hw_loop_p2,
                                        ef_mcast_recv_hw_loop_p3);

    res[0].exp = get_expectation(onload_run,
                                 ip_multicast_loop != 0,
                                 share_stack || pco_iut2 == pco_iut1,
                                 recv_hw_enabled,
                                 ef_mcast_send);

    res[1].exp = get_expectation(onload_run,
                                 ip_multicast_loop != 0,
                                 share_stack || pco_iut3 == pco_iut1,
                                 recv_hw_enabled,
                                 ef_mcast_send);

    TEST_STEP("Check whether receiver sockets were readable or not as "
              "expected given values of environment variables in the IUT "
              "process(es) and @c IP_MULTICAST_LOOP socket option.");
    cmp_exp_results(res, "First receiver");
    cmp_exp_results(res + 1, "Second receiver");

    if (res[0].exp != res[0].got || res[1].exp != res[1].got)
        TEST_STOP;

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut1, tx_s);
    CLEANUP_RPC_CLOSE(pco_iut2, rx_s1);
    CLEANUP_RPC_CLOSE(pco_iut3, rx_s2);

    mcast_listener_fini(pco_iut1, listener);

    for (i = 0; i < proc_count; i++)
        CLEANUP_CHECK_RC(rcf_rpc_server_destroy(pco_iut_proc[i]));

    if (mtu > 0)
        CLEANUP_CHECK_RC(tapi_set_if_mtu_smart2_rollback(&iut_mtus));

    TEST_END;
}
