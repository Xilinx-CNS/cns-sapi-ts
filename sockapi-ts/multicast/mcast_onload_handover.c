/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Multicasting in IP
 */

/**
 * @page multicast-mcast_onload_handover Handover socket via setting EF_MCAST_JOIN_HANDOVER
 *
 * @objective Check that when handover of a socket occurs as a result of a multicast join,
 *            then the kernel socket is still successfully joined to the group.
 *
 * @param env            Testing environment:
 *                       - @ref arg_types_env_peer2peer_mcast
 *                       - @ref arg_types_env_peer2peer_mcast_tst
 * @param mcast_addr     Multicast address
 * @param packet_number  Number of datagrams to send for reliability:
 *                       - 3
 * @param sock_func      Socket creation function:
 *                       - socket()
 *                       - onload_socket_unicast_nonaccel()
 * @param method         Multicast group joining method
 *                       - add_drop
 *                       - join_leave
 *                       - source_add_drop
 *                       - source_join_leave
 * @param handover       EF_MCAST_JOIN_HANDOVER value
 *                       - 0 handover is disabled
 *                       - 1 handover in the case of joining to a multicast group
 *                           on an interface that is not accelerated
 *                       - 2 always handover
 * @param bind_wildcard  Bind @p iut_s to @c INADDR_ANY address or
 *                       @p mcast_addr:
 *                       - TRUE
 *                       - FALSE
 * @param acc_if         Is the interface on IUT SFC-specific:
 *                       - TRUE
 *                       - FALSE
 *
 * @author Denis Pryazhennikov <Denis.Pryazhennikov@oktetlabs.ru>
 */

#define TE_TEST_NAME "multicast/mcast_onload_handover"

#include "sockapi-test.h"
#include "mcast_lib.h"
#include "multicast.h"
#include "onload.h"

int
main(int argc, char *argv[])
{
    rcf_rpc_server        *pco_iut = NULL;
    rcf_rpc_server        *pco_tst = NULL;
    const struct sockaddr *mcast_addr = NULL;
    const struct sockaddr *tst_addr = NULL;
    int                    iut_s = -1;
    int                    tst_s = -1;
    rpc_socket_domain      domain;

    const struct if_nameindex   *iut_if;
    const struct if_nameindex   *tst_if;

    int                    packet_number;
    int                    handover;
    te_bool                bind_wildcard;
    te_bool                acc_if;
    sockts_socket_func     sock_func;
    tarpc_joining_method   method;

    mcast_listener_t listener = CSAP_INVALID_HANDLE;

    int                    act_stack;
    te_bool                exp_onload_stack = FALSE;
    te_bool                readable;

    size_t                 send_buf_len;
    char                  *send_buf = NULL;
    char                  *recv_buf = NULL;
    int                    recv_data_len;
    int                    i;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_ADDR(pco_iut, mcast_addr);
    TEST_GET_INT_PARAM(packet_number);
    SOCKTS_GET_SOCK_FUNC(sock_func);
    TEST_GET_MCAST_METHOD(method);
    TEST_GET_BOOL_PARAM(acc_if);
    TEST_GET_BOOL_PARAM(bind_wildcard);
    TEST_GET_INT_PARAM(handover);
    TEST_GET_IF(iut_if);
    TEST_GET_IF(tst_if);

    CHECK_MCAST_HASH_COLLISION_CREATE_SOCK(pco_iut, pco_tst, iut_if, tst_addr,
                                           mcast_addr);

    send_buf = sockts_make_buf_dgram(&send_buf_len);
    recv_buf = te_make_buf_by_len(SOCKTS_MSG_DGRAM_MAX);

    TEST_STEP("Set @c EF_MCAST_JOIN_HANDOVER environment variable according "
              "to the @p handover and restart RPC server.");
    CHECK_RC(tapi_sh_env_set_int(pco_iut, "EF_MCAST_JOIN_HANDOVER",
                                 handover, TRUE, TRUE));

    domain = rpc_socket_domain_by_addr(tst_addr);

    TEST_STEP("Create @c SOCK_DGRAM socket on @p pco_iut.");
    iut_s = sockts_socket(sock_func, pco_iut, domain,
                          RPC_SOCK_DGRAM, RPC_IPPROTO_UDP);

    TEST_STEP("Bind IUT socket to @p mcast_addr or @c INADDR_ANY "
              "according to the @p bind_wildcard.");
    if (bind_wildcard)
    {
        struct sockaddr_storage any_addr;

        tapi_sockaddr_clone_exact(mcast_addr, &any_addr);
        te_sockaddr_set_wildcard(SA(&any_addr));
        rpc_bind(pco_iut, iut_s, CONST_SA(&any_addr));
    }
    else
    {
        rpc_bind(pco_iut, iut_s, mcast_addr);
    }
    TEST_STEP("Join socket on IUT to @p mcast_addr group using @p method.");
    rpc_common_mcast_join(pco_iut, iut_s, mcast_addr, tst_addr,
                          iut_if->if_index, method);

    TEST_STEP("Check whether the @p iut_s socket is an OS socket or onload one, "
              "depending on @p handover and @p acc_if values.");
    if ((handover == 0) || (handover == 1 && acc_if))
        exp_onload_stack = TRUE;

    act_stack = tapi_onload_is_onload_fd(pco_iut, iut_s);

    if ((act_stack == TAPI_FD_IS_ONLOAD && !exp_onload_stack))
        RING_VERDICT("Socket handover was expected, but it did not happen");

    if ((act_stack == TAPI_FD_IS_SYSTEM && exp_onload_stack))
        RING_VERDICT("Unexpected socket handover was detected");

    TEST_STEP("Create socket on @p pco_tst and set for it @c IP_MULTICAST_IF option "
              "to choose @p tst_if as interface for multicast traffic sending.");
    tst_s = rpc_socket(pco_tst, domain, RPC_SOCK_DGRAM, RPC_IPPROTO_UDP);

    set_ip_multicast_if(pco_tst, tst_s, tst_addr);

    TEST_STEP("Create CSAP to catch packets from Tester to IUT. Start listening.");
    listener = mcast_listener_init(pco_iut, iut_if, mcast_addr, NULL, 1);
    mcast_listen_start(pco_iut, listener);
    TAPI_WAIT_NETWORK;

    TEST_STEP("Send @p packet_number datagrams from @p tst_s to @p mcast_addr "
              "and check that @p iut_s socket recieved datagrams.");
    for (i = 0; i < packet_number; i++)
    {

        rpc_sendto(pco_tst, tst_s, send_buf, send_buf_len, 0, mcast_addr);

        RPC_GET_READABILITY(readable, pco_iut, iut_s, TAPI_WAIT_NETWORK_DELAY);
        if (readable)
        {
           recv_data_len = rpc_recv(pco_iut, iut_s, recv_buf,
                                    SOCKTS_MSG_DGRAM_MAX, 0);
           SOCKTS_CHECK_RECV(pco_iut, send_buf, recv_buf, send_buf_len,
                             recv_data_len);
        }
        else
        {
            TEST_VERDICT("Socket didn't receive multicast packet,"
                         " but it should");
        }
    }

    TEST_STEP("Check that acceleration matches expectations "
              "based on @p handover value.");
    rc = mcast_listen_stop(pco_iut, listener, NULL);
    if (rc > 0)
    {
        if (exp_onload_stack && acc_if)
           RING_VERDICT("%s detected by system, but acceleration was expected",
                        (rc < packet_number) ? "Multicast packets were" :
                        "All multicast packets");

    }
    else if (!exp_onload_stack)
        RING_VERDICT("All multicast packets were unexpectedly accelerated");

    TEST_STEP("Leave a multicasting group.");
    rpc_common_mcast_leave(pco_iut, iut_s, mcast_addr, tst_addr,
                           iut_if->if_index, method);

    TEST_SUCCESS;

cleanup:
    mcast_listener_fini(pco_iut, listener);

    free(send_buf);
    free(recv_buf);

    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);

    CLEANUP_CHECK_RC(tapi_sh_env_unset(pco_iut, "EF_MCAST_JOIN_HANDOVER",
                                       TRUE, TRUE));

    TEST_END;
}
