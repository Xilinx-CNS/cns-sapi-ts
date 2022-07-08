/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * TCP tests library
 *
 * $Id$
 */

#include "sockapi-test.h"
#include "sockapi-ts_tcp.h"
#include "tcp_test_macros.h"
#include "onload.h"
#include "te_dbuf.h"
#include "tapi_route_gw.h"

#define MAX_TCP_STR_LEN 1000

/* See description in tcp_test_macros.h */
void
tcp_test_wait_for_tcp_close(tsa_session *ss, unsigned int time_to_wait,
                            unsigned int attempts)
{
    unsigned int i;

    for (i = 0; i < attempts; i++)
    {
        tsa_update_cur_state(ss);
        if (tsa_state_cur(ss) == RPC_TCP_CLOSE)
            return;
        if (i < attempts - 1)
            MSLEEP(time_to_wait);
    }

    TEST_VERDICT("TCP socket is in %s state a long time since "
                 "last action", tcp_state_rpc2str(tsa_state_cur(ss)));
}

/* See description in tcp_test_macros.h */
const char *
tcp_test_get_path(rpc_tcp_state state, te_bool active)
{
    if (active)
        return tcp_state_rpc2str(state);

    switch (state)
    {
        case RPC_TCP_ESTABLISHED:
            return "TCP_CLOSE->TCP_LISTEN->TCP_SYN_RECV->TCP_ESTABLISHED";

        case RPC_TCP_FIN_WAIT1:
            return "TCP_CLOSE->TCP_LISTEN->TCP_SYN_RECV->TCP_ESTABLISHED->"
                   "TCP_FIN_WAIT1";

        case RPC_TCP_FIN_WAIT2:
            return "TCP_CLOSE->TCP_LISTEN->TCP_SYN_RECV->TCP_ESTABLISHED->"
                   "TCP_FIN_WAIT1->TCP_FIN_WAIT2";

        case RPC_TCP_TIME_WAIT:
            return "TCP_CLOSE->TCP_LISTEN->TCP_SYN_RECV->TCP_ESTABLISHED->"
                   "TCP_FIN_WAIT1->TCP_FIN_WAIT2->TCP_TIME_WAIT";

        case RPC_TCP_CLOSING:
            return "TCP_CLOSE->TCP_LISTEN->TCP_SYN_RECV->TCP_ESTABLISHED->"
                   "TCP_FIN_WAIT1->TCP_CLOSING";

        case TCP_CLOSE_WAIT:
            return "TCP_CLOSE->TCP_LISTEN->TCP_SYN_RECV->TCP_ESTABLISHED->"
                   "TCP_CLOSE_WAIT";

        case RPC_TCP_LAST_ACK:
            return "TCP_CLOSE->TCP_LISTEN->TCP_SYN_RECV->TCP_ESTABLISHED->"
                   "TCP_CLOSE_WAIT->TCP_LAST_ACK";

        case RPC_TCP_SYN_RECV:
            return "TCP_CLOSE->TCP_LISTEN->TCP_SYN_RECV";

        default:
            TEST_VERDICT("Unsupported tcp state was requested for passive "
                         "opening: %s", tcp_state_rpc2str(state));
    }

    return NULL;
}

/* See description in tcp_test_macros.h */
void
test_change_mac(tsa_session *ss, const struct sockaddr *tst_addr,
                struct sockaddr *alien_link_addr)
{
    static struct sockaddr tst_link_addr;

    CHECK_RC(tapi_cfg_del_neigh_entry(ss->config.pco_iut->ta,
                                      ss->config.iut_if->if_name,
                                      ss->config.tst_addr));

    CHECK_RC(tapi_cfg_del_neigh_entry(ss->config.pco_tst->ta,
                                      ss->config.tst_if->if_name,
                                      ss->config.iut_addr));

    if (alien_link_addr == NULL)
    {
        CHECK_RC(tapi_cfg_base_if_get_link_addr(ss->config.pco_tst->ta,
                                                ss->config.tst_if->if_name,
                                                &tst_link_addr));
        alien_link_addr = &tst_link_addr;
    }

    CHECK_RC(tapi_update_arp(ss->config.pco_iut->ta,
                             ss->config.iut_if->if_name,
                             NULL, NULL, tst_addr,
                             alien_link_addr->sa_data, TRUE));

    ss->config.alien_link_addr = alien_link_addr->sa_data;

    CFG_WAIT_CHANGES;
}


/* See description in tcp_test_macros.h */
void
tcp_move_to_state(tsa_session *ss, rpc_tcp_state state_to,
                  opening_listener opening, te_bool cache_socket)
{
    const char *path;
    int rc;

    if (tsa_state_cur(ss) == RPC_TCP_UNKNOWN)
        TEST_VERDICT("TCP socket is in unknown state");

    path = tcp_test_get_path(state_to, opening == OL_ACTIVE);

    if (opening == OL_ACTIVE)
    {
        rc = tsa_do_moves_str(ss, RPC_TCP_UNKNOWN, RPC_TCP_UNKNOWN, 0,
                              path);
        TSA_CHECK_RC(ss, rc);
        return;
    }

    if (opening == OL_PASSIVE_OPEN)
        ss->state.close_listener = TRUE;

    /** Call @b tsa_do_moves_str() to move IUT socket to @p tcp_state TCP
     * state. */
    if (tsa_do_moves_str(ss, RPC_TCP_UNKNOWN, RPC_TCP_LISTEN,
                         0, path) != TSA_ESTOP)
        TEST_VERDICT("TCP_LISTEN state was not achieved, current state "
                     "is %s", tcp_state_rpc2str(tsa_state_cur(ss)));

    if (cache_socket)
    {
        CHECK_RC(tsa_repair_iut_tst_conn(ss));
        TAPI_WAIT_NETWORK;

        sockts_create_cached_socket(ss->config.pco_iut, ss->config.pco_tst,
                                    ss->config.iut_addr, ss->config.tst_addr,
                                    tsa_iut_sock(ss), FALSE, TRUE);

        CHECK_RC(tsa_break_iut_tst_conn(ss));
        TAPI_WAIT_NETWORK;
    }

    rc = tsa_do_moves_str(ss, RPC_TCP_UNKNOWN, RPC_TCP_UNKNOWN, 0,
                          tsa_rem_path(ss));

    if (rc != 0 && (tsa_state_from(ss) == RPC_TCP_LISTEN &&
         tsa_state_to(ss) == RPC_TCP_SYN_RECV &&
         tsa_state_cur(ss) == RPC_TCP_LISTEN))
        rc = tsa_do_moves_str(ss, tsa_state_to(ss), RPC_TCP_UNKNOWN, 0,
                              tsa_rem_path(ss));

    TSA_CHECK_RC(ss, rc);
}

/* See description in tcp_test_macros.h */
te_errno
sockts_tcp_asn_addrs_match(asn_value *pkt,
                           const struct sockaddr *addr1,
                           const struct sockaddr *addr2,
                           sockts_addrs_direction *dir)
{
    struct sockaddr_storage src_addr;
    struct sockaddr_storage dst_addr;
    te_errno rc;

    rc = sockts_get_addrs_from_tcp_asn(pkt, &src_addr, &dst_addr);
    if (rc != 0)
        return rc;

    if (tapi_sockaddr_cmp(SA(&src_addr), addr1) == 0 &&
        tapi_sockaddr_cmp(SA(&dst_addr), addr2) == 0)
    {
        *dir = SOCKTS_ADDRS_FORWARD;
    }
    else if (tapi_sockaddr_cmp(SA(&src_addr), addr2) == 0 &&
             tapi_sockaddr_cmp(SA(&dst_addr), addr1) == 0)
    {
        *dir = SOCKTS_ADDRS_BACKWARD;
    }
    else
    {
        /* Not a packet from tested connection. */
        *dir = SOCKTS_ADDRS_NO_MATCH;
    }

    return 0;
}
