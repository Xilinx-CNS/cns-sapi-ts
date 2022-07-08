/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Advanced usage of send/receive functions
 */

/** @page sendrecv-send_dontroute Support of MSG_DONTROUTE flag
 *
 * @objective Check support of @c MSG_DONTROUTE flag.
 *
 * @type conformance
 *
 * @requirement REQ-1, REQ-2, REQ-3
 *
 * @reference @ref STEVENS section 13.3
 *
 * @param env       Testing environment:
 *                  - @ref arg_types_env_peer2peer
 *                  - @ref arg_types_env_peer2peer_ipv6
 * @param func      Function to be used to send data:
 *                  - @b send
 *                  - @b sendto
 *                  - @b sendmsg
 *                  - @b sendmmsg
 *                  - @b onload_zc_send
 *                  - @b onload_zc_send_user_buf
 *
 * -# Create datagram socket.
 * -# Try to send datagram using @p func function with destination
 *    address reachable throw gateway, but unreachable directly.
 * -# It's expected that attempt returns "Destination Network Unreachable"
 *    error.
 *
 * @author Andrew Rybchenko <Andrew.Rybchenko@oktetlabs.ru>
 */

#define TE_TEST_NAME  "sendrecv/send_dontroute"

#include "sockapi-test.h"
#include "tapi_cfg.h"
#include "tapi_cfg_base.h"

int
main(int argc, char *argv[])
{
    rpc_send_f              func;

    rcf_rpc_server         *pco_iut = NULL;
    rcf_rpc_server         *pco_tst = NULL;

    const struct sockaddr  *iut_addr;
    const struct sockaddr  *tst_addr;
    const struct sockaddr  *tst_alien_addr;

    const struct if_nameindex  *tst_if = NULL;

    int                     iut_s = -1;
    int                     tst_s = -1;

    void                   *tx_buf = NULL;
    size_t                  tx_buf_len;
    ssize_t                 sent;

    cfg_handle              addr_handle = CFG_HANDLE_INVALID;
    cfg_handle              rt_handle = CFG_HANDLE_INVALID;


    TEST_START;

    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR_NO_PORT(tst_addr);
    TEST_GET_ADDR(pco_tst, tst_alien_addr);
    TEST_GET_IF(tst_if);
    TEST_GET_SEND_FUNC(func);

    CHECK_RC(tapi_cfg_base_if_add_net_addr(
        pco_tst->ta, tst_if->if_name, tst_alien_addr,
        te_netaddr_get_bitsize(tst_alien_addr->sa_family),
        FALSE, &addr_handle));
    CHECK_RC(tapi_cfg_add_route(
        pco_iut->ta, tst_alien_addr->sa_family,
        te_sockaddr_get_netaddr(tst_alien_addr),
        te_netaddr_get_bitsize(tst_alien_addr->sa_family),
        te_sockaddr_get_netaddr(tst_addr), NULL, NULL,
        0, 0, 0, 0, 0, 0, &rt_handle));
    CFG_WAIT_CHANGES;

    GEN_CONNECTION(pco_tst, pco_iut, RPC_SOCK_DGRAM, RPC_IPPROTO_UDP,
                   tst_alien_addr, iut_addr, &tst_s, &iut_s);

    CHECK_NOT_NULL(tx_buf = sockts_make_buf_dgram(&tx_buf_len));

    RPC_AWAIT_ERROR(pco_iut);
    sent = func(pco_iut, iut_s, tx_buf, tx_buf_len, 0);
    if (sent < 0)
    {
        TEST_VERDICT("%s() without MSG_DONTROUTE failed with error "
                     RPC_ERROR_FMT, rpc_send_func_name(func),
                     RPC_ERROR_ARGS(pco_iut));
    }
    else if (sent != (ssize_t)tx_buf_len)
    {
        TEST_FAIL("%s() returned unexpected value",
                  rpc_send_func_name(func));
    }

    RPC_AWAIT_IUT_ERROR(pco_iut);
    sent = func(pco_iut, iut_s, tx_buf, tx_buf_len, RPC_MSG_DONTROUTE);
    if (sent >= 0)
        TEST_VERDICT("The packet to destination reachable via gateway "
                     "only is successfully sent with MSG_DONTROUTE flag");
    CHECK_RPC_ERRNO(pco_iut, RPC_ENETUNREACH,
                    "Incorrect errno is set when packet to destination "
                    "reachable via gateway only is sent with "
                    "MSG_DONTROUTE flag");

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    CLEANUP_CHECK_RC(tapi_cfg_del_route(&rt_handle));
    CLEANUP_CHECK_RC(cfg_del_instance(addr_handle, FALSE));

    TEST_END;
}
