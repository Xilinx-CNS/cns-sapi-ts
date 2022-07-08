/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Multicasting in IP
 *
 * $Id$
 */

/** @page multicast-mcast_vlan_alien_packet IP multicasting with VLAN
 *
 * @objective A socket, which is joined to a multicast group, receives
 *            packets only via defined interface.
 *
 * @type conformance
 *
 * @param pco_iut           PCO on IUT
 * @param pco_tst           PCO on TESTER
 * @param iut_if            Network interface on @p pco_iut
 * @param tst_if            Network interface on @p pco_tst
 * @param iut_addr          Network address on @p pco_iut
 * @param tst_addr          Network address on @p pco_tst
 * @param mcast_addr        Multicast address
 * @param vlan              VLAN identifier
 * @param sock_func         Socket creation function
 *
 * @par Test sequence:
 * -# Creat VLAN interface on IUT and TESTER.
 * -# Create a socket on IUT, join it to a multicast group.
 * -# Create two sockets on TESTER, bind one of them to @p tst_addr and
 *    the second one to the VLAN interface address.
 * -# Send multicast packets from both TESTER sockets.
 * -# Receive packets on IUT. Check that only one packet is received, which
 *    is sent via VLAN interface.
 *
 * @author Andrey Dmitrov <Andrey.Dmirtov@oktetlabs.ru>
 */

#define TE_TEST_NAME "multicast/mcast_vlan_alien_packet"

#include "sockapi-test.h"
#include "vlan_common.h"
#include "mcast_lib.h"
#include "multicast.h"

int
main(int argc, char **argv)
{
    rcf_rpc_server             *pco_iut = NULL;
    rcf_rpc_server             *pco_tst = NULL;
    cfg_handle                  vlan1_net_handle;
    cfg_handle                  iut_vlan1_addr_handle = CFG_HANDLE_INVALID;
    cfg_handle                  tst_vlan1_addr_handle = CFG_HANDLE_INVALID;

    const struct sockaddr      *mcast_addr = NULL;
    const struct sockaddr      *iut_addr = NULL;
    const struct sockaddr      *tst_addr = NULL;
    const struct if_nameindex  *iut_if = NULL;
    const struct if_nameindex  *tst_if = NULL;

    struct sockaddr_storage     peer_addr;
    socklen_t                   peer_addrlen = sizeof(peer_addr);
    
    struct sockaddr *iut_addr1 = NULL;
    struct sockaddr *tst_addr1 = NULL;

    int     vlan   = -1;
    int     iut_s  = -1;
    int     tst_s1 = -1;
    int     tst_s2 = -1;

    struct if_nameindex  *iut_if1 = NULL;
    struct if_nameindex  *tst_if1 = NULL;
    te_bool               iut_vlan1_configured = FALSE;
    te_bool               tst_vlan1_configured = FALSE;

    size_t    buf_len = 200;
    size_t    send_len = buf_len / 2;
    void     *snd_buf1 = NULL;
    void     *snd_buf2 = NULL;
    void     *rcv_buf = NULL;

    peer_name_t peer_names[4] = {{NULL, NULL}, };
    sock_name_t sock_names[3] = {{NULL, NULL, NULL}, };
    te_bool     readable;

    sockts_socket_func  sock_func;

    TEST_START;

    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_IF(iut_if);
    TEST_GET_IF(tst_if);
    TEST_GET_ADDR(pco_iut, mcast_addr);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_INT_PARAM(vlan);
    SOCKTS_GET_SOCK_FUNC(sock_func);

    snd_buf1 = te_make_buf_by_len(buf_len);
    snd_buf2 = te_make_buf_by_len(buf_len);
    rcv_buf = te_make_buf_by_len(buf_len);

    create_net_channel(pco_iut, pco_tst, iut_if, tst_if,
                       &vlan1_net_handle, &iut_vlan1_addr_handle,
                       &tst_vlan1_addr_handle,
                       &iut_addr1, &tst_addr1, mcast_addr,
                       sock_func,
                       &iut_s, &tst_s1, TRUE,
                       TRUE, &iut_if1, &tst_if1,
                       vlan, &iut_vlan1_configured,
                       &tst_vlan1_configured);

    peer_names[0].name = "address on IUT parent interface";
    peer_names[0].addr = (struct sockaddr **)&iut_addr;
    peer_names[1].name = "address on TESTER parent interface";
    peer_names[1].addr = (struct sockaddr **)&tst_addr;
    peer_names[2].name = "address on IUT vlan interface";
    peer_names[2].addr = &iut_addr1;
    peer_names[3].name = "address on TESTER vlan interface";
    peer_names[3].addr = &tst_addr1;

    sock_names[0].sock = &iut_s;
    sock_names[0].pco = &pco_iut;
    sock_names[0].name = "IUT socket on vlan interface";
    sock_names[1].sock = &tst_s1;
    sock_names[1].pco = &pco_tst;
    sock_names[1].name = "TESTER socket on vlan interface";
    sock_names[2].sock = &tst_s2;
    sock_names[2].pco = &pco_tst;
    sock_names[2].name = "TESTER socket on parent interface";

    tst_s2 = rpc_socket(pco_tst, RPC_AF_INET, RPC_SOCK_DGRAM,
                        RPC_PROTO_DEF);
    rpc_bind(pco_tst, tst_s2, tst_addr);

    rpc_mcast_join(pco_iut, iut_s, mcast_addr, iut_if1->if_index,
                   TARPC_MCAST_ADD_DROP);

    CFG_WAIT_CHANGES;

    rpc_sendto(pco_tst, tst_s1, snd_buf1, send_len, 0, mcast_addr);
    rpc_sendto(pco_tst, tst_s2, snd_buf2, send_len, 0, mcast_addr);

    TAPI_WAIT_NETWORK;

    RPC_GET_READABILITY(readable, pco_iut, iut_s, 1000);
    if (!readable)
        TEST_VERDICT("IUT didn't receive any packets");
    else
    {
        rc = rpc_recvfrom(pco_iut, iut_s, rcv_buf, buf_len, 0,
                          SA(&peer_addr), &peer_addrlen);
        CHECK_RETURNED_LEN(rc, send_len, SA(&peer_addr), tst_addr1,
                           RING_VERDICT, RING_VERDICT, peer_names, NULL,
                           NULL,
                           get_name_by_sock(iut_s, pco_iut, sock_names));
    }

    RPC_GET_READABILITY(readable, pco_iut, iut_s, 1000);
    if (readable)
    {
        rc = rpc_recvfrom(pco_iut, iut_s, rcv_buf, buf_len, 0,
                          SA(&peer_addr), &peer_addrlen);

        if (te_sockaddrcmp(SA(&peer_addr),
                           te_sockaddr_get_size(SA(&peer_addr)), tst_addr,
                           te_sockaddr_get_size(tst_addr)) != 0)
            CHECK_RETURNED_LEN(rc, send_len, SA(&peer_addr), tst_addr,
                               TEST_VERDICT, TEST_VERDICT, peer_names, NULL,
                               NULL, get_name_by_sock(iut_s, pco_iut,
                                                      sock_names));

        if (rc != (int)send_len || memcmp(snd_buf2, rcv_buf, send_len) != 0)
            TEST_VERDICT("A packet was received from TESTER parent "
                         "interface and it differs from sent packet");
        RING_VERDICT("IUT has received a packet from TESTER parent "
                     "interface");
    }

    TEST_SUCCESS;
cleanup:
    CLEANUP_RPC_CLOSE(pco_tst, tst_s1);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s2);
    CLEANUP_MULTICAST_LEAVE(pco_iut, iut_s, mcast_addr,
                            iut_if1->if_index, TARPC_MCAST_ADD_DROP);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);


    if (iut_if1 != NULL)
    {
        free(iut_if1->if_name);
        free(iut_if1);
    }
    if (tst_if1 != NULL)
    {
        free(tst_if1->if_name);
        free(tst_if1);
    }

    free(rcv_buf);
    free(snd_buf1);
    free(snd_buf2);

    CLEANUP_REMOVE_VLAN(pco_iut, iut_if, vlan, iut_vlan1_configured);
    CLEANUP_REMOVE_VLAN(pco_tst, tst_if, vlan, tst_vlan1_configured);

    tapi_cfg_free_entry(&vlan1_net_handle);
    tapi_cfg_free_entry(&iut_vlan1_addr_handle);
    tapi_cfg_free_entry(&tst_vlan1_addr_handle);

    TEST_END;
}
