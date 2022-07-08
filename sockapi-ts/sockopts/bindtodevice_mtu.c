/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Socket options
 *
 * $Id$
 */

/** @page sockopts-bindtodevice_mtu Changing of MTU for bound socket
 *
 * @objective Check that changing of mtu correctly handles when
 *            @b setsockopt(@c SO_BINDTODEVICE) was called on socket.
 *
 * @type conformance
 *
 * @param pco_iut       PCO on IUT
 * @param pco_tst       PCO on Tester
 * @param packet_num    Number of packets to send for IUT to Tester
 * @param packet_len    Lenght of each packet
 *
 * @par Test sequence:
 * -# Create @c SOCK_DGRAM sockets @p iut_s on @p pco_iut and @p tst_s on
 *    @p pco_tst.
 * -# Bind @p tst_s socket to @p tst_addr.
 * -# If current mtu on @p pco_iut is less then packet len set mtu on
 *    @p pco_iut and on @p pco_tst to @p packet_len + 1000.
 * -# Call @b setsockopt(@c SO_BINDTODEVICE) on @p iut_s socket.
 * -# Send @p packet num packets from @p iut_s to @p tst_s.
 * -# Receive packets on @p tst_s and check them.
 * -# Set mtu on @p pco_iut to @p packet_len / 2.
 * -# Send @p packet num packets from @p iut_s to @p tst_s.
 * -# Receive packets on @p tst_s and check them.
 *
 * @author Yurij Plotnikov <Yurij.Plotnikov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "sockopts/bindtodevice_mtu"

#include "sockapi-test.h"
#include "tapi_cfg.h"
#include "tapi_cfg_base.h"

int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut  = NULL;
    rcf_rpc_server *pco_tst = NULL;
    int             iut_s  = -1;
    int             tst_s = -1;

    const struct sockaddr     *iut_addr;
    const struct if_nameindex *iut_if;
    const struct if_nameindex *tst_if;
    const struct sockaddr     *tst_addr;

    void     *tx_buf = NULL;
    void     *rx_buf = NULL;

    int          packet_num;
    int          packet_len;

    int          old_mtu;
    int          new_mtu;
    te_bool      readable;
    int          opt_val;

    te_saved_mtus   iut_mtus = LIST_HEAD_INITIALIZER(iut_mtus);
    te_saved_mtus   tst_mtus = LIST_HEAD_INITIALIZER(tst_mtus);

    int i;

    /* Preambule */
    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR_NO_PORT(iut_addr);
    TEST_GET_IF(iut_if);
    TEST_GET_IF(tst_if);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_INT_PARAM(packet_num);
    TEST_GET_INT_PARAM(packet_len);

    CHECK_NOT_NULL(tx_buf = te_make_buf_by_len(packet_len));
    CHECK_NOT_NULL(rx_buf = te_make_buf_by_len(packet_len));

    iut_s = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr),
                       RPC_SOCK_DGRAM, RPC_PROTO_DEF);
    tst_s = rpc_socket(pco_tst, rpc_socket_domain_by_addr(tst_addr),
                       RPC_SOCK_DGRAM, RPC_PROTO_DEF);

    rpc_bind(pco_tst, tst_s, tst_addr);

    CHECK_RC(tapi_cfg_base_if_get_mtu_u(pco_iut->ta, iut_if->if_name,
                                        &old_mtu));
    if (packet_len > old_mtu)
    {
        new_mtu = packet_len + 1000;
        CHECK_RC(tapi_set_if_mtu_smart2(pco_iut->ta, iut_if->if_name,
                                        new_mtu, &iut_mtus));
        CHECK_RC(tapi_set_if_mtu_smart2(pco_tst->ta, tst_if->if_name,
                                        new_mtu, &tst_mtus));

        CHECK_RC(sockts_wait_for_if_up(pco_iut, iut_if->if_name));
        CHECK_RC(sockts_wait_for_if_up(pco_tst, tst_if->if_name));
    }

    rpc_setsockopt_raw(pco_iut, iut_s, RPC_SO_BINDTODEVICE,
                       iut_if->if_name, (strlen(iut_if->if_name) + 1));
    TAPI_WAIT_NETWORK;

    opt_val = packet_len * packet_num * 2;
    rpc_setsockopt(pco_tst, tst_s, RPC_SO_RCVBUF, &opt_val);

    for (i = 0; i < packet_num; i++)
    {
        rc = rpc_sendto(pco_iut, iut_s, tx_buf, packet_len, 0, tst_addr);
        if (i == 0)
            TAPI_WAIT_NETWORK;
        if (rc != packet_len)
            TEST_FAIL("Incorrect number of bytes was sent");

    }
    TAPI_WAIT_NETWORK;

    for (i = 0; i < packet_num; i++)
    {
        RPC_GET_READABILITY(readable, pco_tst, tst_s, 1);
        if (readable)
        {
            rc = rpc_recv(pco_tst, tst_s, rx_buf, packet_len, 0);
            if (rc != packet_len || memcmp(rx_buf, tx_buf, rc) != 0)
                TEST_FAIL("Incorrect data has been received");
        }
        else
        {
            if (packet_num - i > 1)
                TEST_VERDICT("Too many packets were dropped during "
                             "first sending");
            else
                RING_VERDICT("First packet was dropped in first sending");
            break;
        }
    }
    RPC_CHECK_READABILITY(pco_tst, tst_s, FALSE);

    new_mtu = (old_mtu < packet_len) ? old_mtu : (packet_len - 100);

    CHECK_RC(tapi_set_if_mtu_smart2(pco_iut->ta, iut_if->if_name,
                                    new_mtu, &iut_mtus));
    CHECK_RC(tapi_set_if_mtu_smart2(pco_tst->ta, tst_if->if_name,
                                    new_mtu, &tst_mtus));

    CHECK_RC(sockts_wait_for_if_up(pco_iut, iut_if->if_name));
    CHECK_RC(sockts_wait_for_if_up(pco_tst, tst_if->if_name));

    for (i = 0; i < packet_num; i++)
    {
        rc = rpc_sendto(pco_iut, iut_s, tx_buf, packet_len, 0, tst_addr);
        if (i == 0)
            MSLEEP(1100); /* cplane_no_listen compatibility */
        if (rc != packet_len)
            TEST_FAIL("Incorrect number of bytes was sent");

    }
    TAPI_WAIT_NETWORK;

    for (i = 0; i < packet_num; i++)
    {
        RPC_GET_READABILITY(readable, pco_tst, tst_s, 1);
        if (readable)
        {
            rc = rpc_recv(pco_tst, tst_s, rx_buf, packet_len, 0);
            if (rc != packet_len || memcmp(rx_buf, tx_buf, rc) != 0)
                TEST_FAIL("Incorrect data has been received");
        }
        else
        {
            if (packet_num - i > 1)
                TEST_VERDICT("Too many packets were dropped during "
                             "second sending");
            else
                RING_VERDICT("First packet was dropped in second sending");
            break;
        }
    }

    TEST_SUCCESS;

cleanup:
    CLEANUP_CHECK_RC(tapi_set_if_mtu_smart2_rollback(&iut_mtus));
    CLEANUP_CHECK_RC(tapi_set_if_mtu_smart2_rollback(&tst_mtus));

    CLEANUP_CHECK_RC(sockts_wait_for_if_up(pco_iut, iut_if->if_name));
    CLEANUP_CHECK_RC(sockts_wait_for_if_up(pco_tst, tst_if->if_name));

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    free(tx_buf);
    free(rx_buf);

    TEST_END;
}
