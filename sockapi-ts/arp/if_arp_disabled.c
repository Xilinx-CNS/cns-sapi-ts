/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * ARP table
 *
 * $Id$
 */

/** @page arp-if_arp_disabled Stack behaviour in case of attempting to operate via interface with disabled arp
 *
 * @objective Check the stack's behaviour when the arp processing on
 *            interface is disabled and there is not an appropriate
 *            arp entry in the table
 *
 * @type conformance
 *
 * @param pco_iut       PCO on IUT on @p iut_host
 * @param pco_tst       PCO on TESTER on @p tst_host
 * @param iut_addr      IP address of @p iut_host interface
 *                      attached to subnet @p iut_host-tst_host
 * @param tst_addr      IP address of @p tst_host interface
 *                      attached to subnet @p iut_host-tst_host
 *
 * @par Test sequence:
 *
 * -# Create @p iut_s socket of type @p sock_type on @p pco_iut;
 * -# Create @p tst_s socket of type @c sock_type on @p pco_tst;
 * -# Bind @p iut_s socket to device @p iut_if to exclude
 *    multihomed routing;
 * -# @b bind() @p iut_s to @p iut_addr;
 * -# If there is @p tst_addr ARP entry in @p iut_host ARP cache,
 *    delete it;
 * -# Check that  @p tst_addr ARP entry is absent in @p iut_host ARP cache;
 * -# Disable arp resolution on @p iut_if;
 * -# Initiate a socket operation to provoke ARP resolution;
 * -# Wait for synchronization time;
 * -# Check that an appropriate arp entry does not appear in
 *    @p iut_host ARP cache;
 * -# Close opened sockets and free allocated resources.
 *
 * @author Igor Vasiliev <Igor.Vasiliev.ru>
 */

#define TE_TEST_NAME "arp/if_arp_disabled"

#include "sockapi-test.h"
#include "arp_test_macros.h"
#include "tapi_cfg_base.h"
#include "tapi_cfg.h"

/** Next definitions are in seconds */
#define TST_RPC_TIMEOUT            8
#define TST_SELECT_TIMEOUT         TST_RPC_TIMEOUT - 2

#define TST_SELECT_CALL(pco_, sock_, rfds_) \
    do {                                                \
        timeout.tv_sec = TST_SELECT_TIMEOUT;            \
        timeout.tv_usec = 0;                            \
        rpc_do_fd_zero(pco_, rfds_);                    \
        rpc_do_fd_set(pco_, sock_, rfds_);               \
        pco_->op = RCF_RPC_CALL;                        \
        rpc_select(pco_, (sock_ + 1), rfds_, RPC_NULL,  \
                   RPC_NULL, &timeout);                 \
    } while (0)

#define TST_SELECT_WAIT(pco_, sock_, rfds_) \
    do {                                                \
        pco_->op = RCF_RPC_WAIT;                                \
        rc = rpc_select(pco_, (sock_ + 1), rfds_, RPC_NULL,     \
                        RPC_NULL, &timeout);                    \
        if (rc != 0)                                            \
        {                                                       \
            if (rpc_do_fd_isset(pco_, sock_, rfds_))            \
            {                                                   \
                ERROR("select() returns %d, and set 'sock_' "   \
                      "in 'readfds'", rc);                      \
            }                                                   \
            TEST_FAIL("select() has not returned "              \
                      "with timeout");                          \
        }                                                       \
    } while (0)

int
main(int argc, char *argv[])
{
    rpc_socket_type         sock_type;
    rcf_rpc_server         *pco_iut = NULL;
    rcf_rpc_server         *pco_tst = NULL;
    rcf_rpc_server         *pco_aux = NULL;
    int                     iut_s = -1;
    int                     tst_s = -1;

    tapi_env_host          *iut_host = NULL;

    const struct sockaddr  *iut_addr = NULL;
    const struct sockaddr  *tst_addr = NULL;

#ifdef TST_MORE_DETAILED
    struct sockaddr         tst_hwaddr;
    int                     arp_flags;
    te_bool                 arp_entry_exist;
#endif

    char                    opt_ifname[IFNAMSIZ];

    const struct if_nameindex  *iut_if = NULL;

    rpc_fd_set_p            readfds = RPC_NULL;
    tarpc_timeval           timeout;
    uint8_t                 buf[100];
    te_bool                 op_completed;

    /* Preambule */
    TEST_START;
    TEST_GET_SOCK_TYPE(sock_type);
    TEST_GET_HOST(iut_host);
    TEST_GET_IF(iut_if);
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);

    /* Scenario */

    readfds = rpc_fd_set_new(pco_tst);
    strncpy(opt_ifname, iut_if->if_name, IFNAMSIZ);

    CHECK_RC(tapi_cfg_base_if_down(pco_iut->ta, iut_if->if_name));
    CFG_WAIT_CHANGES;

    CHECK_RC(tapi_cfg_base_if_arp_disable(pco_iut->ta, iut_if->if_name));

    CHECK_RC(tapi_cfg_base_if_up(pco_iut->ta, iut_if->if_name));
    CFG_WAIT_CHANGES;

    CHECK_RC(tapi_cfg_del_neigh_entry(pco_iut->ta, iut_if->if_name,
                                      tst_addr));
    CFG_WAIT_CHANGES;

    TEST_CHECK_ARP_ENTRY_IS_DELETED(pco_iut->ta, iut_if->if_name,
                                    tst_addr);

    iut_s = rpc_socket(pco_iut, RPC_PF_INET, sock_type, RPC_PROTO_DEF);

    tst_s = rpc_socket(pco_tst, RPC_PF_INET, sock_type, RPC_PROTO_DEF);

    CHECK_RC(rcf_rpc_server_thread_create(pco_iut, "killer",
                                          &pco_aux));

    if (sock_type == RPC_SOCK_STREAM)
    {
        rpc_listen(pco_tst, tst_s, SOCKTS_BACKLOG_DEF);
    }

    rpc_bind(pco_iut, iut_s, iut_addr);

    TST_SELECT_CALL(pco_tst, tst_s, readfds);

    if (sock_type == RPC_SOCK_DGRAM)
    {
        rc = rpc_sendto(pco_iut, iut_s,  buf, 100, 0, tst_addr);
        rc = rpc_sendto(pco_iut, iut_s,  buf, 100, 0, tst_addr);
    }
    else if (sock_type == RPC_SOCK_STREAM)
    {

        pco_iut->timeout = TST_RPC_TIMEOUT;
        pco_iut->op = RCF_RPC_CALL;
        rc = rpc_connect(pco_iut, iut_s, tst_addr);

        SLEEP(TST_SELECT_TIMEOUT);
        rcf_rpc_server_is_op_done(pco_iut, &op_completed);

        if (op_completed == TRUE)
        {
            ERROR("connect() has been unexpectedly unblocked");
            pco_iut->op = RCF_RPC_WAIT;
            rc = rpc_connect(pco_iut, iut_s, tst_addr);
        }
        else
            RING("connect() has been blocked");
    }
    else
        TEST_FAIL("Unsupported type of socket");

    TST_SELECT_WAIT(pco_tst, tst_s, readfds);

#ifdef TST_MORE_DETAILED
    /*
     * In this case after socket operation that provokes arp
     * resolution arp entry existing into arp cache is validated
     * It seems this problem can be resolved with SLEEP(600)
     * after an appropriate arp entry delition.
     */
    TEST_GET_ARP_ENTRY(pco_aux, tst_addr, iut_if->if_name,
                       &tst_hwaddr, arp_flags, arp_entry_exist);
    if ((arp_entry_exist == TRUE) && (arp_flags & ATF_COM))

    {
        TEST_FAIL("Unexpected ARP entry in ARP cache "
                  "after %d seconds", TST_SELECT_TIMEOUT);
    }
#endif

    TEST_SUCCESS;

cleanup:

    CLEANUP_CHECK_RC(tapi_cfg_base_if_down(pco_iut->ta, iut_if->if_name));
    CFG_WAIT_CHANGES;

    CLEANUP_CHECK_RC(tapi_cfg_base_if_arp_enable(pco_iut->ta,
                                                 iut_if->if_name));

    CLEANUP_CHECK_RC(tapi_cfg_base_if_up(pco_iut->ta, iut_if->if_name));
    CFG_WAIT_CHANGES;

    rpc_fd_set_delete(pco_tst, readfds);

    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    CLEANUP_CHECK_RC(tapi_cfg_base_if_arp_enable(pco_iut->ta,
                                                 iut_if->if_name));
    if (pco_aux != NULL)
       CLEANUP_CHECK_RC(rcf_rpc_server_destroy(pco_aux));

    /* Calling close() on the socket does not really close the socket in
     * this case for OOL. So reboot PCO.
     */
    CLEANUP_CHECK_RC(rcf_rpc_server_restart(pco_iut));

    TEST_END;
}
