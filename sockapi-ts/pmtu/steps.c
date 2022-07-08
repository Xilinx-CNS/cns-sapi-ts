/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Path MTU
 *
 * $Id$
 */

/** @page pmtu-steps Checking TCP behaviour in the case of mtu changing on the next hop and send buffer is filled by a complex sending scenario
 *
 * @objective Check correctness of TCP processing in the case of decreasing next
 *            hop MTU. This test checks correctness of retransmit queue
 *            processing by transmitting TCP.
 *
 * @type conformance
 *
 * @param pco_iut       PCO on IUT
 * @param pco_gw        PCO on host in the tested network
 *                      that is able to forward incoming packets (router)
 * @param pco_tst       PCO on TESTER
 * @param send_buf_size Buffer size of the socket on the sender's side:
 *                          - 65536
 * @param recv_buf_size Buffer size of the socket on the receiver's side:
 *                          - 65536
 * @param retr_queue    Check retransmission queue if @c TRUE
 * @param mtu_seq       Sequence of PMTU value to use:
 *                          - 1500,576
 *                          - 1500,1280
 *                          - 1280
 *                          - 576
 * @param send_params   List of function to use for sending data.:
 *                          - send
 *                          - write, sys_write, writev, sys_writev
 *                          - write, write, writev, writev
 *                          - sendfile, sys_sendfile
 *                          - sendfile, sys_sendfile, writev, sys_writev
 * @param before_start  Time before the first senders RPC call
 *                      (in milliseconds):
 *                          - 200
 * @param time_limit    Time limit for operation of data reception
 *                      (in seconds):
 *                          - 30
 * @param passive       Open TCP connection passively if @c TRUE
 *
 * @par Test sequence:
 *
 * -# Add route on @p pco_iut: @p tst_addr via gateway @p gw_iut_addr.
 * -# Add route on @p pco_tst: @p iut_addr via gateway @p gw_tst_addr.
 * -# Set MTU on @p gw_tst_if and @p tst_if to the first value from
 *    @p mtu_seq and check that the new value is set.
 * -# Establish connection of the @c SOCK_STREAM type between @p pco_iut 
 *    and @p pco_tst by means of @c GEN_CONNECTION.
 * -# Start threads sending data using functions from @p send_params.
 * -# Check that some data is really sent by receiving some data from 
 *    each sending thread.
 *
 * -# Iterate following steps:
 *        -# Sleep to allow TCP to fill send and receive buffers.
 *        -# If @p retr_queue is on, add an alien ARP entry on the router
 *           to garantee that @p TST will not receive any packets from 
 *           @p IUT. Receive some data to open window and fill retransmit
 *           queue.
 *        -# Set new MTU on @p gw_tst_if to the next value from @p mtu_seq and
 *           check that new value is set.
 *        -# If @p retr_queue is on, remove an alien ARP entry on the router
 *           to allow re-formated packets from retransmit queue to pass.
 *        -# Receive some data from each sending thread, check it 
 *           correctness.
 * 
 * -# Stop sending data and receive all sent data.
 *
 * @author Igor Vasiliev <Igor.Vasiliev@oktetlabs.ru>
 * @author Alexander Kukuta <Alexander.Kukuta@oktetlabs.ru>
 * @author Alexandra Kossovsky <Alexandra.Kossovsky@oktetlabs.ru>
 */

#define TE_TEST_NAME  "pmtu/steps"

#include "sockapi-test.h"
#include "tapi_cfg.h"
#include "tapi_cfg_base.h"
#include "pmtu_lib.h"
#include "iomux.h"

#define MAX_MTU_VALUES   10
#define PMTU_SLEEP_TIMES 100
#define PMTU_SLEEP_SLOT  500

int
main(int argc, char *argv[])
{
    rcf_rpc_server         *pco_iut = NULL;
    rcf_rpc_server         *pco_gw  = NULL;
    rcf_rpc_server         *pco_tst = NULL;

    int                   *mtu_seq = NULL;
    int                    mtu_times;
    int                    mtu_index;
    char                 **send_params = NULL;
    int                    threads;
    pmtu_scenario          scenario;

    const struct sockaddr *tst_addr = NULL;
    const struct sockaddr *iut_addr = NULL;
    const struct sockaddr *gw_iut_addr = NULL;
    const struct sockaddr *gw_tst_addr = NULL;
    tapi_env_net          *net1;
    tapi_env_net          *net2;
    int                    mtu_orig;

    te_bool                retr_queue = FALSE;

    int                    send_buf_size;
    int                    recv_buf_size;

    const struct if_nameindex   *tst_if = NULL;
    const struct if_nameindex   *gw_tst_if = NULL;
    cfg_handle                   blackhole_route;

    rpc_socket_addr_family family;
    int                    i;
    int                    prev_nread = -1;
    int                    data_size;
    int                    nread_no_incr_count = 0;
    int                    max_nread_no_incr_count = 2;

    te_bool                passive;

    struct tarpc_timeval   t = { 0, 0 };
    int                    before_start;
    int                    time_limit;


    
    TEST_START;
    memset(&scenario, 0, sizeof(scenario));
    scenario.send_s = scenario.recv_s = -1;

    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_gw);
    TEST_GET_PCO(pco_tst);

    TEST_GET_NET(net1);
    TEST_GET_NET(net2);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_ADDR_NO_PORT(gw_iut_addr);
    TEST_GET_ADDR_NO_PORT(gw_tst_addr);

    TEST_GET_IF(tst_if);
    TEST_GET_IF(gw_tst_if);

    TEST_GET_BOOL_PARAM(retr_queue);
    TEST_GET_INT_PARAM(send_buf_size);
    TEST_GET_INT_PARAM(recv_buf_size);

    TEST_GET_STRING_LIST_PARAM(send_params, threads);
    TEST_GET_INT_LIST_PARAM(mtu_seq, mtu_times);
    
    TEST_GET_BOOL_PARAM(passive);

    TEST_GET_INT_PARAM(before_start);
    TEST_GET_INT_PARAM(time_limit);

    PMTU_GET_MTU(pco_tst->ta, tst_if->if_name, &mtu_orig);
    family = sockts_domain2family(rpc_socket_domain_by_addr(iut_addr));

    /* Add routes to connect IUT & TST */
    PMTU_ADD_ROUTE(pco_iut->ta, family,
                   family == RPC_AF_INET6 ? net2->ip6addr : net2->ip4addr,
                   family == RPC_AF_INET6 ? net2->ip6pfx : net2->ip4pfx,
                   gw_iut_addr);

    PMTU_ADD_ROUTE(pco_tst->ta, family,
                   family == RPC_AF_INET6 ? net1->ip6addr : net1->ip4addr,
                   family == RPC_AF_INET6 ? net1->ip6pfx : net1->ip4pfx,
                   gw_tst_addr);

    CFG_WAIT_CHANGES;

    CHECK_RC(rpc_gettimeofday(pco_iut, &t, NULL));
    scenario.start = t.tv_sec * 1000 + t.tv_usec / 1000 + before_start;
    scenario.timeout = time_limit;

    scenario.pco_recv = pco_tst;
    scenario.sndbuf = send_buf_size;
    scenario.rcvbuf = recv_buf_size;
    scenario.threads_num = threads;
    pmtu_start_sending_threads(pco_iut, iut_addr, tst_addr,
                               send_params, &scenario, passive);
    if (retr_queue)
        pco_tst->def_timeout *= 10;

    for (mtu_index = 0; mtu_index < mtu_times; mtu_index++)
    {
        pmtu_recv_some_data(&scenario,
                            scenario.sndbuf + scenario.rcvbuf + 1);

        /* Wait for buffers to be filled */
        for (i = 0; i < PMTU_SLEEP_TIMES; i++)
        {
            MSLEEP(PMTU_SLEEP_SLOT * (retr_queue ? 4 : 1));
            rpc_ioctl(pco_tst, scenario.recv_s, RPC_FIONREAD, &data_size);

            if (prev_nread >= data_size)
            {
                nread_no_incr_count++;

                /*
                 * Send/receive buffers are considered filled when
                 * ioctl(FIONREAD) does not report an increased value
                 * a few times in a row and sender socket is not writable.
                 */
                if (nread_no_incr_count >= max_nread_no_incr_count &&
                    iomux_call_default_simple(pco_iut,
                                              scenario.send_s,
                                              EVT_WR, NULL, 0) == 0)
                {
                    break;
                }
            }
            else
            {
                nread_no_incr_count = 0;
            }

            prev_nread = data_size;
        }
        if (i == PMTU_SLEEP_TIMES)
            TEST_FAIL("Failed to get send and receive buffers filled");

        /* Receive something to make retransmit queue non-empty */
        if (retr_queue)
        {
            char *buf;

            rpc_ioctl(pco_tst, scenario.recv_s, RPC_FIONREAD, &data_size);
            data_size = MIN(data_size, scenario.rcvbuf / 4);
            buf = malloc(data_size);
            if (buf == NULL)
                TEST_FAIL("Out of memory");

            /* Move all traffic from IUT to black hole. */
            if (tapi_cfg_add_typed_route(pco_gw->ta, 
                            addr_family_rpc2h(family), 
                            te_sockaddr_get_netaddr(tst_addr), 
                            te_netaddr_get_size(addr_family_rpc2h(family)) * 8,
                            NULL, NULL, NULL, "blackhole", 
                            0, 0, 0, 0, 0, 0, &blackhole_route) != 0)
                TEST_FAIL("Failed to add blackhole route");

            pmtu_recv_and_check(&scenario, buf, data_size, NULL);
            free(buf);
        }

        /* Change path MTU */
        PMTU_SET_CHECK_MTU(pco_gw->ta, gw_tst_if->if_name, mtu_seq[mtu_index]);
        PMTU_SET_CHECK_MTU(pco_tst->ta, tst_if->if_name, mtu_seq[mtu_index]);

        /* Restore route between IUT & TST */
        if (retr_queue)
        {
            if (tapi_cfg_del_route(&blackhole_route) != 0)
                TEST_FAIL("Failed to delete blackhole route");
        }
    }

    pmtu_finish(&scenario);
#if 0 
    rpc_system(pco_iut, "/home/konst/work/l5/v5/build/gnu/tools/ip/stackdump all");
#endif
    TEST_SUCCESS;

cleanup:

    if (!scenario.stop)
    {
        scenario.stop = TRUE;
    }
#if 0
    if (result != EXIT_SUCCESS)
    {
        pco_iut->def_timeout = RCF_RPC_DEFAULT_TIMEOUT / 4;
        rpc_kill(pco_iut, rpc_getpid(pco_iut), RPC_SIGKILL);
    }
#endif

    if (scenario.threads != NULL)
    {
        /* To unblock send() */
        rpc_shutdown(pco_iut, scenario.send_s, RPC_SHUT_RDWR);
        for (i = 0; i < scenario.threads_num; i++)
        {
            void *ret;

            if (scenario.threads[i].thread != 0)
                pthread_join(scenario.threads[i].thread, &ret);
            if (scenario.threads[i].pco_send != NULL)
                rcf_rpc_server_destroy(scenario.threads[i].pco_send);
            if (scenario.threads[i].filename)
            {
                free(scenario.threads[i].filename);
            }
        }
        free(scenario.threads);
    }

    CLEANUP_RPC_CLOSE(pco_iut, scenario.send_s);
    CLEANUP_RPC_CLOSE(pco_tst, scenario.recv_s);


    /* 
     * Cope with Linux issue with disabled IPv6 support on interface,
     * if its MTU was less that 1280.
     * Also, it is necessary to specify "nohistory" for track_conf,
     * to prevent configurator from setting "bad" MTU again.
     */
    if (mtu_seq[mtu_times - 1] < 1280)
    {
        SLEEP(1); /* Let TCP finish connection. */
        if (pco_gw != NULL && gw_tst_if != NULL)
        {
            PMTU_SET_CHECK_MTU(pco_gw->ta, gw_tst_if->if_name, mtu_orig);
            CLEANUP_CHECK_RC(tapi_cfg_base_if_down(pco_gw->ta,
                                                   gw_tst_if->if_name));
            CLEANUP_CHECK_RC(tapi_cfg_base_if_up(pco_gw->ta,
                                                 gw_tst_if->if_name));
        }
        if (pco_tst != NULL && tst_if != NULL)
        {
            PMTU_SET_CHECK_MTU(pco_tst->ta, tst_if->if_name, mtu_orig);
            CLEANUP_CHECK_RC(tapi_cfg_base_if_down(pco_tst->ta,
                                                   tst_if->if_name));
            CLEANUP_CHECK_RC(tapi_cfg_base_if_up(pco_tst->ta,
                                                 tst_if->if_name));
        }
    }

    TEST_END;
}

