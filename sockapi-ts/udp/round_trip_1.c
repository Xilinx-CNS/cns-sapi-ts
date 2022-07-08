/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * ARP table
 * 
 * $Id$
 */

/** @page udp-round_trip_1 test 1 on timely round trip
 *
 * @objective send/receive messages to distinct destination
 *            in a timely manner
 *          
 *
 * @type conformance
 *
 * @reference @ref STEVENS, chapter 4
 *
 * @param iut_node        host with IUT residing on it
 * @param host_1          host with TESTER residing on it
 * @param host_2          host with TESTER residing on it
 * @param net_1           net connected @p iut and @p host1
 * @param net_2           net connected @p iut and @p host2
 * @param pco_iut         IUT on iut_node
 * @param pco_tst_1       TESTER on @p host1
 * @param pco_tst_2       TESTER on @p host2
 * @param net_1_iut_if    @p net1 physical interface on @p iut
 * @param net_2_iut_if    @p net2 phycical interface on @p iut
 * @param net_1_tst_if    @p net1 physical interface on @p host1
 * @param net_2_tst_if    @p net1 physycal interface on @p host2 
 * @param net_1_remote    @p net1 address on @p host1
 * @param net_2_remote    @p net2 address on @p host2
 * @param size            size of UDP datagrams being sent
 * @param num             number of distinct destination
 *                        UDP datagrams should be sent towards
 * @param timeout         time to waiting up UDP datagram
 * @param time2wait       time period during which UDP datagram should 
 *                        be sent from IUT and received back
 * 
 * @par Test sequence:
 * -# For @p i = 0, @p i < @p num do:
 *      -# Get free net from netpool, 
 *         get free address @p dst_addr from the net;
 *      -# Let @p k is @c 0 if @p i is odd, and @c 1 otherwise;
 *      -# Assign @p dst_addr to @p host_k;
 *      -# Add route to @p dst_addr via @p net_k_remote;
 *      -# Create @c SOCK_DGRAM socket @p tst_sock_k on @p pco_tst_k,
 *         bind it to @p dst_addr;
 * -# Create @c SOCK_DGRAM socket @p iut_s on @p pco_iut;
 * -# Add ARP entries in @p pco_iut ARP table which resolve
 *    @p net_remote addresses;
 * -# On each @p pco_tst call rpc procedure @b round_trip_echoer
 *    in non-blocking mode which do:
 *    -# For each socket from @p tst_sock list which belongs 
 *       to this @p pco_tst do:
 *        -# Call @b select() with @p readfds set to @p tst_sock
 *           and timeout @p timeout;
 *        -# If timeout is expired exit with error;
 *        -# Call @b recvmsg() on @p tst_sock to receive UDP datagram;
 *        -# Call @b sendmsg() on @p tst_sock 
 *           to send received UDP datagram back;
 * -# On @p pco_iut call rpc procedure @b timely_round_trip 
 *    in blocking mode which do:
 *    -# For each address from @p dst_addr list do:
 *        -# Call @b sendmsg() on @p iut_s to send UDP datagram
 *           of size @p size towards @p dst_addr;
 *        -# Call @b select() with @p readfds set to @p iut_s
 *           and timeout @p timeout;
 *        -# If timeout is expired exit with error;
 *        -# Call @b recvmsg() on @p iut_s to receive UDP datagram back;
 *        -# Check that time passed between sending and receiving datagram
 *           is not greater than @p time2wait;
 * -# On each @p pco_tst call rpc procedure @b round_trip_echoer
 *    in blocking mode to get its result.
 *
 * @note Test should be run with enabling and disabling tunnelling.   
 *       In case of tunnelling is enable, filter should be started on
 *       @p iut_node to check that no UDP data is seen at the receiver's
 *       net driver.
 *
 * @author Renata Sayakhova <Renata.Sayakhova@oktetlabs.ru>
 */

#define TE_TEST_NAME    "udp/round_trip_1"

#include <errno.h>
#include <pthread.h>

#include "sockapi-test.h"
#include "rcf_api.h"
#include "tapi_cfg.h"
#include "tapi_cfg_base.h"
#include "conf_api.h" 
#include "tapi_ip4.h"
 
#define WAITING_FOR_CONFIGURATION_CHANGES 15

/** Convert protocol address to be used in tapi_arp */
#define CVT_PROTO_ADDR(addr_) \
    (uint8_t *)&(SIN(addr_)->sin_addr.s_addr)

int
main(int argc, char *argv[])
{
    tapi_env_net      *net[2];
    tapi_env_net      *net1 = NULL;
    tapi_env_net      *net2 = NULL;
    
    tapi_env_host     *iut   = NULL;
    
    rcf_rpc_server    *pco_iut = NULL;
    
    rcf_rpc_server    *pco_tst[2] = { NULL, NULL };
    rcf_rpc_server    *pco_iut1 = NULL;
    rcf_rpc_server    *pco_iut2 = NULL;

    int      iut_s = -1;
    int     *tst1_s = NULL;
    int     *tst2_s = NULL;
    int     *tst_s[2];

    const struct if_nameindex  *net1_iut_if = NULL;
    const struct if_nameindex  *net2_iut_if = NULL;
    struct if_nameindex        *iut_ifs[2];

    const struct if_nameindex  *net1_tst_if = NULL;
    const struct if_nameindex  *net2_tst_if = NULL;
    struct if_nameindex        *tst_ifs[2];

    const struct sockaddr *net1_remote = NULL;
    const struct sockaddr *net2_remote = NULL;
    struct sockaddr *remote_addresses[2];

    const struct sockaddr *net1_local = NULL;
    const struct sockaddr *net2_local = NULL;
    
    struct sockaddr      *addr_list = NULL;
    socklen_t             addr_len;
    struct sockaddr      *new_addr = NULL;
    
    uint32_t size;
    uint32_t timeout;
    uint32_t time2wait;

    int      num;
    int      nums[2];
    int      i;

    struct sockaddr net1_tst_mac;
    struct sockaddr net2_tst_mac;
    struct sockaddr net1_iut_mac;
    struct sockaddr net2_iut_mac;

    struct sockaddr *tst_mac[2];
    
    char                   buf[INET_ADDRSTRLEN];
    cfg_handle             handle = CFG_HANDLE_INVALID;

    unsigned int  net1_received;
    csap_handle_t net1_handle;
    int           net1_sid;

    unsigned int  net2_received;
    csap_handle_t net2_handle;
    int           net2_sid;

    te_bool       disable_tunnelling;

   /* Preambule */
    TEST_START;

    TEST_GET_BOOL_PARAM(disable_tunnelling);

    TEST_GET_NET(net1);
    TEST_GET_NET(net2);

    TEST_GET_HOST(iut);

    TEST_GET_IF(net1_iut_if);
    TEST_GET_IF(net2_iut_if);
    TEST_GET_IF(net1_tst_if);
    TEST_GET_IF(net2_tst_if);    
  
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_iut1);
    TEST_GET_PCO(pco_iut2);

    TEST_GET_ADDR(pco_iut1, net1_remote);
    TEST_GET_ADDR(pco_iut2, net2_remote);

    TEST_GET_ADDR(pco_iut, net1_local);
    TEST_GET_ADDR(pco_iut, net2_local);

    TEST_GET_INT_PARAM(num);
    TEST_GET_INT_PARAM(size);

    TEST_GET_INT_PARAM(timeout);
    TEST_GET_INT_PARAM(time2wait);

    pco_tst[0] = pco_iut1;
    pco_tst[1] = pco_iut2;
    
    net[0] = net1;
    net[1] = net2;

    iut_ifs[0] = (struct if_nameindex *)net1_iut_if;
    iut_ifs[1] = (struct if_nameindex *)net2_iut_if;

    tst_ifs[0] = (struct if_nameindex *)net1_tst_if;
    tst_ifs[1] = (struct if_nameindex *)net2_tst_if;

    remote_addresses[0] = (struct sockaddr *)net1_remote;
    remote_addresses[1] = (struct sockaddr *)net2_remote;

    if ((addr_list = calloc(num, sizeof(struct sockaddr_in))) == NULL)
        TEST_FAIL("No resources");

    if ((tst1_s = calloc(num/2 + num%2, sizeof(int))) == NULL)
        TEST_FAIL("No resources");

    memset(tst1_s, -1, (num/2 + num%2) * sizeof(int));

    if ((tst2_s = calloc(num/2, sizeof(int))) == NULL)
        TEST_FAIL("No resources");

    memset(tst2_s, -1, num/2 * sizeof(int));

    nums[0] = num/2 + num%2;
    nums[1] = num/2;

    tst_s[0] = tst1_s;
    tst_s[1] = tst2_s;

    /* For debugging purposes, must be removed */
    for (i = 0; i < num; i++)
        SIN(remote_addresses[i%2])->sin_port = htons(3261);
    
    for (i = 0; i < num; i++)
    {
        cfg_handle new_addr_handle = CFG_HANDLE_INVALID;
       
        CHECK_RC(tapi_env_allocate_addr(net[i%2], AF_INET,
                                        &new_addr, &addr_len));
        SIN(new_addr)->sin_port = SIN(remote_addresses[i%2])->sin_port;
        CHECK_RC(tapi_cfg_base_if_add_net_addr(pco_tst[i%2]->ta, tst_ifs[i%2]->if_name,
                                               new_addr, 0, FALSE,
                                               &new_addr_handle));         
        memcpy(&addr_list[i], new_addr, addr_len);
    }
    
    CHECK_RC(tapi_cfg_base_if_get_link_addr(pco_iut->ta, net1_iut_if->if_name, &net1_iut_mac));
    CHECK_RC(tapi_cfg_base_if_get_link_addr(pco_iut->ta, net2_iut_if->if_name, &net2_iut_mac));
    
    CHECK_RC(tapi_cfg_base_if_get_link_addr(pco_iut1->ta, net1_tst_if->if_name, &net1_tst_mac));
    CHECK_RC(tapi_cfg_base_if_get_link_addr(pco_iut2->ta, net2_tst_if->if_name, &net2_tst_mac));

    tst_mac[0] = &net1_tst_mac;
    tst_mac[1] = &net2_tst_mac;

    /* Add ARP entries on IUT */
    for (i = 0; i < num; i++)
    {
        rc = cfg_add_instance_fmt(&handle, CVT_ADDRESS, tst_mac[i%2],
                                  "/agent:%s/interface:%s/neigh_dynamic:%s",
                                  pco_iut->ta,
                                  iut_ifs[i%2]->if_name,
                                  inet_ntop(AF_INET, &(SIN(&addr_list[i])->sin_addr),
                                            buf, INET_ADDRSTRLEN));
       if (rc != 0 && TE_RC_GET_ERROR(rc) != TE_EEXIST)
          TEST_FAIL("Cannot add ARP entry on IUT");
    }
    rc = cfg_add_instance_fmt(&handle, CVT_ADDRESS, &net1_tst_mac, 
                              "/agent:%s/interface:%s/neigh_dynamic:%s", 
                              pco_iut->ta,
                              net1_iut_if->if_name,
                              inet_ntop(AF_INET, &(SIN(net1_remote)->sin_addr),
                                        buf, INET_ADDRSTRLEN));
    if (rc != 0 && TE_RC_GET_ERROR(rc) != TE_EEXIST)
        TEST_FAIL("Cannot add ARP entry on IUT");
                                                 
    rc = cfg_add_instance_fmt(&handle, CVT_ADDRESS, &net2_tst_mac, 
                              "/agent:%s/interface:%s/neigh_dynamic:%s", 
                              pco_iut->ta,
                              net2_iut_if->if_name,
                              inet_ntop(AF_INET, &(SIN(net2_remote)->sin_addr),
                                        buf, INET_ADDRSTRLEN));
    if (rc != 0 && TE_RC_GET_ERROR(rc) != TE_EEXIST)
        TEST_FAIL("Cannot add ARP entry on IUT");

    /* Add ARP entries on TESTER */
    rc = cfg_add_instance_fmt(&handle, CVT_ADDRESS, &net1_iut_mac, 
                              "/agent:%s/interface:%s/neigh_dynamic:%s", 
                              pco_iut1->ta,
                              net1_tst_if->if_name,
                              inet_ntop(AF_INET, &(SIN(net1_local)->sin_addr),
                                        buf, INET_ADDRSTRLEN));
    if (rc != 0 && TE_RC_GET_ERROR(rc) != TE_EEXIST)
        TEST_FAIL("Cannot add ARP entry on IUT");
                                                 
    rc = cfg_add_instance_fmt(&handle, CVT_ADDRESS, &net2_iut_mac, 
                              "/agent:%s/interface:%s/neigh_dynamic:%s", 
                              pco_iut2->ta,
                              net2_tst_if->if_name,
                              inet_ntop(AF_INET, &(SIN(net2_local)->sin_addr),
                                        buf, INET_ADDRSTRLEN));
    if (rc != 0 && TE_RC_GET_ERROR(rc) != TE_EEXIST)
        TEST_FAIL("Cannot add ARP entry on IUT");

    SLEEP(WAITING_FOR_CONFIGURATION_CHANGES);

    if (disable_tunnelling == FALSE)
    {
        cfg_handle handle;

        uint32_t mask;
        uint32_t ef_udp_netmask;
        char    *ef_udp_netmask_str = NULL;

        char buf[INET_ADDRSTRLEN] = {0,};

        if (net1->ip4pfx != net2->ip4pfx)
            TEST_FAIL("Nets attached to IUT have different prefixes, exit");
        mask = htonl(PREFIX2MASK(net1->ip4pfx));
        ef_udp_netmask = (disable_tunnelling == TRUE) ? 0xffffffff :  mask;
        if ((ef_udp_netmask_str = 
             (char *)inet_ntop(AF_INET, &ef_udp_netmask, buf, INET_ADDRSTRLEN)) == NULL)
            TEST_FAIL("Failed to convert EF_UDP_NETMASK to string");

        /* IUT */
        if (cfg_find_fmt(&handle, "/agent:%s/env:EF_UDP_NETMASK", 
                         pco_iut->ta) != 0)
            rc = cfg_add_instance_fmt(&handle, CVT_STRING, 
                                      ef_udp_netmask_str,
                                      "/agent:%s/env:EF_UDP_NETMASK", 
                                      pco_iut->ta);
        else
            rc = cfg_set_instance(handle, CVT_STRING, ef_udp_netmask_str);

        /* Tester 1 */
        if (cfg_find_fmt(&handle, "/agent:%s/env:EF_UDP_NETMASK", 
                         pco_iut1->ta) != 0)
            rc = cfg_add_instance_fmt(&handle, CVT_STRING, 
                                      ef_udp_netmask_str,
                                      "/agent:%s/env:EF_UDP_NETMASK", 
                                      pco_iut1->ta);
        else
            rc = cfg_set_instance(handle, CVT_STRING, ef_udp_netmask_str);

        /* Tester 2 */
        if (cfg_find_fmt(&handle, "/agent:%s/env:EF_UDP_NETMASK", 
                         pco_iut2->ta) != 0)
            rc = cfg_add_instance_fmt(&handle, CVT_STRING, 
                                      ef_udp_netmask_str,
                                      "/agent:%s/env:EF_UDP_NETMASK", 
                                      pco_iut2->ta);
        else
            rc = cfg_set_instance(handle, CVT_STRING, ef_udp_netmask_str);

        if (rc != 0)
            TEST_FAIL("Failed to set EF_UDP_NETMASK");

        if (rcf_rpc_server_restart(pco_iut) != 0)
            TEST_FAIL("Failed to restart pco_iut");

        if (rcf_rpc_server_restart(pco_iut1) != 0)
            TEST_FAIL("Failed to restart pco_iut1");

        if (rcf_rpc_server_restart(pco_iut2) != 0)
            TEST_FAIL("Failed to restart pco_iut2");
    }

    /* Socket on IUT */
    iut_s = rpc_socket(pco_iut, RPC_AF_INET, 
                       RPC_SOCK_DGRAM, RPC_PROTO_DEF);


    /* Sockets on TESTER */
    for (i = 0; i < num; i++)
    {
        (tst_s[i % 2])[i / 2] = rpc_socket(pco_tst[i % 2], RPC_AF_INET,
                                           RPC_SOCK_DGRAM, RPC_PROTO_DEF);
        rpc_bind(pco_tst[i % 2], tst_s[i % 2][i / 2], &addr_list[i]);
    }

    /* Filters */ 
    if (disable_tunnelling == FALSE)
    {    
        CHECK_RC(rcf_ta_create_session(pco_iut->ta, &net1_sid));
        CHECK_RC(tapi_ip4_eth_csap_create(pco_iut->ta, net1_sid,
                                          net1_iut_if->if_name,
                                          TAD_ETH_RECV_DEF,
                                          CVT_HW_ADDR(&net1_iut_mac),
                                          CVT_HW_ADDR(&net1_tst_mac),
                                          SIN(net1_local)->sin_addr.s_addr,
                                          htonl(INADDR_ANY),
                                          IPPROTO_UDP, &net1_handle));
        CHECK_RC(tapi_tad_trrecv_start(pco_iut->ta, net1_sid, net1_handle,
                                       NULL, TAD_TIMEOUT_INF, 0,
                                       RCF_TRRECV_COUNT));
        CHECK_RC(rcf_ta_create_session(pco_iut->ta, &net2_sid));
        CHECK_RC(tapi_ip4_eth_csap_create(pco_iut->ta, net2_sid,
                                          net2_iut_if->if_name,
                                          TAD_ETH_RECV_DEF,
                                          CVT_HW_ADDR(&net2_iut_mac),
                                          CVT_HW_ADDR(&net2_tst_mac),
                                          SIN(net2_local)->sin_addr.s_addr,
                                          htonl(INADDR_ANY),
                                          IPPROTO_UDP, &net2_handle));
        CHECK_RC(tapi_tad_trrecv_start(pco_iut->ta, net2_sid, net2_handle,
                                       NULL, TAD_TIMEOUT_INF, 0,
                                       RCF_TRRECV_COUNT));
    }
    /* OK, all is prepared, let's dance */
    for (i = 0; i < 2; i++)
    {    
        pco_tst[i%2]->op = RCF_RPC_CALL;
        pco_tst[i%2]->def_timeout = 2 *timeout;
        rpc_round_trip_echoer(pco_tst[i], nums[i], tst_s[i], 1, size, 1,
                              timeout, 0);
    }
    pco_iut->def_timeout = 2 * timeout;
    rpc_timely_round_trip(pco_iut, 1, &iut_s, size, 1, timeout, time2wait,
                          0, num, addr_list);
        
    for (i = 0; i < 2; i++)
    {
        rpc_round_trip_echoer(pco_tst[i], nums[i], tst_s[i], 1, size, 1,
                              timeout, 0);
    }

    if (disable_tunnelling == FALSE)
    {    
        CHECK_RC(rcf_ta_trrecv_stop(pco_iut->ta, 0, net1_handle,
                                    NULL, NULL, &net1_received));
        if (net1_received != 0)
            TEST_FAIL("Filter catch packets");
    
        CHECK_RC(rcf_ta_trrecv_stop(pco_iut->ta, 0, net2_handle,
                                    NULL, NULL, &net2_received));
        if (net2_received != 0)
            TEST_FAIL("Filter catch packets");
    }
    
    TEST_SUCCESS;
cleanup:
    for (i = 0; i < 2; i++)
    {
        if (pco_tst[i] != NULL && pco_tst[i]->op == RCF_RPC_WAIT)
            rpc_round_trip_echoer(pco_tst[i], nums[i], tst_s[i], 
                                  1, size, 1, timeout, 0);
    }
    if (pco_iut != NULL && pco_iut->op == RCF_RPC_WAIT)
        rpc_timely_round_trip(pco_iut, 1, &iut_s, size, 1, 
                              timeout, time2wait, 0, num,
                              addr_list);
    
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    
    if (tst1_s != NULL)
        for (i = 0; i < num/2 + num%2; i++)
            CLEANUP_RPC_CLOSE(pco_iut1, tst1_s[i]);
    free(tst1_s);
    
    if (tst2_s != NULL)
        for (i = 0; i < num/2; i++)
            CLEANUP_RPC_CLOSE(pco_iut2, tst2_s[i]);
    free(tst2_s);
    
    free(addr_list);
    
    if (pco_iut != NULL)
        cfg_del_instance_fmt(FALSE, "/agent:%s/env:EF_UDP_NETMASK", 
                             pco_iut->ta);

    if (pco_iut1 != NULL)
        cfg_del_instance_fmt(FALSE, "/agent:%s/env:EF_UDP_NETMASK", 
                             pco_iut1->ta);

    if (pco_iut2 != NULL)
        cfg_del_instance_fmt(FALSE, "/agent:%s/env:EF_UDP_NETMASK", 
                             pco_iut2->ta);

    if (pco_iut != NULL)
        tapi_cfg_del_neigh_dynamic(pco_iut->ta, NULL);
    if (pco_iut1 != NULL)
        tapi_cfg_del_neigh_dynamic(pco_iut1->ta, NULL);

    if (pco_iut != NULL)
        if (rcf_rpc_server_restart(pco_iut) != 0)
            WARN("Failed to restart pco_iut");

    if (pco_iut1 != NULL)
        if (rcf_rpc_server_restart(pco_iut1) != 0)
            WARN("Failed to restart pco_iut");

    if (pco_iut2 != NULL)
        if (rcf_rpc_server_restart(pco_iut2) != 0)
            WARN("Failed to restart pco_iut");
    
    TEST_END;
}
