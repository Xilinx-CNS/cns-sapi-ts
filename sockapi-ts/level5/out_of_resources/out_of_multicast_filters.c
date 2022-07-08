/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Level5-specific test reproducing run out of hardware resources
 *
 * $Id$
 */

/** @page level5-out_of_resources-out_of_multicast_filters Multicast filters exhaustion caused by joining to many groups
 *
 * @objective Check that Level5 library does not return error
 *            when there are no more multicast filters available
 *            when joining to too many multicast groups.
 *
 * @type conformance, robustness
 *
 *
 * @param pco_iut           PCO on IUT
 * @param pco_tst           PCO on TESTER
 * @param sock_func         Socket creation function for IUT
 * @param bind_before       Bind socket on IUT to the port before or after
 *                          joining the groups
 * @param overfill          Overflow HW filters before using multicasts
 *                          if @c TRUE
 * 
 * @par Test sequence:
 * -# Set @p net.ipv4.igmp_max_memberships to @c 4096 and
 *    @p net.core.optmem_max to @c 196608 on @p pco_iut.
 * -# Create @p iut_tcp_s, @p tst_tcp_s1, @p tst_tcp_s2, @p iut_udp_s and
 *    @p tst_udp_s of @c SOCK_STREAM and @c SOCK_DGRAM types on @p pco_iut
 *    and @p pco_tst respectively.
 * -# Bind @p iut_tcp_s socket to some port @p port1.
 * -# Call @b listen() on @p iut_tcp_s.
 * -# Bind @p iut_udp_s socket to some port @p port2.
 * -# Create @p sock @c SOCK_DGRAM socket on @p pco_iut.
 * -# If @p bind_before is @c TRUE bind @p sock to some @p port.
 * -# On @p sock join all multicast groups between @c 239.255.16.0 and
 *    @c 239.255.23.255.
 * -# If @p bind_before is @c FALSE bind @p sock to some @p port.
 * -# Send datagrams from @p pco_tst to some of multicast groups between
 *    @c 239.255.16.0 and @c 239.255.23.255, read them from @p sock socket,
 *    and check that they are correct.
 * -# Chech that the stack is still working properly:
 *      - Call @b connect() on tst_tcp_s1 socket to connect to 
 *        @p iut_addr1:@p port1
 *      - Call @b accept() on @p iut_tcp_s to create @p acc_s1 socket.
 *      - Call @b connect() on tst_tcp_s2 socket to connect to 
 *        @p iut_addr2:@p port1
 *      - Call @b accept() on @p iut_tcp_s to create @p acc_s2 socket.
 *      - Check data transmission though those two connections.
 *      - Send data from @p tst_udp_s socket to @p iut_addr1:@p port2
 *      - Recieve data on @p iut_udp_s and check that it is correct.
 *      - Send data from @p tst_udp_s socket to @p iut_addr2:@p port2
 *      - Recieve data on @p iut_udp_s and check that it is correct.
 *
 * @author Yurij Plotnikov <Yurij.Plotnikov@oktetlabs.ru>
 */

#define TE_TEST_NAME    "level5/out_of_resources/out_of_multicast_filters"

#include "sockapi-test.h"
#include "out_of_resources.h"
#include "onload.h"

#define DATA_BULK   200
#define SOCK_NUM 3
#define JOIN_PER_SOCK 3000

#define MAX_ATTEMPTS 50

#define MAX_ATTEMPTS_ONE_GR 5

#define TIMEOUT 90000

/**
 * Address context.
 */
typedef struct address_ctx {
    unsigned long s_addr;   /**< Address value */
    te_bool skip;           /**< Is it skipped */
} address_ctx;

#define CHECK_CONNECTION(_pco1, _sock1, _pco2, _sock2)  \
do {                                                                    \
    RPC_SEND(rc, _pco2, _sock2, tx_buf, buf_len, 0);                    \
    rc = rpc_recv(_pco1, _sock1, rx_buf, buf_len, 0);                   \
                                                                        \
    if ((rc != (int)buf_len) || (memcmp(tx_buf, rx_buf, buf_len) != 0)) \
    {                                                                   \
        TEST_FAIL("Some data was corrupted while sending from"          \
                  "%s to %s", #_pco2, #_pco1);                          \
    }                                                                   \
} while (0)

/**
 * Try to connect to the same multicast group a few times.
 * 
 * @param pco_iut       RPC server handler
 * @param sock          Socket
 * @param mcast_addr    Multicast address
 * @param iut_if        Interface handler
 * @param err           Error counter location
 * 
 * @return @c TRUE in case of failure, else @c FALSE
 */
te_bool
try_mcast_join(rcf_rpc_server *pco_iut, int sock,
               struct sockaddr_in *mcast_addr,
               const struct if_nameindex *iut_if)
{
    int rc;
    int i;

    for (i = 0; i < MAX_ATTEMPTS_ONE_GR; i++)
    {
        RPC_AWAIT_IUT_ERROR(pco_iut);
        rc = rpc_mcast_join(pco_iut, sock, SA(mcast_addr),
                            iut_if->if_index, TARPC_MCAST_ADD_DROP);
        if (rc < 0)
        {
            if (RPC_ERRNO(pco_iut) == RPC_EBUSY)
                continue;
            else
                TEST_VERDICT("Failed to join to the multicast with "
                             "unexpected errno: %r", RPC_ERRNO(pco_iut));
        }
        else
        {
            if (i == 0)
                return FALSE;
            else
                TEST_VERDICT("Multicast group is joined with attempt #%d", i);
        }
    }

    return TRUE;
}

int
main(int argc, char *argv[])
{

    rcf_rpc_server *pco_iut  = NULL;
    rcf_rpc_server *pco_tst  = NULL;

    rcf_rpc_server *pco_aux = NULL;
    rcf_rpc_server *pco_tst_aux = NULL;

    const struct if_nameindex *iut_if;

    const struct sockaddr     *iut_addr;
    struct sockaddr_storage    iut_addr_an_port;
    const struct sockaddr     *tst_addr;
    struct sockaddr           *aux_iut_addr;

    struct sockaddr_storage  wildcard_addr;
    struct sockaddr_in       mcast_addr;

    cfg_handle      new_addr_hndl = CFG_HANDLE_INVALID;
    rpc_ptr         accept_hndl = RPC_NULL;

    int             sock[SOCK_NUM] = {-1, -1, -1};
    int             iut_tcp_s = -1;
    int             tst_tcp_s1 = -1;
    int             tst_tcp_s2 = -1;
    int             acc_s1 = -1;
    int             acc_s2 = -1;
    int             iut_udp_s = -1;
    int             tst_udp_s = -1;
    int             mcast_send_sock  = -1;

    int             tst_l = -1;
    int             iut_s_1 = -1;
    int             iut_s_2 = -1;
    int             tst_s_1 = -1;
    int             tst_s_2 = -1;

    struct tarpc_mreqn         mreq;

    sockts_socket_func    sock_func;

    te_bool         bind_before = FALSE;
    te_bool         overfill;
    int             i;
    char            addr_buf[16];

    unsigned char         *tx_buf = NULL;
    unsigned char         *rx_buf = NULL;
    size_t                 buf_len = DATA_BULK;

    tapi_env_net          *net;

    address_ctx  *ac = NULL;
    unsigned int  unacc = 0;
    int           hw_filters_max;
    te_bool       ef_no_fail;
    te_bool       check_res = FALSE;
    int req_num     = 0;
    int sock_num    = 0;
    int acc         = 0;
    int err         = 0;
    int attempt     = 0;
    int limit       = 0;
    int req_num_m   = 0;
    int sock_num_m  = 0;
    int sock_num_n  = 0;
    int acc_m       = 0;
    int loglevel;
    int s;

    csap_handle_t csap = CSAP_INVALID_HANDLE;

    TEST_START;
    TEST_GET_NET(net);
    TEST_GET_IF(iut_if);
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    SOCKTS_GET_SOCK_FUNC(sock_func);
    TEST_GET_BOOL_PARAM(bind_before);
    TEST_GET_BOOL_PARAM(overfill);
    TEST_GET_BOOL_PARAM(ef_no_fail);

    /* This arguments combination does not have sense for this test.
     * Skipping is done here since @p ef_no_fail is the session argument. */
    if (overfill && !ef_no_fail)
    {
        RING("This iteration does not have sense for EF_NO_FAIL=0");
        TEST_SUCCESS;
    }

    hw_filters_max = get_hw_filters_limit(pco_iut);
    req_num_m = hw_filters_max / 4;

    /** Increase ARP table size. It can be exhausted on the old linux
     * (tested on 2.6.32-bpo.5-amd64), because of multiple sendto() with
     * multicasts. Modern linux like 2.6.32-431.29.2.el6.x86_64 can work
     * without this. */
    CHECK_RC(tapi_cfg_sys_ns_set_int(pco_tst->ta, hw_filters_max + 1000, NULL,
                                     "net/ipv4/neigh:default/gc_thresh3"));

    CHECK_RC(tapi_cfg_sys_ns_set_int(pco_iut->ta, 10000, NULL,
                                     "net/ipv4/igmp_max_memberships"));
    CHECK_RC(tapi_cfg_sys_ns_set_int(pco_iut->ta, 500000, NULL,
                                     "net/core/optmem_max"));

    if (overfill)
    {
        TAPI_SYS_LOGLEVEL_DEBUG(pco_iut, &loglevel);

        pco_aux = pco_iut;
        req_num = req_num_m;
        prepare_parent_pco(pco_aux, 2 * hw_filters_max);
        CHECK_RC(rcf_rpc_server_fork(pco_aux, "child", &pco_iut));
        CHECK_RC(rcf_rpc_server_exec(pco_iut));
        prepare_parent_pco(pco_tst, 2 * hw_filters_max);
        CHECK_RC(rcf_rpc_server_fork(pco_tst, "tst_child", &pco_tst_aux));

        if ((tst_l = rpc_create_and_bind_socket(pco_tst_aux, RPC_SOCK_STREAM,
                                                RPC_PROTO_DEF, FALSE, FALSE,
                                                tst_addr)) < 0)
            TEST_FAIL("Cannot create SOCK_STREAM 'tst_l' socket");
        rpc_listen(pco_tst_aux, tst_l, hw_filters_max);

        rpc_fcntl(pco_tst_aux, tst_l, RPC_F_SETFL, RPC_O_NONBLOCK);

        pco_tst_aux->timeout =  TIMEOUT;
        pco_tst_aux->op = RCF_RPC_CALL;
        rpc_many_accept(pco_tst_aux, tst_l, req_num + 3000, 0, 0,
                        &tst_s_1, &tst_s_2, &accept_hndl);

        pco_iut->timeout = TIMEOUT;
        sock_num = rpc_out_of_hw_filters_do(pco_iut, TRUE, iut_addr,
            tst_addr, RPC_SOCK_STREAM, RPC_OOR_CONNECT, req_num, &acc, &err,
            &iut_s_1, &iut_s_2);

        RING("Created sockets number %d/%d/%d/%d", req_num, sock_num, acc, err);

        rpc_many_accept(pco_tst_aux, tst_l, req_num + 3000, 0, 0, &tst_s_1,
                        &tst_s_2, &accept_hndl);
        rpc_fcntl(pco_tst_aux, tst_l, RPC_F_SETFL, 0);

        TAPI_SYS_LOGLEVEL_CANCEL_DEBUG(pco_iut, loglevel);

        req_num_m = 20;
    }

    tx_buf = te_make_buf_by_len(buf_len);
    rx_buf = te_make_buf_by_len(buf_len);

    if ((iut_tcp_s = rpc_create_and_bind_socket(pco_iut, RPC_SOCK_STREAM,
                                                RPC_PROTO_DEF, TRUE, FALSE,
                                                iut_addr)) < 0)
        TEST_FAIL("Cannot create SOCK_STREAM 'iut_tcp_s' socket");
    rpc_listen(pco_iut, iut_tcp_s, SOCKTS_BACKLOG_DEF);

    tst_tcp_s1 = rpc_socket(pco_tst, RPC_PF_INET, RPC_SOCK_STREAM,
                            RPC_PROTO_DEF);
    tst_tcp_s2 = rpc_socket(pco_tst, RPC_PF_INET, RPC_SOCK_STREAM,
                            RPC_PROTO_DEF);

    CHECK_RC(tapi_sockaddr_clone(pco_iut, iut_addr, &iut_addr_an_port));
    if ((iut_udp_s = rpc_create_and_bind_socket(pco_iut, RPC_SOCK_DGRAM,
                                                RPC_PROTO_DEF, TRUE, FALSE,
                                                SA(&iut_addr_an_port))) < 0)
        TEST_FAIL("Cannot create SOCK_DGRAM 'iut_udp_s' socket");
    tst_udp_s = rpc_socket(pco_tst, RPC_PF_INET, RPC_SOCK_DGRAM,
                           RPC_PROTO_DEF);

    memset(&mcast_addr, 0, sizeof(mcast_addr));
    mcast_addr.sin_family = AF_INET;
    TAPI_SET_NEW_PORT(pco_iut, &mcast_addr);
    memcpy(&wildcard_addr, &mcast_addr,
           te_sockaddr_get_size(SA(&mcast_addr)));
    te_sockaddr_set_wildcard(SA(&wildcard_addr));

    if (req_num_m > SOCK_NUM * JOIN_PER_SOCK)
        TEST_FAIL("Not enoguth sockets number. Fix the test!");

    limit = req_num_m;
    ac = te_calloc_fill(limit, sizeof(*ac), 0);

    TAPI_SYS_LOGLEVEL_DEBUG(pco_iut, &loglevel);
    for (s = 0, i = 0; s < SOCK_NUM && i < limit; s++, i++)
    {
        sock[s] = sockts_socket(sock_func, pco_iut, RPC_PF_INET,
                                RPC_SOCK_DGRAM, RPC_PROTO_DEF);
        rpc_setsockopt_int(pco_iut, sock[s], RPC_SO_REUSEADDR, 1);

        if (bind_before)
            rpc_bind(pco_iut, sock[s], SA(&wildcard_addr));

        for (; i < limit; i++)
        {
            memset(addr_buf, 0, sizeof(addr_buf));
            sprintf(addr_buf, "239.255.%d.%d", (i / 256) + 16, i % 256);
            ac[i].s_addr = inet_addr(addr_buf);
            mcast_addr.sin_addr.s_addr = ac[i].s_addr;

            if (!bind_before)
                rpc_mcast_join(pco_iut, sock[s], SA(&mcast_addr),
                               iut_if->if_index, TARPC_MCAST_ADD_DROP);
            else
            {
                if (try_mcast_join(pco_iut, sock[s], &mcast_addr, iut_if))
                {
                    ac[i].skip = TRUE;
                    err++;
                    attempt++;
                }
                else
                    attempt = 0;
            }

            sock_num_m = i;
            if ((i > 0 && i % JOIN_PER_SOCK == 0) || attempt > MAX_ATTEMPTS)
                break;
        }

        sock_num_n = s;

        if (attempt > MAX_ATTEMPTS)
            break;
    }

    memset(&mreq, 0, sizeof(mreq));
    mreq.type = OPT_IPADDR;
    memcpy(&mreq.address, te_sockaddr_get_netaddr(tst_addr),
           sizeof(mreq.address));

    mcast_send_sock = rpc_socket(pco_tst, RPC_PF_INET, RPC_SOCK_DGRAM, RPC_PROTO_DEF);
    rpc_setsockopt(pco_tst, mcast_send_sock, RPC_IP_MULTICAST_IF, &mreq);

    csap = create_listener_csap(pco_iut, iut_if);

    for (i = 0, s = 0; s <= sock_num_n && i < sock_num_m; s++, i++)
    {
        if (!bind_before)
        {
            if (!ef_no_fail && s == sock_num_n)
                RPC_AWAIT_IUT_ERROR(pco_iut);
            pco_iut->timeout = 90000;
            if (rpc_bind(pco_iut, sock[s], SA(&wildcard_addr)) < 0)
            {
                check_res = FALSE;
                sock_num_m = i;
                break;
            }
        }

        for (; i < sock_num_m; i++)
        {
            if (i > 0 && i % JOIN_PER_SOCK == 0)
                break;

            if (ac[i].skip)
                continue;

            mcast_addr.sin_addr.s_addr = ac[i].s_addr;
            rpc_sendto(pco_tst, mcast_send_sock, tx_buf, DATA_BULK, 0,
                       SA(&mcast_addr));

            rc = rpc_recv(pco_iut, sock[s], rx_buf, buf_len, 0);
            if ((rc != (int)buf_len) || (memcmp(tx_buf, rx_buf, buf_len) != 0))
                TEST_FAIL("Some data was corrupted while sending from to %s "
                          "multicast address", addr_buf);
        }
    }
    TAPI_SYS_LOGLEVEL_CANCEL_DEBUG(pco_iut, loglevel);

    CHECK_RC(tapi_tad_trrecv_stop(pco_iut->ta, 0, csap, NULL,
                                  (unsigned int *)&unacc));
    acc_m = sock_num_m - unacc;

    RING("Multicast packets number %d/%d/%d", req_num_m, sock_num_m, acc_m);

    CHECK_RC(tapi_cfg_alloc_net_addr(net->ip4net, NULL, &aux_iut_addr));
    if (tapi_cfg_base_if_add_net_addr(pco_iut->ta, iut_if->if_name,
                                      aux_iut_addr, net->ip4pfx, FALSE,
                                      &new_addr_hndl) != 0)
        TEST_FAIL("Cannot add additional address to iut_if");
    TAPI_WAIT_NETWORK;

    rpc_connect(pco_tst, tst_tcp_s1, iut_addr);
    acc_s1 = rpc_accept(pco_iut, iut_tcp_s, NULL, NULL);

    te_sockaddr_set_port(SA(aux_iut_addr),
                         *(te_sockaddr_get_port_ptr(SA(iut_addr))));
    rpc_connect(pco_tst, tst_tcp_s2, aux_iut_addr);
    TAPI_WAIT_NETWORK;
    acc_s2 = rpc_accept(pco_iut, iut_tcp_s, NULL, NULL);

    RPC_SENDTO(rc, pco_tst, tst_udp_s, tx_buf, buf_len, 0,
               SA(&iut_addr_an_port));
    te_sockaddr_set_port(SA(aux_iut_addr),
                         *(te_sockaddr_get_port_ptr(
                                            SA(&iut_addr_an_port))));
    RPC_SENDTO(rc, pco_tst, tst_udp_s, tx_buf, buf_len, 0,
               aux_iut_addr);

    CHECK_CONNECTION(pco_iut, acc_s1, pco_tst, tst_tcp_s1);
    CHECK_CONNECTION(pco_iut, acc_s2, pco_tst, tst_tcp_s2);

    rc = rpc_recv(pco_iut, iut_udp_s, rx_buf, buf_len, 0);
    if ((rc != (int)buf_len) || (memcmp(tx_buf, rx_buf, buf_len) != 0))
        TEST_FAIL("Some data was corrupted while sending via UDP socket.");
    rc = rpc_recv(pco_iut, iut_udp_s, rx_buf, buf_len, 0);
    if ((rc != (int)buf_len) || (memcmp(tx_buf, rx_buf, buf_len) != 0))
        TEST_FAIL("Some data was corrupted while sending via UDP socket.");

    TEST_STEP("Check busy HW filters number.");
    RING("Results: requested/joined/accelerated/errors hw_filters_max: "
         "%d/%d/%d/%d  %d", req_num + req_num_m, sock_num + sock_num_m  - err,
         acc + acc_m  - err, err, hw_filters_max);

    if (ef_no_fail && err != 0)
        TEST_VERDICT("Fails were observed when EF_NO_FAIL=1");
    if (!ef_no_fail && unacc != 0)
        TEST_VERDICT("Unaccelerated multicast packets were received");

    /* Don't try to calculate spent HW filters, since there is no strict
     * rules for that and actually we do not need this to check if Onload
     * works. @p check_res is alway @c FALSE now. */
    if (check_res && approx_cmp(acc + acc_m, hw_filters_max) != 0)
        TEST_VERDICT("Opened accelerated sockets number differs "
                     "from HW filters number");

    TEST_SUCCESS;

cleanup:
    CLEANUP_CHECK_RC(tapi_tad_csap_destroy(pco_iut->ta, 0, csap));
    if (pco_tst_aux != NULL)
        rpc_many_close(pco_tst_aux, accept_hndl, req_num + 3000);

    for (i = 0; i < SOCK_NUM; i++)
    {
        pco_iut->timeout = 300000;
        CLEANUP_RPC_CLOSE(pco_iut, sock[i]);
    }

    CLEANUP_RPC_CLOSE(pco_tst, mcast_send_sock);
    CLEANUP_RPC_CLOSE(pco_iut, iut_tcp_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_tcp_s1);
    CLEANUP_RPC_CLOSE(pco_tst, tst_tcp_s2);
    CLEANUP_RPC_CLOSE(pco_iut, acc_s1);
    CLEANUP_RPC_CLOSE(pco_iut, acc_s2);
    CLEANUP_RPC_CLOSE(pco_iut, iut_udp_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_udp_s);

    if (new_addr_hndl != CFG_HANDLE_INVALID)
        cfg_del_instance(new_addr_hndl, FALSE);

    free(tx_buf);
    free(rx_buf);
    free(ac);

    /* RHEL6 kernels are VERY SLOW in removing mcast address, so stop RPC
     * server (close sockets - remove mcast addresses from the interface)
     * and wait for some time. */
    rcf_rpc_server_restart(pco_iut);
    SLEEP(10);

    TEST_END;
}
