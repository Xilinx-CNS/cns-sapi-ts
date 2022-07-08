/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Socket options
 *
 * $Id$
 */

/** @page sockopts-keepalive_enforce Influence of SO_KEEPALIVE functionality on a state of probing socket
 *
 * @objective Check that unsuccessful 'keepalive' probing influences on
 *            socket itself. For example, the @b iomux_call() should break
 *            out with read event on this socket.
 *
 * @type conformance
 *
 * @param pco_iut       PCO on IUT
 * @param pco_gw        PCO on host in the tested network
 *                      that is able to forward incoming packets (router)
 * @param pco_tst       PCO on TESTER
 * @param func          @b iomux_call(), @b read(), @b readv(), @b recv(),
 *                      @b recv_from(), @b recv_msg()
 * @param check_iomux   TRUE - @b iomux_call() should be tested;
 *                      FALSE - @p func should be tested only;
 * @param intv_cor      Correction for KEEPINTVL socket option to make
 *                      condition when KEEPINTVL < KEEPIDLE and
 *                      KEEPINTVL > KEEPIDLE
 *
 * @par Test sequence:
 * -# Create @c SOCK_STREAM connection between @p pco_iut and @p pco_tst
 *    by means of GEN_CONNECTION to get @p iut_s and @p tst_s sockets.
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Configure idle time, number of probes and interval between probes
 *    to avoid awating for two hours.
 * -# Call @b getsockopt() on @p iut_s socket with @c SO_KEEPALIVE socket
 *    option to get its initial value.
 * -# If @c SO_KEEPALIVE option is set to zero enable it with 
 *    @b setsockopt().
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# On @p pco_tst side add an alien static ARP entry for @p iut_addr
 *    specifying a link layer address that is not belong to any
 *    stations in subnetwork. Such trick makes it impossible for 
 *    @p pco_iut side receiving any data sent from @p tst_s.
 * -# 
 * -# According to @p check_iomux call @b iomux_call() or @p func on
 *    @p pco_iut.
 * -# Sleep while probes are being sent and RST will be sent.
 * -# According to @p check_iomux wait for @b iomux_call() return and 
 *    call @p func after or wait for @p func results.
 * -# Check that returned expected value:
 *     - @b iomux_call() - readable event;
 *     - @b recv() - -1 and errno set to @c ETIMEOUT.
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Delete the static ARP entry to allow further packets to be delivered.
 * -# Check that connection is aborted from @p tst_s socket point of
 *    view as well:
 *      -# Try to send data via @p tst_s socket, if attempt fails
 *         check that @b errno is set to @c ECONNRESET.
 *      -# If the first attempt is passed, try once more 10 milliseconds
 *         later and check that it fails with @c ECONNRESET @b errno set.
 * -# Close @p tst_s, and @p iut_s sockets.
 *
 * @author Igor Vasiliev <Igor.Vasiliev@oktetlabs.ru>
 */

#define TE_TEST_NAME  "sockopts/keepalive_enforce"

#include "sockapi-test.h"
#include "tapi_cfg.h"
#include "tapi_cfg_base.h"
#include "tapi_route_gw.h"
#include "iomux.h"


/* This configuration enables to avoid awaiting for two hours */

#define TIME_BEFORE_PROBES  (30)
#define PROB_INTERVAL       (24)
#define PROB_NUM             2
#define EPSILON              10

#define TST_SET_OPT_WITH_CHECKING(_level, _opt, _optval) \
        do {                                                        \
            int optval = _optval;                                   \
                                                                    \
            RPC_AWAIT_IUT_ERROR(pco_iut);                           \
            ret = rpc_setsockopt(pco_iut, iut_s, _opt, &optval);    \
            if (ret != 0)                                           \
            {                                                       \
                TEST_VERDICT("setsockopt(%s) failed with errno %s", \
                             sockopt_rpc2str(_opt),                 \
                             errno_rpc2str(RPC_ERRNO(pco_iut)));    \
            }                                                       \
            optval = 0;                                             \
            rpc_getsockopt(pco_iut, iut_s, _opt, &optval);          \
            if (optval != _optval)                                  \
                TEST_FAIL("It's impossible to set "#_opt" to %d",   \
                          _optval);                                 \
        } while (0)

#define CALL_RPC_IOMUX_READBL(_pco, _sock, _timeout) \
    do {                                                           \
        pco_##_pco->op = RCF_RPC_CALL;                             \
        rc = iomux_call_default_simple(pco_##_pco, _sock, EVT_RD,  \
                                       NULL, TE_SEC2MS(_timeout)); \
        if (rc != 0)                                               \
        {                                                          \
            TEST_FAIL("Start of non-blocking operation "           \
                      "on 'pco_"#_pco"' returns %d "               \
                      "instead of 0", rc);                         \
        }                                                          \
    } while (0)

#define WAIT_RPC_IOMUX_READBL(_pco, _sock, _timeout) \
    do {                                                             \
        iomux_evt revt = 0;                                          \
        pco_##_pco->op = RCF_RPC_WAIT;                               \
        rc = iomux_call_default_simple(pco_##_pco, _sock, EVT_RD,    \
                                       &revt, TE_SEC2MS(_timeout));  \
                                                                     \
        if (rc == 0)                                                 \
            TEST_FAIL("Unexpected iomux_call() timeout");            \
        else if (!(revt & EVT_RD))                                   \
            TEST_FAIL("iomux_call() returns with unexpected event"); \
    } while (0)

#define TST_VEC                 1
#define TST_BUF_LEN             4096
#define TST_BUF_RW              10

#define TST_FUNC(_func) \
    do {                                                                \
        RPC_AWAIT_IUT_ERROR(pco_iut);                                   \
        if (strcmp(_func, "read") == 0)                                 \
        {                                                               \
            rc = rpc_read(pco_iut, iut_s, tst_buf, TST_BUF_RW);         \
        }                                                               \
        else if (strcmp(_func, "readv") == 0)                           \
        {                                                               \
            rc = rpc_readv(pco_iut, iut_s, &xx_vector, TST_VEC);        \
        }                                                               \
        else if (strcmp(_func, "recv") == 0)                            \
        {                                                               \
            rc = rpc_recv(pco_iut, iut_s, tst_buf, TST_BUF_RW, 0);      \
        }                                                               \
        else if (strcmp(_func, "recvfrom") == 0)                        \
        {                                                               \
            rc = rpc_recvfrom(pco_iut, iut_s, tst_buf,                  \
                              TST_BUF_RW, 0, NULL, NULL);               \
        }                                                               \
        else if (strcmp(_func, "recvmsg") == 0)                         \
        {                                                               \
             rc = rpc_recvmsg(pco_iut, iut_s, &xx_msghdr, 0);           \
        }                                                               \
        else if (strcmp(_func, "onload_zc_recv") == 0)                  \
        {                                                               \
             rc = rpc_simple_zc_recv(pco_iut, iut_s, &xx_msghdr, 0);    \
        }                                                               \
        else                                                            \
        {                                                               \
            TEST_FAIL("Unexpected %s() function for testing", _func);   \
        }                                                               \
    } while (0)

#define CALL_TST_FUNC(_func) \
    do {                                \
        pco_iut->op = RCF_RPC_CALL;     \
        TST_FUNC(_func);                \
    } while (0)

#define WAIT_TST_FUNC(_func) \
    do {                                \
        pco_iut->op = RCF_RPC_WAIT;     \
        TST_FUNC(_func);                \
    } while (0)



int
main(int argc, char *argv[])
{
    rpc_socket_domain      domain;
    rcf_rpc_server        *pco_iut = NULL;
    rcf_rpc_server        *pco_gw = NULL;
    rcf_rpc_server        *pco_tst = NULL;
    int                    iut_s = -1;
    int                    tst_s = -1;

    const struct sockaddr *iut_addr = NULL;
    const struct sockaddr *tst_addr = NULL;
    const struct sockaddr *gw1_addr = NULL;
    const struct sockaddr *gw2_addr = NULL;

    const struct if_nameindex   *gw2_if = NULL;
    const struct if_nameindex   *tst_if = NULL;

    te_bool                route_dst_added = FALSE;
    te_bool                route_src_added = FALSE;
    te_bool                arp_entry_added = FALSE;

    const void            *alien_link_addr;

    int                    ret;
    int                    optval;

    /* buffers for test purposes */
    uint8_t                  tst_buf[TST_BUF_LEN];
    struct sockaddr_storage  msg_name;
    socklen_t                msg_namelen = sizeof(msg_name);

    struct rpc_iovec         xx_vector;
    rpc_msghdr               xx_msghdr;

    int                      timeout;

    const char              *func;
    te_bool                  check_iomux = TRUE;

    int                      intv_cor;
    

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_gw);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_ADDR_NO_PORT(gw1_addr);
    TEST_GET_ADDR_NO_PORT(gw2_addr);
    TEST_GET_LINK_ADDR(alien_link_addr);
    TEST_GET_IF(gw2_if);
    TEST_GET_IF(tst_if);
    TEST_GET_BOOL_PARAM(check_iomux);
    TEST_GET_STRING_PARAM(func);
    TEST_GET_INT_PARAM(intv_cor);
    
    domain = rpc_socket_domain_by_addr(iut_addr);

    xx_vector.iov_base = tst_buf;
    xx_vector.iov_len = xx_vector.iov_rlen = TST_BUF_RW;

    memset(&xx_msghdr, 0, sizeof(xx_msghdr));
    xx_msghdr.msg_iovlen = xx_msghdr.msg_riovlen = TST_VEC;
    xx_msghdr.msg_iov = &xx_vector;
    xx_msghdr.msg_control = NULL;
    xx_msghdr.msg_controllen = 0;
    xx_msghdr.msg_cmsghdr_num = 1;
    xx_msghdr.msg_name = &msg_name;
    xx_msghdr.msg_namelen = xx_msghdr.msg_rnamelen = msg_namelen;

    /* Add route on 'pco_iut': 'tst_addr' via gateway 'gw1_addr' */
    if (tapi_cfg_add_route_via_gw(pco_iut->ta,
            addr_family_rpc2h(sockts_domain2family(domain)),
            te_sockaddr_get_netaddr(tst_addr),
            te_netaddr_get_size(addr_family_rpc2h(
                sockts_domain2family(domain))) * 8,
            te_sockaddr_get_netaddr(gw1_addr)) != 0)
    {
        TEST_FAIL("Cannot add route to the dst");
    }
    route_dst_added = TRUE;

    /* Add route on 'pco_tst': 'iut_addr' via gateway 'gw2_addr' */
    if (tapi_cfg_add_route_via_gw(pco_tst->ta,
            addr_family_rpc2h(sockts_domain2family(domain)),
            te_sockaddr_get_netaddr(iut_addr),
            te_netaddr_get_size(addr_family_rpc2h(
                sockts_domain2family(domain))) * 8,
            te_sockaddr_get_netaddr(gw2_addr)) != 0)
    {
        TEST_FAIL("Cannot add route to the src");
    }
    route_src_added = TRUE;

    /* Turn on forwarding on router host */
    CHECK_RC(tapi_cfg_sys_set_int(pco_gw->ta, 1, NULL,
                                  "net/ipv4/ip_forward"));
    CFG_WAIT_CHANGES;


    /* Scenario */
    GEN_CONNECTION(pco_iut, pco_tst, RPC_SOCK_STREAM, RPC_PROTO_DEF,
                   iut_addr, tst_addr, &iut_s, &tst_s);

    /*
     * Configure idle time, number of probes and
     * interval between probes to avoid awating for two hours
     */
    RPC_AWAIT_IUT_ERROR(pco_iut);
    ret = rpc_getsockopt(pco_iut, iut_s, RPC_TCP_KEEPIDLE, &optval);
    if (ret == 0)
    {
        TST_SET_OPT_WITH_CHECKING(RPC_SOL_TCP, RPC_TCP_KEEPIDLE,
                                  TIME_BEFORE_PROBES);
        TST_SET_OPT_WITH_CHECKING(RPC_SOL_TCP, RPC_TCP_KEEPINTVL,
                                  PROB_INTERVAL + intv_cor);
        TST_SET_OPT_WITH_CHECKING(RPC_SOL_TCP, RPC_TCP_KEEPCNT,
                                  PROB_NUM);
    }
    else
    {
        CHECK_RPC_ERRNO(pco_iut, RPC_ENOPROTOOPT,
                        "getsockopt(TCP_KEEPIDLE) failed");

        TST_SET_OPT_WITH_CHECKING(RPC_SOL_TCP,
                                  RPC_TCP_KEEPALIVE_THRESHOLD,
                                  TE_SEC2MS(TIME_BEFORE_PROBES));
        TST_SET_OPT_WITH_CHECKING(RPC_SOL_TCP,
                                  RPC_TCP_KEEPALIVE_ABORT_THRESHOLD,
                                  TE_SEC2MS((PROB_INTERVAL + intv_cor)
                                            * PROB_NUM));
    }

    rpc_getsockopt(pco_iut, iut_s, RPC_SO_KEEPALIVE, &optval);
    RING("Default value for SO_KEEPALIVE is turned %s",
                          optval ? "ON" : "OFF");
    if (optval == 0)
    {
        optval = 1;
        rpc_setsockopt(pco_iut, iut_s, RPC_SO_KEEPALIVE, &optval);

        rpc_getsockopt(pco_iut, iut_s, RPC_SO_KEEPALIVE, &optval);
        if (optval == 0)
        {
            TEST_FAIL("The value of SO_KEEPALIVE socket option is not "
                      "updated by setsockopt() function");
        }
    }

    /* Add an alien static ARP entry for 'iut' address */
    if (tapi_update_arp(pco_tst->ta, tst_if->if_name, NULL, NULL,
                        gw2_addr, CVT_HW_ADDR(alien_link_addr),
                        TRUE) != 0)
    {
        TEST_FAIL("Cannot add an alien ARP entry for 'iut' address ");
    }
    arp_entry_added = TRUE;

    if (check_iomux)
    {
        timeout = (PROB_INTERVAL + intv_cor) * PROB_NUM * 2 +
                  EPSILON * 2 + TIME_BEFORE_PROBES;
        CALL_RPC_IOMUX_READBL(iut, iut_s, timeout);
    }
    else
    {
        CALL_TST_FUNC(func);
    }

    SLEEP(TIME_BEFORE_PROBES);

    /*
     * Sleep while probes are being sent.
     * After all the probes exausted, 'pco_iut' sends RST and we should
     * capture it on 'pco_tst'.
     */
    SLEEP(((PROB_INTERVAL + intv_cor)* PROB_NUM) - ((PROB_INTERVAL + intv_cor)/ 2));

    /* Wait until RST comes */
    SLEEP((PROB_INTERVAL + intv_cor)/ 2 + EPSILON);

    if (check_iomux == TRUE)
    {
        WAIT_RPC_IOMUX_READBL(iut, iut_s, timeout);
        TST_FUNC(func);
    }
    else
    {
        WAIT_TST_FUNC(func);
    }

    if (rc != -1)
        TEST_FAIL("%s(pco_iut) returned %d instead of -1 when "
                  "RST is sent to 'pco_tst'", func, rc);
    CHECK_RPC_ERRNO(pco_iut, RPC_ETIMEDOUT,
                    "%s(pco_iut) returned -1, but", func);


    CHECK_RC(tapi_cfg_del_neigh_entry(pco_tst->ta, tst_if->if_name,
                                      gw2_addr));
    arp_entry_added = FALSE;
    CFG_WAIT_CHANGES;


    /* Now 'tst_s' socket has received RST, so the following send() fails */
    RPC_AWAIT_IUT_ERROR(pco_tst);
    rc = rpc_send(pco_tst, tst_s, tst_buf, sizeof(tst_buf), 0);
    if (rc == -1)
    {
        CHECK_RPC_ERRNO(pco_tst, RPC_ECONNRESET, "send() returns -1, but");
    }
    else
    {
        RING("Keep-alive failed, but IUT does not send RST in "
             "broken connection");

        /* 
         * Try to send once more with small delay to have a chance to
         * receive RST sent by IUT in response to our data.
         */
        MSLEEP(10);
        RPC_AWAIT_IUT_ERROR(pco_tst);
        rc = rpc_send(pco_tst, tst_s, tst_buf, sizeof(tst_buf), 0);
        if (rc != -1)
        {
            TEST_VERDICT("Keep-alive failed, but IUT does not send RST "
                         "in response to peer data");
        }
        CHECK_RPC_ERRNO(pco_tst, RPC_ECONNRESET, "send() returns -1, but");
    }

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    if (arp_entry_added &&
        tapi_cfg_del_neigh_entry(pco_tst->ta, tst_if->if_name, gw2_addr) != 0)
    {
        ERROR("Cannot delete ARP entry while cleanup");
        result = EXIT_FAILURE;
    }

    if (route_dst_added &&
        tapi_cfg_del_route_via_gw(pco_iut->ta,
            addr_family_rpc2h(sockts_domain2family(domain)),
            te_sockaddr_get_netaddr(tst_addr),
            te_netaddr_get_size(addr_family_rpc2h(
                sockts_domain2family(domain))) * 8,
            te_sockaddr_get_netaddr(gw1_addr)) != 0)
    {
        ERROR("Cannot delete route to the dst");
        result = EXIT_FAILURE;
    }

    if (route_src_added &&
        tapi_cfg_del_route_via_gw(pco_tst->ta,
            addr_family_rpc2h(sockts_domain2family(domain)),
            te_sockaddr_get_netaddr(iut_addr),
            te_netaddr_get_size(addr_family_rpc2h(
                sockts_domain2family(domain))) * 8,
            te_sockaddr_get_netaddr(gw2_addr)) != 0)
    {
        ERROR("Cannot delete route to the src");
        result = EXIT_FAILURE;
    }

    TEST_END;
}

