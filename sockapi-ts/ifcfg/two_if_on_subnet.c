/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 *
 *
 * $Id$
 */

/** @page ifcfg-two_if_on_subnet Two IUT interfaces are assigned IP addresses from the same subnet
 *
 * @objective Check stack behaviour if two IUT interfaces have
 *            IP addresses from the same subnet and check which is the route
 *            choosen to interact through.
 *
 * @note Linux behaviour depends on the order of the interface addresses
 *       assignment.
 *
 * @type conformance
 *
 * @param sock_type       @c SOCK_DGRAM or @c SOCK_STREAM
 * @param pco_iut1        PCO on IUT on iut_host
 * @param pco_tst1        PCO on TESTER on tst1_host
 * @param pco_tst2        PCO on TESTER on tst2_host
 * @param iut1_if_first   Order of assignment interface addresses:
 *                        TRUE/FALSE  - iut1_if/iut2_if is configured first
 *
 * @par Test sequence:
 * -# Allocate subnet from environment resources and configure:
 *    - both iut1_if and iut2_if with different addresses from allocated
 *      subnet;
 *    - both tst1_if and tst2_id with the same address from allocated
 *      subnet;
 * -# Create @p tst1_s socket of @p sock_type on @p pco_tst1;
 * -# @b bind() @p tst1_s socket to the @p tstsn_address;
 * -# In the case of @c SOCK_STREAM socket type call @b listen()
 *    on @p tst1_s socket;
 * -# Create @p tst2_s socket of @p sock_type on @p pco_tst2;
 * -# @b bind() @p tst2_s socket to the @p tstsn_address;
 * -# In the case of @c SOCK_STREAM socket type call @b listen()
 *    on @p tst2_s socket;
 * -# Create @p iut1_s socket of @p sock_type on @p pco_iut1;
 * -# In the case of:
 *    - @c SOCK_STREAM socket type call @b connect() on @p iut1_s
 *      socket to @p tstsn_address;
 *    - @c SOCK_DGRAM socket type call @b sendto() on @p iut1_s
 *      socket to @p tstsn_address;
 * -# On both @p tst1_s and tst2_s in the case of:
 *    - @c SOCK_STREAM socket type call @b accept();
 *    - @c SOCK_DGRAM socket type call @b recv();
 *    and check that only one of them has appropriate data,
 *    and appropriate link was active.
 * -# Close all involved sockets and free allocated resources.
 *
 * @author Igor Vasiliev <Igor.Vasiliev@oktetlabs.ru>
 */

#define TE_TEST_NAME  "ifcfg/two_if_on_subnet"

#include "sockapi-test.h"
#include "tapi_cfg.h"
#include "tapi_cfg_base.h"

#define TST_BUF_LEN           1024

int
main(int argc, char *argv[])
{
    rpc_socket_domain      domain;
    rpc_socket_type        sock_type;
    te_bool                iut1_if_first = FALSE;

    int                    af;
    tapi_env_host         *iut_host = NULL;
    tapi_env_host         *tst1_host = NULL;
    tapi_env_host         *tst2_host = NULL;

    tapi_env_net          *net1 = NULL;
    tapi_env_net          *net2 = NULL;

    rcf_rpc_server        *pco_iut1 = NULL;
    rcf_rpc_server        *pco_iut2 = NULL;
    rcf_rpc_server        *pco_tst1 = NULL;
    rcf_rpc_server        *pco_tst2 = NULL;

    int                    iut1_s = -1;
    int                    iut2_s = -1;
    int                    tst1_s = -1;
    int                    tst2_s = -1;
    int                    acc1_s = -1;
    int                    acc2_s = -1;

    const struct sockaddr   *iut1_addr = NULL;
    struct sockaddr_storage  iut1sn_addr;
    struct sockaddr         *iut1_subnet_addr = NULL;

    const struct sockaddr   *iut2_addr = NULL;
    struct sockaddr_storage  iut2sn_addr;
    struct sockaddr         *iut2_subnet_addr = NULL;

    const struct sockaddr   *tst1_addr = NULL;
    const struct sockaddr   *tst2_addr = NULL;

    struct sockaddr_storage  tstsn_addr;
    struct sockaddr         *tst_subnet_addr = NULL;

    const struct if_nameindex  *iut1_if = NULL;
    const struct if_nameindex  *iut2_if = NULL;
    const struct if_nameindex  *tst1_if = NULL;
    const struct if_nameindex  *tst2_if = NULL;
    cfg_handle                  net_handle;

    void     *tx_buf;
    void     *rx_buf;

    int     req_val;

    te_bool link1_active;
    te_bool link2_active;


    struct sockaddr_in     peer1_addr;
    socklen_t              peer1_addrlen = sizeof(struct sockaddr_in);

    struct sockaddr_in     peer2_addr;
    socklen_t              peer2_addrlen = sizeof(struct sockaddr_in);

    TEST_START;
    TEST_GET_SOCK_TYPE(sock_type);

    TEST_GET_PCO(pco_iut1);
    TEST_GET_PCO(pco_iut2);
    TEST_GET_PCO(pco_tst1);
    TEST_GET_PCO(pco_tst2);

    TEST_GET_NET(net1);
    TEST_GET_NET(net2);
    TEST_GET_HOST(iut_host);
    TEST_GET_HOST(tst1_host);
    TEST_GET_HOST(tst2_host);

    TEST_GET_ADDR(pco_iut1, iut1_addr);
    TEST_GET_ADDR(pco_iut2, iut2_addr);
    TEST_GET_ADDR(pco_tst1, tst1_addr);
    TEST_GET_ADDR(pco_tst2, tst2_addr);

    TEST_GET_IF(iut1_if);
    TEST_GET_IF(iut2_if);
    TEST_GET_IF(tst1_if);
    TEST_GET_IF(tst2_if);

    TEST_GET_BOOL_PARAM(iut1_if_first);

    tx_buf = te_make_buf_by_len(TST_BUF_LEN);
    rx_buf = te_make_buf_by_len(TST_BUF_LEN);

    domain = rpc_socket_domain_by_addr(iut1_addr);
    af = addr_family_rpc2h(sockts_domain2family(domain));

    CHECK_RC(tapi_cfg_alloc_ip4_net(&net_handle));
    CHECK_RC(tapi_cfg_alloc_net_addr(net_handle, NULL, &iut1_subnet_addr));
    CHECK_RC(tapi_cfg_alloc_net_addr(net_handle, NULL, &iut2_subnet_addr));
    CHECK_RC(tapi_cfg_alloc_net_addr(net_handle, NULL, &tst_subnet_addr));

    /*
     * Prepare two addresses from the same network to assign it
     * to iut_host interfaces.
     * These addresses have port the same as iut1_addr.
     */
    memset(&iut1sn_addr, 0, sizeof(iut1sn_addr));
    iut1sn_addr.ss_family = af;
    te_sockaddr_set_netaddr(SA(&iut1sn_addr),
                            te_sockaddr_get_netaddr(iut1_subnet_addr));
    te_sockaddr_set_port(SA(&iut1sn_addr), te_sockaddr_get_port(iut1_addr));

    memset(&iut2sn_addr, 0, sizeof(iut2sn_addr));
    iut2sn_addr.ss_family = af;
    te_sockaddr_set_netaddr(SA(&iut2sn_addr),
                            te_sockaddr_get_netaddr(iut2_subnet_addr));
    te_sockaddr_set_port(SA(&iut2sn_addr), te_sockaddr_get_port(iut1_addr));

    /*
     * Prepare address from the same network as previous two
     * to assign it to tst1_host interface and tst2_host interface.
     * This address has port the same as tst1_addr.
     */
    memset(&tstsn_addr, 0, sizeof(tstsn_addr));
    tstsn_addr.ss_family = af;
    te_sockaddr_set_netaddr(SA(&tstsn_addr),
                            te_sockaddr_get_netaddr(tst_subnet_addr));
    te_sockaddr_set_port(SA(&tstsn_addr), te_sockaddr_get_port(tst1_addr));

    /*
     * Two interfaces on IUT side should be configured with net addresses
     * from the same subnet. The order of the net address addition
     * influences on choice of the interface to connect/send.
     */
    if (iut1_if_first == TRUE)
    {
        /* Add iut1_subnet address to iut1_if */
        CHECK_RC(tapi_cfg_base_if_add_net_addr(pco_iut1->ta,
                                               iut1_if->if_name,
                                               SA(&iut1sn_addr),
                                               net1->ip4pfx,
                                               FALSE, NULL));
        /* Add iut2_subnet address to iut2_if */
        CHECK_RC(tapi_cfg_base_if_add_net_addr(pco_iut2->ta,
                                               iut2_if->if_name,
                                               SA(&iut2sn_addr),
                                               net2->ip4pfx,
                                               FALSE, NULL));
        RING("'iut1_if' has been configured first");
    }
    else
    {
        /* Add iut2_subnet address to iut2_if */
        CHECK_RC(tapi_cfg_base_if_add_net_addr(pco_iut2->ta,
                                               iut2_if->if_name,
                                               SA(&iut2sn_addr),
                                               net2->ip4pfx,
                                               FALSE, NULL));
        /* Add iut1_subnet address to iut1_if */
        CHECK_RC(tapi_cfg_base_if_add_net_addr(pco_iut1->ta,
                                               iut1_if->if_name,
                                               SA(&iut1sn_addr),
                                               net1->ip4pfx,
                                               FALSE, NULL));
        RING("'iut2_if' has been configured first");
    }

    /* Add tst_subnet address to tst1_if */
    CHECK_RC(tapi_cfg_base_if_add_net_addr(pco_tst1->ta, tst1_if->if_name,
                                           SA(&tstsn_addr), net1->ip4pfx,
                                           FALSE, NULL));
    /* Add tst_subnet address to tst2_if */
    CHECK_RC(tapi_cfg_base_if_add_net_addr(pco_tst2->ta, tst2_if->if_name,
                                           SA(&tstsn_addr), net2->ip4pfx,
                                           FALSE, NULL));

    CFG_WAIT_CHANGES;

    /* Create server on pco_tst1 */
    tst1_s = rpc_socket(pco_tst1, domain, sock_type, RPC_PROTO_DEF);
    rpc_bind(pco_tst1, tst1_s, SA(&tstsn_addr));
    if (sock_type == RPC_SOCK_STREAM)
        rpc_listen(pco_tst1, tst1_s, SOCKTS_BACKLOG_DEF);

    /* Create server on pco_tst2 */
    tst2_s = rpc_socket(pco_tst2, domain, sock_type, RPC_PROTO_DEF);
    rpc_bind(pco_tst2, tst2_s, SA(&tstsn_addr));
    if (sock_type == RPC_SOCK_STREAM)
        rpc_listen(pco_tst2, tst2_s, SOCKTS_BACKLOG_DEF);

    iut1_s = rpc_socket(pco_iut1, domain, sock_type, RPC_PROTO_DEF);
    if (sock_type == RPC_SOCK_STREAM)
        rpc_connect(pco_iut1, iut1_s, SA(&tstsn_addr));
    else
        rc = rpc_sendto(pco_iut1, iut1_s, tx_buf, TST_BUF_LEN, 0,
                        CONST_SA(&tstsn_addr));

    SLEEP(1);

    /* Turn on FIONBIO request on 'tst1_s' and 'tst2_s' sockets */
    req_val = TRUE;
    rpc_ioctl(pco_tst1, tst1_s, RPC_FIONBIO, &req_val);

    req_val = TRUE;
    rpc_ioctl(pco_tst2, tst2_s, RPC_FIONBIO, &req_val);

    /*
     * Check what of links has been used for interaction
     */

    /* Check for link to pco_tst1 */
    RPC_AWAIT_IUT_ERROR(pco_tst1);
    if (sock_type == RPC_SOCK_STREAM)
    {
        rc = acc1_s = rpc_accept(pco_tst1, tst1_s, NULL, NULL);
    }
    else
    {
        rc = rpc_recvfrom(pco_tst1, tst1_s, rx_buf, TST_BUF_LEN, 0,
                          SA(&peer1_addr), &peer1_addrlen);
    }

    if (rc == -1)
    {
        CHECK_RPC_ERRNO(pco_tst1, RPC_EAGAIN,
                        "%s() called on the tst1_s socket "
                        "returns %d, but",
                         (sock_type == RPC_SOCK_STREAM) ?
                        "accept" : "recv", rc);
        link1_active = FALSE;
    }
    else
    {
        link1_active = TRUE;
        if (sock_type == RPC_SOCK_DGRAM)
        {
            /* Because autobind is used */
            te_sockaddr_set_port(SA(&iut1sn_addr),
                                 te_sockaddr_get_port(SA(&peer1_addr)));
            if (te_sockaddrcmp((struct sockaddr *)&peer1_addr, peer1_addrlen,
                               (struct sockaddr *)&iut1sn_addr, peer1_addrlen)
                != 0)
            {
                TEST_FAIL("recvfrom(pco_tst1) retrieved dgram from %s, "
                          "but expected from %s",
                          te_sockaddr2str((struct sockaddr *)&peer1_addr),
                          te_sockaddr2str((struct sockaddr *)&iut1sn_addr));
            }
        }
    }

    /* Check for link to pco_tst2 */
    RPC_AWAIT_IUT_ERROR(pco_tst2);
    if (sock_type == RPC_SOCK_STREAM)
    {
        rc = acc2_s = rpc_accept(pco_tst2, tst2_s, NULL, NULL);
    }
    else
    {
        rc = rpc_recvfrom(pco_tst2, tst2_s, rx_buf, TST_BUF_LEN, 0,
                          SA(&peer2_addr), &peer2_addrlen);
    }

    if (rc == -1)
    {
        CHECK_RPC_ERRNO(pco_tst2, RPC_EAGAIN,
                        "%s() called on the tst1_s socket "
                        "returns %d, but",
                         (sock_type == RPC_SOCK_STREAM) ?
                        "accept" : "recv", rc);
        link2_active = FALSE;
    }
    else
    {
        link2_active = TRUE;
        if (sock_type == RPC_SOCK_DGRAM)
        {
            /* Because autobind is used */
            te_sockaddr_set_port(SA(&iut2sn_addr),
                                 te_sockaddr_get_port(SA(&peer2_addr)));
            if (te_sockaddrcmp((struct sockaddr *)&peer2_addr, peer2_addrlen,
                               (struct sockaddr *)&iut2sn_addr, peer2_addrlen)
                != 0)
            {
                TEST_FAIL("recvfrom(pco_tst2) retrieved dgram from %s, "
                          "but expected from %s",
                          te_sockaddr2str((struct sockaddr *)&peer2_addr),
                          te_sockaddr2str((struct sockaddr *)&iut2sn_addr));
            }
        }
    }

    if (link1_active == link2_active)
    {
        TEST_VERDICT("Both links are %sactive", 
                     link1_active ? "" : "not ");
    }
    else
    {
        RING_VERDICT("The %s configured link is active",
                     iut1_if_first == link1_active ? "first" : "second");
    }

    /* Additional checking to exclude handover to underlying O/S */
    if (sock_type == RPC_SOCK_DGRAM)
    {
        rc = rpc_sendto(pco_iut1, iut1_s, tx_buf, TST_BUF_LEN, 0,
                        CONST_SA(&tstsn_addr));

        /* Check for link to pco_tst1 */
        RPC_AWAIT_IUT_ERROR(pco_tst1);
        rc = rpc_recvfrom(pco_tst1, tst1_s, rx_buf, TST_BUF_LEN, 0,
                          SA(&peer1_addr), &peer1_addrlen);
        if (rc == -1)
        {
            CHECK_RPC_ERRNO(pco_tst1, RPC_EAGAIN,
                            "recv(tst1_s) returns %d, but", rc);
            if (link1_active)
                TEST_VERDICT("The second portion of data is not "
                             "delivered via expected link");
        }
        else
        {
            if (te_sockaddrcmp((struct sockaddr *)&peer1_addr, peer1_addrlen,
                               (struct sockaddr *)&iut1sn_addr, peer1_addrlen)
                != 0)
            {
                TEST_FAIL("recvfrom(pco_tst1) retrieved dgram from %s, "
                          "but expected from %s",
                          te_sockaddr2str((struct sockaddr *)&peer1_addr),
                          te_sockaddr2str((struct sockaddr *)&iut1sn_addr));
            }
            if (!link1_active)
            {
                TEST_VERDICT("The second portion of data is unexpectedly "
                             "delivered via not expected link");
            }
        }

        /* Check for link to pco_tst2 */
        RPC_AWAIT_IUT_ERROR(pco_tst2);
        rc = rpc_recvfrom(pco_tst2, tst2_s, rx_buf, TST_BUF_LEN, 0,
                          SA(&peer2_addr), &peer2_addrlen);
        if (rc == -1)
        {
            CHECK_RPC_ERRNO(pco_tst2, RPC_EAGAIN,
                            "recv(tst2_s) returns %d, but", rc);
            if (link2_active)
                TEST_VERDICT("The second portion of data is not "
                             "delivered via expected link");
        }
        else
        {
            if (te_sockaddrcmp((struct sockaddr *)&peer2_addr, peer2_addrlen,
                               (struct sockaddr *)&iut2sn_addr, peer2_addrlen)
                != 0)
            {
                TEST_FAIL("recvfrom(pco_tst2) retrieved dgram from %s, "
                          "but expected from %s",
                          te_sockaddr2str((struct sockaddr *)&peer2_addr),
                          te_sockaddr2str((struct sockaddr *)&iut2sn_addr));
            }
            if (!link2_active)
            {
                TEST_VERDICT("The second portion of data is unexpectedly "
                             "delivered via not expected link");
            }
        }
    }

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut1, iut1_s);
    CLEANUP_RPC_CLOSE(pco_iut2, iut2_s);
    CLEANUP_RPC_CLOSE(pco_tst1, tst1_s);
    CLEANUP_RPC_CLOSE(pco_tst2, tst2_s);
    CLEANUP_RPC_CLOSE(pco_tst1, acc1_s);
    CLEANUP_RPC_CLOSE(pco_tst2, acc2_s);

    free(tx_buf);
    free(rx_buf);
    TEST_END;
}
