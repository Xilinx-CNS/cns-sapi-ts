/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Socket options
 */

/** @page sockopts-bindtodevice_send Bind socket to an interface and try to send data to destination rootable via another interface
 *
 * @objective Check that data will not arrive at the destination host if
 *            the route to this host is over an interface different from
 *            the interface to which a sending socket is bound.
 *
 * @type conformance
 *
 * @reference MAN 7 socket
 *
 * @note To perform this test @p pco_iut should have at least two
 *       network interfaces.
 *
 * @param pco_iut       PCO on IUT
 * @param pco_tst1      PCO on TST
 * @param iut1_if       Name of a network interface on the host with
 *                      @p pco_iut that connected to the same subnetwork
 *                      as @p pco_tst1
 * @param tst1_if       Name of a network interface on the host with
 *                      @p pco_tst1 that connected to the same subnetwork
 *                      as @p pco_iut (interface @p iut1_if)
 * @param gw_addr       Address from IP subnet assigned to @p tst1_if
 *                      and routable via subnet route
 * @param pco_tst2      PCO on TST
 * @param iut2_if       Name of a network interface on the host with
 *                      @p pco_iut that connected to the same subnetwork
 *                      as @p pco_tst2
 * @param iut2_addr     Network address on @p iut2_if
 * @param tst2_if       Name of a network interface on the host with
 *                      @p pco_tst2 that connected to the same subnetwork
 *                      as @p pco_iut (interface @p iut2_if)
 * @param dst_addr      Destination address (may be alien or from the
 *                      IP subnet assigned to @p iut2_if - @p tst2_if)
 * @param direct_route  Direct route or route via gateway should be used
 *
 * @htmlonly

  <pre>

  --------------------  +------ NET 1 ----- { pco_tst1 }
  |      iut1_if+|---|--+
  | IUT              |
  |      iut2_if+|---|--+
  --------------------  +------ NET 2 ----- { pco_tst2 }

  </pre>

  @endhtmlonly
 *
 * @par Test sequence:
 *
 * @todo Investigate source address selection depending on
 *       explicit/implicit @b bind() to @p iut1_if/iut2_if address and
 *       @b bind() / @c SO_BINDTODEVICE order.
 *
 * @author Yurij Plotnikov <Yurij.Plotnikov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "sockopts/bindtodevice_send"

#include "sockapi-test.h"
#include "tapi_cfg.h"
#include "tapi_cfg_base.h"
#include "iomux.h"

#define DATA_BULK                      1024


static uint8_t buf[DATA_BULK];

int
main(int argc, char *argv[])
{
    tapi_env_net              *net1 = NULL;
    tapi_env_net              *net2 = NULL;
    rcf_rpc_server            *pco_iut = NULL;
    rcf_rpc_server            *pco_tst1 = NULL;
    rcf_rpc_server            *pco_tst2 = NULL;

    const struct if_nameindex *iut1_if;
    const struct if_nameindex *iut2_if;
    const struct if_nameindex *tst1_if;
    const struct if_nameindex *tst2_if;

    const struct sockaddr     *iut1_addr;
    const struct sockaddr     *iut2_addr;
    const struct sockaddr     *gw_addr;
    const struct sockaddr     *dst_addr;
    int                        af = AF_INET;

    te_bool                    direct_route;

    rpc_socket_domain          domain;

    cfg_handle                 addr1_handle = CFG_HANDLE_INVALID;
    cfg_handle                 addr2_handle = CFG_HANDLE_INVALID;
    cfg_handle                 rt_handle = CFG_HANDLE_INVALID;

    int                        iut_s = -1;
    int                        tst1_s = -1;
    int                        tst2_s = -1;

    te_bool                    readable;
    int                        ret;


    /* Test preambule */
    TEST_START;
    TEST_GET_NET(net1);
    TEST_GET_NET(net2);
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst1);
    TEST_GET_PCO(pco_tst2);
    TEST_GET_ADDR(pco_iut, iut1_addr);
    TEST_GET_ADDR(pco_iut, iut2_addr);
    TEST_GET_ADDR_NO_PORT(gw_addr);
    TEST_GET_ADDR(pco_tst1, dst_addr);
    TEST_GET_IF(iut1_if);
    TEST_GET_IF(iut2_if);
    TEST_GET_IF(tst1_if);
    TEST_GET_IF(tst2_if);
    TEST_GET_BOOL_PARAM(direct_route);

    domain = rpc_socket_domain_by_addr(iut1_addr);
    af = iut1_addr->sa_family;

    TEST_STEP("Add @p dst_addr address on @p tst1_if and @p tst2_if.");
    CHECK_RC(tapi_cfg_base_if_add_net_addr(pco_tst1->ta,
                                           tst1_if->if_name, dst_addr,
                                           (af == AF_INET ?
                                               net1->ip4pfx : net1->ip6pfx),
                                           FALSE,
                                           &addr1_handle));
    CHECK_RC(tapi_cfg_base_if_add_net_addr(pco_tst2->ta,
                                           tst2_if->if_name, dst_addr,
                                           (af == AF_INET ?
                                               net2->ip4pfx : net2->ip6pfx),
                                           FALSE,
                                           &addr2_handle));

    TEST_STEP("Add a route to @b dst_addr on IUT. If @p direct_route "
              "is @c TRUE, add direct route over @p iut1_if, otherwise "
              "add route via gateway @p gw_addr (which can be reached "
              "over @p iut1_if).");
    if (tapi_cfg_add_route(pco_iut->ta,
            af,
            te_sockaddr_get_netaddr(dst_addr),
            te_netaddr_get_bitsize(af),
            direct_route ? NULL : te_sockaddr_get_netaddr(gw_addr),
            direct_route ? iut1_if->if_name : NULL, NULL,
            0, 0, 0, 0, 0, 0, &rt_handle) != 0)
    {
        TEST_FAIL("Cannot add route to the dst");
    }
    CFG_WAIT_CHANGES;

    TEST_STEP("Create @c SOCK_DGRAM sockets @b tst1_s and @b tst2_s "
              "on @p pco_tst1 and @p pco_tst2 and bind them "
              "to @p dst_addr.");
    tst1_s = rpc_socket(pco_tst1, domain, RPC_SOCK_DGRAM, RPC_PROTO_DEF);
    rpc_bind(pco_tst1, tst1_s, dst_addr);
    tst2_s = rpc_socket(pco_tst2, domain, RPC_SOCK_DGRAM, RPC_PROTO_DEF);
    rpc_bind(pco_tst2, tst2_s, dst_addr);

    TEST_STEP("Create @c SOCK_SGRAM socket @b iut_s on IUT. Bind it to "
              "@p iut2_addr and connect to @p dst_addr.");
    iut_s = rpc_socket(pco_iut, domain, RPC_SOCK_DGRAM, RPC_PROTO_DEF);
    rpc_bind(pco_iut, iut_s, iut2_addr);
    rpc_connect(pco_iut, iut_s, dst_addr);

    TEST_STEP("Bind @b iut_s to @p iut2_if interface with "
              "@c SO_BINDTODEVICE socket option.");
    RPC_AWAIT_IUT_ERROR(pco_iut);
    ret = rpc_setsockopt_raw(pco_iut, iut_s, RPC_SO_BINDTODEVICE,
                             iut2_if->if_name,
                             (strlen(iut2_if->if_name) + 1));
    if (ret != 0)
    {
        TEST_VERDICT("setsockopt(SOL_SOCKET, SO_BINDTODEVICE) failed "
                     "with errno %s", errno_rpc2str(RPC_ERRNO(pco_iut)));
    }

    TEST_STEP("Send a datagram from IUT socket.");
    te_fill_buf(buf, DATA_BULK);
    RPC_AWAIT_ERROR(pco_iut);
    rc = rpc_send(pco_iut, iut_s, buf, DATA_BULK, 0);
    if (rc < 0)
    {
        TEST_VERDICT("send() failed unexpectedly with errno %r",
                     RPC_ERRNO(pco_iut));
    }

    MSLEEP(100);

    TEST_STEP("Check what happens. No datagram should be sent: "
              "- to @p pco_tst1 - because we bound our socket "
              "  to @p iut2_if; "
              "- to @p pco_tst2 - because route to @p dst_addr "
              "  is via @p iut1_if.");

    RPC_GET_READABILITY(readable, pco_tst1, tst1_s, 1);
    if (readable)
    {
        /* May be it is OK? If SO_BINDTODEVICE is for Rx only. */
        TEST_VERDICT("Datagram is sent via route in despite of "
                     "SO_BINDTODEVICE option value");
    }

    RPC_GET_READABILITY(readable, pco_tst2, tst2_s, 1);
    if (readable)
    {
        TEST_VERDICT("Datagram is sent directly to the interface "
                     "specified in SO_BINDTODEVICE option value "
                     "in despite of routing table");
    }

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst1, tst1_s);
    CLEANUP_RPC_CLOSE(pco_tst2, tst2_s);

    CLEANUP_CHECK_RC(cfg_del_instance(rt_handle, FALSE));
    CLEANUP_CHECK_RC(cfg_del_instance(addr2_handle, FALSE));
    CLEANUP_CHECK_RC(cfg_del_instance(addr1_handle, FALSE));

    if (af == AF_INET6)
    {
        CLEANUP_CHECK_RC(sockts_ifs_down_up(pco_iut, iut1_if,
                                            pco_iut, iut2_if, NULL));
    }

    TEST_END;
}
