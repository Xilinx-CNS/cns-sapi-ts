/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Socket options
 */

/** @page sockopts-auto_flowlabels Usage of auto_flowlabels system parameter and IPV6_AUTOFLOWLABEL socket option
 *
 * @objective Check that IPv6 Flow Label is set or not according to
 *            @c auto_flowlabels system parameter and @c IPV6_AUTOFLOWLABEL
 *            option.
 *
 * @type conformance
 *
 * @param env           Environment:
 *                      - @ref arg_types_env_peer2peer_ipv6
 * @param sock_type     IUT socket type:
 *                      - @c udp (connected UDP socket)
 *                      - @c udp_notconn (not connected UDP socket)
 *                      - @c tcp_active (actively established TCP
 *                        connection)
 *                      - @c tcp_passive (passively established TCP
 *                        connection)
 *                      - @c tcp_passive_close (passively established
 *                        TCP connection, listener is closed after
 *                        @b accept())
 * @param auto_fl       Value to set for @c auto_flowlabels:
 *                      - @c 0
 *                      - @c 1
 *                      - @c 2
 *                      - @c 3
 *
 * @par Test sequence:
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME  "sockopts/auto_flowlabels"

#include "sockapi-test.h"
#include "tapi_tcp.h"
#include "tapi_udp.h"
#include "tapi_ip_common.h"
#include "sockopts_common.h"

static int iut_s = -1;
static int iut_listener = -1;
static int tst_s = -1;

csap_handle_t csap = CSAP_INVALID_HANDLE;

/**
 * Set IPV6_AUTOFLOWLABEL option if required, send some data
 * from IUT, capture packets by CSAP on Tester, check value of
 * Flow Label header field.
 *
 * @param pco_iut             RPC server on IUT.
 * @param pco_tst             RPC server on Tester.
 * @param iut_addr            Network address on IUT.
 * @param tst_addr            Network address on Tester.
 * @param tst_if              Network interface on Tester.
 * @param sock_type           IUT socket type.
 * @param auto_fl             Value to which auto_flowlabels system
 *                            parameter was set.
 * @param opt_val             Value to which to set IPV6_AUTOFLOWLABEL
 *                            (if negative, do not set it).
 * @param failed              Will be set to TRUE if some problem
 *                            encountered.
 * @param stage               String describing the stage of testing
 *                            (will be printed in verdicts).
 */
static void
check_flowlabel(rcf_rpc_server *pco_iut, rcf_rpc_server *pco_tst,
                const struct sockaddr *iut_addr,
                const struct sockaddr *tst_addr,
                const struct if_nameindex *tst_if,
                sockts_socket_type sock_type,
                int auto_fl, int opt_val, te_bool *failed,
                const char *stage)
{
    int got_opt_val;
    int rc;
    int exp_fl = 0;

    struct sockaddr_storage new_iut_addr;
    struct sockaddr_storage new_tst_addr;
    rpc_socket_type         rpc_sock_type;
    te_bool                 test_stop = FALSE;

    rpc_sock_type = sock_type_sockts2rpc(sock_type);

    CHECK_RC(tapi_sockaddr_clone(pco_iut, iut_addr, &new_iut_addr));
    CHECK_RC(tapi_sockaddr_clone(pco_tst, tst_addr, &new_tst_addr));

    CHECK_RC(tapi_tcp_udp_ip_eth_csap_create(
                    pco_tst->ta, 0, tst_if->if_name,
                    TAD_ETH_RECV_DEF | TAD_ETH_RECV_NO_PROMISC,
                    NULL, NULL,
                    iut_addr->sa_family,
                    (rpc_sock_type == RPC_SOCK_STREAM ?
                            IPPROTO_TCP : IPPROTO_UDP),
                    TAD_SA2ARGS(SA(&new_tst_addr), SA(&new_iut_addr)),
                    &csap));
    CHECK_RC(tapi_tad_trrecv_start(pco_tst->ta, 0, csap, NULL,
                                   TAD_TIMEOUT_INF, 0, RCF_TRRECV_PACKETS));

    iut_s = rpc_socket(pco_iut, RPC_PF_INET6,
                       rpc_sock_type, RPC_PROTO_DEF);

    if (opt_val < 0)
    {
        RPC_AWAIT_ERROR(pco_iut);
        rc = rpc_getsockopt(pco_iut, iut_s, RPC_IPV6_AUTOFLOWLABEL,
                            &got_opt_val);
        if (rc < 0)
        {
            ERROR_VERDICT("%s: getsockopt(IPV6_AUTOFLOWLABEL) failed "
                          "with errno %r", stage, RPC_ERRNO(pco_iut));
            *failed = TRUE;
            test_stop = TRUE;
            goto cleanup;
        }
        if (auto_fl == 1 || auto_fl == 3)
        {
            if (got_opt_val == 0)
            {
                ERROR_VERDICT("%s: IPV6_AUTOFLOWLABEL is 0 instead of 1 "
                              "just after creating a socket", stage);
                *failed = TRUE;
            }
        }
        else
        {
            if (got_opt_val == 1)
            {
                ERROR_VERDICT("%s: IPV6_AUTOFLOWLABEL is 1 instead of 0 "
                              "just after creating a socket", stage);
                *failed = TRUE;
            }
        }
        if (got_opt_val != 0 && got_opt_val != 1)
        {
            ERROR_VERDICT("%s: IPV6_AUTOFLOWLABEL is neither 0 nor 1 "
                          "just after creating a socket", stage);
            *failed = TRUE;
        }
    }
    else
    {
        RPC_AWAIT_ERROR(pco_iut);
        rc = rpc_setsockopt_int(pco_iut, iut_s, RPC_IPV6_AUTOFLOWLABEL,
                                opt_val);
        if (rc < 0)
        {
            ERROR_VERDICT("%s: failed to set IPV6_AUTOFLOWLABEL to %d, "
                          "errno %r", stage, opt_val, RPC_ERRNO(pco_iut));
            *failed = TRUE;
            test_stop = TRUE;
            goto cleanup;
        }

        RPC_AWAIT_ERROR(pco_iut);
        rc = rpc_getsockopt(pco_iut, iut_s, RPC_IPV6_AUTOFLOWLABEL,
                            &got_opt_val);
        if (rc < 0)
        {
            ERROR_VERDICT("%s: failed to get IPV6_AUTOFLOWLABEL after "
                          "setting, errno %r", stage, RPC_ERRNO(pco_iut));
            *failed = TRUE;
        }
        else if (got_opt_val != opt_val)
        {
            ERROR_VERDICT("%s: after setting IPV6_AUTOFLOWLABEL to %d "
                          "getsockopt() reports %d",
                          stage, opt_val, got_opt_val);
            *failed = TRUE;
        }
    }

    sockts_connection(pco_iut, pco_tst, SA(&new_iut_addr),
                      SA(&new_tst_addr), sock_type, FALSE,
                      TRUE, NULL, &iut_s, &tst_s, &iut_listener,
                      SOCKTS_SOCK_FUNC_SOCKET);

    switch (auto_fl)
    {
        case 0:
            exp_fl = 0;
            break;

        case 1:
            if (opt_val == 0)
                exp_fl = 0;
            else
                exp_fl = SOCKTS_SEND_CHECK_FIELD_SAME_NONZERO;

            break;

        case 2:
            if (opt_val == 1)
                exp_fl = SOCKTS_SEND_CHECK_FIELD_SAME_NONZERO;
            else
                exp_fl = 0;

            break;

        case 3:
            exp_fl = SOCKTS_SEND_CHECK_FIELD_SAME_NONZERO;
            break;
    }

    sockts_send_check_field(pco_iut, iut_s, pco_tst, tst_s,
                            sock_type, SA(&new_tst_addr),
                            "Flow Label",
                            "pdus.1.#ip6.flow-label.plain",
                            "Flow Label", exp_fl,
                            "", -1,
                            csap, failed, stage);

cleanup:

    RPC_CLOSE(pco_iut, iut_s);
    if (iut_listener >= 0)
        RPC_CLOSE(pco_iut, iut_listener);
    RPC_CLOSE(pco_tst, tst_s);

    CHECK_RC(tapi_tad_csap_destroy(pco_tst->ta, 0, csap));
    csap = CSAP_INVALID_HANDLE;

    if (test_stop)
        TEST_STOP;
}

int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst = NULL;

    const struct sockaddr     *iut_addr = NULL;
    const struct sockaddr     *tst_addr = NULL;
    const struct if_nameindex *tst_if = NULL;

    sockts_socket_type    sock_type;
    int                   auto_fl;
    int                   old_val = -1;

    te_bool               test_failed = FALSE;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_IF(tst_if);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    SOCKTS_GET_SOCK_TYPE(sock_type);
    TEST_GET_INT_PARAM(auto_fl);

    TEST_STEP("Set /proc/sys/net/ipv6/auto_flowlabels to @p auto_fl.");
    rc = tapi_cfg_sys_set_int(
                          pco_iut->ta, auto_fl, &old_val,
                          "net/ipv6/auto_flowlabels");
    if (rc != 0)
    {
        TEST_VERDICT("Setting net/ipv6/auto_flowlabels failed with "
                     "errno %r", rc);
    }
    CHECK_RC(rcf_rpc_server_restart(pco_iut));

    TEST_STEP("Check how Flow Label is set by default:");
    TEST_SUBSTEP("Create a socket on IUT and its peer on Tester, establish "
                 "connection according to @p sock_type.");
    TEST_SUBSTEP("Get @c IPV6_AUTOFLOWLABEL socket option value on the IUT "
                 "socket, check that it is @c 1 if @p auto_fl is @c 1 or "
                 "@c 3, and @c 0 otherwise.");
    TEST_SUBSTEP("Send some data over the established connection, receive "
                 "it on Tester. Capture IUT packets with CSAP.");
    TEST_SUBSTEP("If @p auto_fl is @c 0 or @c 2, check that in all the "
                 "captured packets Flow Label field is set to @c 0.");
    TEST_SUBSTEP("If @p auto_fl is @c 1 or @c 3, check that in all the "
                 "captured packets Flow Label field is set to the same "
                 "non-zero value.");
    TEST_SUBSTEP("Close the sockets.");
    check_flowlabel(pco_iut, pco_tst, iut_addr, tst_addr, tst_if, sock_type,
                    auto_fl, -1, &test_failed,
                    "Not setting IPV6_AUTOFLOWLABEL");

    TEST_STEP("Check how Flow Label is set when @c IPV6_AUTOFLOWLABEL "
              "is set to @c 0:");
    TEST_SUBSTEP("Create a socket on IUT, set @c IPV6_AUTOFLOWLABEL to "
                 "@c 0 on it. Create a peer on Tester, establish "
                 "connection according to @p sock_type.");
    TEST_SUBSTEP("Send some data over the established connection, receive "
                 "it on Tester. Capture IUT packets with CSAP.");
    TEST_SUBSTEP("If @p auto_fl is not @c 3, check that in all the "
                 "captured packets Flow Label field is set to @c 0.");
    TEST_SUBSTEP("If @p auto_fl is @c 3, check that in all the captured "
                 "packets Flow Label field is set to the same non-zero "
                 "value.");
    TEST_SUBSTEP("Close the sockets.");
    check_flowlabel(pco_iut, pco_tst, iut_addr, tst_addr, tst_if, sock_type,
                    auto_fl, 0, &test_failed,
                    "Setting IPV6_AUTOFLOWLABEL to 0");

    TEST_STEP("Check how Flow Label is set when @c IPV6_AUTOFLOWLABEL "
              "is set to @c 1:");
    TEST_SUBSTEP("Create a socket on IUT, set @c IPV6_AUTOFLOWLABEL to "
                 "@c 1 on it. Create a peer on Tester, establish "
                 "connection according to @p sock_type.");
    TEST_SUBSTEP("Send some data over the established connection, receive "
                 "it on Tester. Capture IUT packets with CSAP.");
    TEST_SUBSTEP("If @p auto_fl is @c 0, check that in all the "
                 "captured packets Flow Label field is set to @c 0.");
    TEST_SUBSTEP("If @p auto_fl is not @c 0, check that in all the "
                 "captured packets Flow Label field is set to the same "
                 "non-zero value.");
    TEST_SUBSTEP("Close the sockets.");
    check_flowlabel(pco_iut, pco_tst, iut_addr, tst_addr, tst_if, sock_type,
                    auto_fl, 1, &test_failed,
                    "Setting IPV6_AUTOFLOWLABEL to 1");

    if (test_failed)
        TEST_STOP;

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    CLEANUP_RPC_CLOSE(pco_iut, iut_listener);
    CLEANUP_CHECK_RC(tapi_tad_csap_destroy(pco_tst->ta, 0,
                                           csap));

    if (old_val >= 0)
    {
        CLEANUP_CHECK_RC(tapi_cfg_sys_set_int(
                              pco_iut->ta, old_val, NULL,
                              "net/ipv6/auto_flowlabels"));
        CLEANUP_CHECK_RC(rcf_rpc_server_restart(pco_iut));
    }

    TEST_END;
}
