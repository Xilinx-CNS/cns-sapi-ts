/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2025 Advanced Micro Devices, Inc. */
/*
 * Socket API Test Suite
 *
 * TCP protocol special cases
 */

/** @page tcp-rst_pkt_without_ack Test that RST in response to packet without ACK-bit set contains correct ACK
 *
 * @objective Test that RST in response to packet without ACK-bit set contains
 *            correct ACK
 *
 * @param env                 Testing environment:
 *                                - @ref arg_types_env_peer2peer
 *                                - @ref arg_types_env_peer2peer_ipv6
 * @param tcpdump_mode        How tcpdump should be used:
 *                            - @c none - no use
 *                            - @c linux - use usual tcpdump
 *                            - @c onload - use onload_tcpdump
 *
 * @par Test sequence:
 *
 * @author Nikolai Kosovskii <Nikolai.Kosovskii@arknetworks.am>
 */

#define TE_TEST_NAME  "tcp/rst_pkt_without_ack"
#define EF_TCP_SHARED_LOCAL_PORTS_TO_SET 10
#define TIME_TO_RUN_TCPDUMP_SEC 2
#include "sockapi-test.h"
#include "tapi_cfg_process.h"
#define TCPDUMP_CMD_LEN 128

typedef enum {
    TCPDUMP_NONE,
    TCPDUMP_LINUX,
    TCPDUMP_ONLOAD,
} tcpdump_mode_t;

#define TCPDUMP_MODE_LIST \
    { "none",   TCPDUMP_NONE },        \
    { "linux",  TCPDUMP_LINUX },       \
    { "onload", TCPDUMP_ONLOAD }

int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst = NULL;

    const struct sockaddr *iut_addr;
    const struct sockaddr *tst_addr;
    const struct if_nameindex *iut_if;

    int iut_s = -1;
    int tst_s = -1;
    tcpdump_mode_t tcpdump_mode;

    struct sockaddr addr;
    socklen_t addr_len = sizeof(addr);
    bool shared_local_ports_existed;
    int shared_local_ports_old_value;
    char tcpdump_cmd[TCPDUMP_CMD_LEN];
    char tcpdump_opt[TCPDUMP_CMD_LEN];

    TEST_START;

    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_IF(iut_if);
    TEST_GET_ENUM_PARAM(tcpdump_mode, TCPDUMP_MODE_LIST);

    TEST_STEP("If @p tcpdump_mode is not @c none, start tcpdump process.");
    if (tcpdump_mode != TCPDUMP_NONE)
    {
        snprintf(tcpdump_cmd, sizeof(tcpdump_cmd), "%stcpdump",
                 tcpdump_mode == TCPDUMP_ONLOAD ? "te_onload_" :"");
        CHECK_RC(tapi_cfg_ps_add(pco_iut->ta, "process_tcpdump",
                                 tcpdump_cmd, FALSE));

        snprintf(tcpdump_opt, sizeof(tcpdump_opt), "-i%s",
                 iut_if->if_name);
        CHECK_RC(tapi_cfg_ps_add_arg(pco_iut->ta, "process_tcpdump", 1,
                                     tcpdump_opt));

        rc = tapi_cfg_ps_start(pco_iut->ta, "process_tcpdump");
        TAPI_WAIT_NETWORK;
    }

    TEST_STEP("Set EF_TCP_SHARED_LOCAL_PORTS to @c 10.");
    CHECK_RC(tapi_sh_env_save_set_int(pco_iut, "EF_TCP_SHARED_LOCAL_PORTS",
                                      EF_TCP_SHARED_LOCAL_PORTS_TO_SET, TRUE,
                                      &shared_local_ports_existed,
                                      &shared_local_ports_old_value));

    TEST_STEP("Create a socket @p iut_s on @p pco_iut.");
    iut_s = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr),
                       RPC_SOCK_STREAM, RPC_PROTO_DEF);

    TEST_STEP("Try to connect the socket @p iut_s to @p tst_addr and fail.");
    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_connect(pco_iut, iut_s, tst_addr);
    if (rc == 0)
    {
        TEST_VERDICT("connect() without listen unexpectedly successed");
    }
    else
    {
        CHECK_RPC_ERRNO(pco_iut, TE_RC(TE_RPC, TE_ECONNREFUSED),
                        "connect() without listen");
    }


    TEST_STEP("Get the port of the socket @p iut_s.");
    rpc_getsockname(pco_iut, iut_s, &addr, &addr_len);

    TEST_STEP("Close the socket @p iut_s.");
    RPC_CLOSE(pco_iut, iut_s);

    TEST_STEP("Create a socket @p tst_s on @p pco_tst.");
    tst_s = rpc_socket(pco_tst, rpc_socket_domain_by_addr(tst_addr),
                       RPC_SOCK_STREAM, RPC_PROTO_DEF);

    TEST_STEP("Try to connect the socket @p tst_s to  @p iut_s and check "
              "an errno to be ECONNREFUSED. It means the reaction on RST "
              "is right and ACK is correct. Otherwise it would be TIMEOUT.");
    te_sockaddr_set_netaddr(&addr, te_sockaddr_get_netaddr(iut_addr));

    RPC_AWAIT_IUT_ERROR(pco_tst);
    rc = rpc_connect(pco_tst, tst_s, &addr);
    if (rc != -1)
    {
        TEST_VERDICT("connect() to closed socket unexpectedly "
                     "does not fail");
    }
    else
    {
        CHECK_RPC_ERRNO(pco_tst, TE_RC(TE_RPC, TE_ECONNREFUSED),
                        "connect() to closed socket");
    }

    TEST_STEP("If @p tcpdump_mode is not @c none, wait some time. "
              "Then stop and delete tcpdump process.");
    if (tcpdump_mode != TCPDUMP_NONE)
    {
        SLEEP(TIME_TO_RUN_TCPDUMP_SEC);

        CHECK_RC(tapi_cfg_ps_stop(pco_iut->ta, "process_tcpdump"));

        CHECK_RC(tapi_cfg_ps_del(pco_iut->ta, "process_tcpdump"));
    }
    TEST_SUCCESS;

cleanup:

    if (shared_local_ports_existed)
    {
        CLEANUP_CHECK_RC(tapi_sh_env_set_int(pco_iut,
                                             "EF_TCP_SHARED_LOCAL_PORTS",
                                             shared_local_ports_old_value,
                                             TRUE, FALSE));
    }
    else
    {
        CLEANUP_CHECK_RC(tapi_sh_env_unset(pco_iut, "EF_TCP_SHARED_LOCAL_PORTS",
                                           TRUE, FALSE));
    }
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    TEST_END;
}
