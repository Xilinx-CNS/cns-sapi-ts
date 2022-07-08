/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Socket options
 */

/**
 * @page sockopts-tcp_info_snd_adv_mss Check tcpi_snd_mss and tcpi_advmss values reported by TCP_INFO option
 *
 * @objective Check that @c TCP_INFO structure fields @b tcpi_snd_mss and @b
 *            tcpi_advmss are changed correctly during connection
 *
 * @param env     Testing environment:
 *                - @ref arg_types_env_peer2peer
 *                - @ref arg_types_env_peer2peer_ipv6
 * @param active  Active/passive connection opening:
 *                - FALSE (passive opening)
 *                - TRUE (active opening)
 *
 * @par Scenario:
 *
 * @author Vasilij Ivanov <Vasilij.Ivanov@oktetlabs.ru>
 */

#define TE_TEST_NAME "sockopts/tcp_info_snd_adv_mss"

#include "sockapi-test.h"
#include "tapi_tcp.h"

#define MAX_MSS 1440
#define MIN_MSS 128

int
main(int argc, char *argv[])
{
    rcf_rpc_server            *pco_iut = NULL;
    rcf_rpc_server            *pco_tst = NULL;

    const struct sockaddr     *iut_addr = NULL;
    const struct sockaddr     *tst_addr = NULL;

    int                       s_listener = -1;
    int                       s_conn = -1;
    int                       s_acc = -1;
    rcf_rpc_server           *pco_srv;
    rcf_rpc_server           *pco_clnt;
    const struct sockaddr    *srv_addr;
    const struct sockaddr    *clnt_addr;


    struct rpc_tcp_info       info;
    uint8_t                  *buf = NULL;
    uint32_t                  len;
    uint32_t                  mss;
    uint32_t                  expected_mss;
    int                       ret;
    te_bool                   active;
    /** TCP timestamps size */
    int                       offset = 12;

    /* Preambule */
    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);

    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_BOOL_PARAM(active);

    if (active)
    {
        pco_srv = pco_tst;
        pco_clnt = pco_iut;
        srv_addr = tst_addr;
        clnt_addr = iut_addr;
    }
    else
    {
        pco_srv = pco_iut;
        pco_clnt = pco_tst;
        srv_addr = iut_addr;
        clnt_addr = tst_addr;
    }

    /** Check if TCP timestamps are disabled during test */
    if (getenv("DISABLE_TIMESTAMPS") != NULL)
        offset = 0;

    TEST_STEP("Get random @b mss value");
    mss = rand_range(MIN_MSS, MAX_MSS);
    RING("MSS value: %d", mss);
    expected_mss = mss - offset;

    TEST_STEP("Call @c rpc_setsockopt(RPC_TCP_MAXSEG) on IUT socket");
    s_conn = rpc_socket(pco_clnt, rpc_socket_domain_by_addr(clnt_addr),
                        RPC_SOCK_STREAM, RPC_PROTO_DEF);

    s_listener = rpc_socket(pco_srv, rpc_socket_domain_by_addr(srv_addr),
                            RPC_SOCK_STREAM, RPC_PROTO_DEF);
    RPC_AWAIT_ERROR(pco_iut);
    ret = rpc_setsockopt(pco_iut, active ? s_conn : s_listener,
                         RPC_TCP_MAXSEG, &mss);
    if (ret != 0)
    {
        TEST_VERDICT("setsockopt(TCP_MAXSEG) failed with errno %r",
                     RPC_ERRNO(pco_iut));
    }

    TEST_STEP("Create connection between a pair of sockets on IUT and Tester");
    rpc_bind(pco_srv, s_listener, srv_addr);
    rpc_listen(pco_srv, s_listener, SOCKTS_BACKLOG_DEF);
    rpc_connect(pco_clnt, s_conn, srv_addr);
    CHECK_SOCKET_STATE(pco_clnt, s_conn, pco_srv, s_listener,
                       STATE_CONNECTED);
    s_acc = rpc_accept(pco_srv, s_listener, NULL, NULL);

    TEST_STEP("Send data from Client side");
    len = rand_range(MIN_MSS, mss);
    buf = te_make_buf_by_len(len);
    rpc_send(pco_clnt, s_conn, buf, len, 0);

    TEST_STEP("Receive data on Tester side");
    rpc_recv(pco_srv, s_acc, buf, len, 0);

    TEST_STEP("Check that @b tcpi_advmss on IUT socket equals @b mss");
    memset(&info, 0, sizeof(info));
    rpc_getsockopt(pco_iut, active ? s_conn : s_acc, RPC_TCP_INFO, &info);
    if (info.tcpi_advmss != expected_mss)
    {
        TEST_ARTIFACT("tcpi_advmss on IUT socket is: %d, when expected: %d",
                      info.tcpi_advmss, expected_mss);
        TEST_VERDICT("TCP_INFO option return unexpected "
                     "tcpi_advmss value on IUT socket");
    }

    TEST_STEP("Check that @b tcpi_snd_mss on Tester socket equals @b mss");
    rpc_getsockopt(pco_tst, active ? s_acc : s_conn, RPC_TCP_INFO, &info);
    if (info.tcpi_snd_mss != expected_mss)
    {
        TEST_ARTIFACT("tcpi_snd_mss on TST socket is: %d, when expected: %d",
                      info.tcpi_snd_mss, expected_mss);
        TEST_VERDICT("TCP_INFO option return unexpected "
                     "tcpi_snd_mss value on TST socket");
    }

    TEST_SUCCESS;

cleanup:
    free(buf);
    CLEANUP_RPC_CLOSE(pco_srv, s_acc);
    CLEANUP_RPC_CLOSE(pco_clnt, s_conn);
    CLEANUP_RPC_CLOSE(pco_srv, s_listener);

    TEST_END;
}

