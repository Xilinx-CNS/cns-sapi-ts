/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Reliability of Socket API in Normal Use
 */

/** @page usecases-fill_huge_rcvbuf Overfill huge receive buffer and read all data
 *
 * @objective Check what happens if a huge receive buffer is overfilled and
 *            we try to read all the data from it.
 *
 *
 * @param env               Testing environment:
 *                          - @ref arg_types_env_peer2peer
 *                          - @ref arg_types_env_peer2peer_lo
 *                          - @ref arg_types_env_peer2peer_ipv6
 *                          - @ref arg_types_env_peer2peer_lo_ipv6
 * @param sock_type         Socket type:
 *                          - @c tcp_active
 *                          - @c tcp_passive
 *                          - @c udp
 *                          - @c udp_notconn
 *
 * @par Test sequence:
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME  "usecases/fill_huge_rcvbuf"

#include "sockapi-test.h"
#include "onload.h"

/* These values were taken from ON-11181 */

/** Value for EF_MAX_PACKETS */
#define MAX_PACKETS 10240000
/** Value for EF_MAX_RX_PACKETS */
#define MAX_RX_PACKETS 4608000
/** Value for EF_MAX_TX_PACKETS */
#define MAX_TX_PACKETS 4608000

/**
 * Value to set for rmem_max. It cannot exceed
 * maximum possible 32bit signed integer value.
 */
#define MAX_RMEM_MAX ((int)((1L << 31) - 1L))

/**
 * Value to set for SO_RCVBUF.
 * It should be half of maximum rmem_max, otherwise multiplying by two
 * done by setsockopt() will result in overfilling and setting minimum
 * value.
 */
#define RCVBUF_SIZE (MAX_RMEM_MAX / 2)

/**
 * Maximum time sending or receiving can take, in seconds.
 */
#define TRANSMIT_TIME  300

/**
 * Time to wait for writability or readability on a socket
 * before stopping sending/receiving, in milliseconds.
 */
#define TIME2WAIT  5000

int
main(int argc, char *argv[])
{
    rcf_rpc_server         *pco_iut = NULL;
    rcf_rpc_server         *pco_tst = NULL;

    const struct sockaddr  *iut_addr = NULL;
    const struct sockaddr  *tst_addr = NULL;

    sockts_socket_type   sock_type;
    rpc_socket_type      rpc_sock_type;

    int iut_s = -1;
    int iut_listener = -1;
    int tst_s = -1;

    te_bool onload_run = tapi_onload_run();
    int     opt_val;
    char   *cfg_backup_name = NULL;

    tapi_pat_sender     sender_ctx;
    tapi_pat_receiver   receiver_ctx;
    int                 max_send_size;
    tarpc_pat_gen_arg  *pat_arg = NULL;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    SOCKTS_GET_SOCK_TYPE(sock_type);

    rpc_sock_type = sock_type_sockts2rpc(sock_type);

    if (onload_run)
    {
        char str_buf[256] = "";

        CHECK_RC(cfg_create_backup(&cfg_backup_name));

        TEST_STEP("If we run the test on Onload, set EF_MAX_PACKETS, "
                  "EF_MAX_RX_PACKETS and EF_MAX_TX_PACKETS to big values.");
        CHECK_RC(tapi_sh_env_save_set_int(pco_iut,
                                          "EF_MAX_PACKETS",
                                          MAX_PACKETS,
                                          FALSE, NULL, NULL));

        CHECK_RC(tapi_sh_env_save_set_int(pco_iut,
                                          "EF_MAX_RX_PACKETS",
                                          MAX_RX_PACKETS,
                                          FALSE, NULL, NULL));

        CHECK_RC(tapi_sh_env_save_set_int(pco_iut,
                                          "EF_MAX_TX_PACKETS",
                                          MAX_TX_PACKETS,
                                          FALSE, NULL, NULL));

        TE_SPRINTF(str_buf, "%d", MAX_PACKETS);
        CHECK_RC(
            cfg_set_instance_fmt(
              CFG_VAL(STRING, str_buf),
              "/agent:%s/module:onload/parameter:max_packets_per_stack",
              pco_iut->ta));
    }

    TEST_STEP("Set /proc/sys/net/core/rmem_max to maximum possible value.");
    CHECK_RC(tapi_cfg_sys_ns_set_int(pco_iut->ta, MAX_RMEM_MAX,
                                     NULL, "net/core/rmem_max"));

    CHECK_RC(rcf_rpc_server_restart(pco_iut));

    TEST_STEP("Create sockets of @p sock_type type on IUT and Tester.");
    iut_s = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr),
                       rpc_sock_type, RPC_PROTO_DEF);
    tst_s = rpc_socket(pco_tst, rpc_socket_domain_by_addr(tst_addr),
                       rpc_sock_type, RPC_PROTO_DEF);

    TEST_STEP("Set @c SO_RCVBUF on the IUT socket to half of rmem_max.");
    rpc_setsockopt_int(pco_iut, iut_s, RPC_SO_RCVBUF, RCVBUF_SIZE);
    TEST_STEP("Obtain the actual value of @c SO_RCVBUF with getsockopt(), "
              "check that it is not less than the value we set before.");
    rpc_getsockopt(pco_iut, iut_s, RPC_SO_RCVBUF, &opt_val);
    if (opt_val < RCVBUF_SIZE)
    {
        ERROR_VERDICT("getsockopt(SO_RCVBUF) reports value smaller than "
                      "that which was set before.");
    }

    TEST_STEP("Establish connection if required by @p sock_type.");
    sockts_connection(pco_iut, pco_tst, iut_addr, tst_addr, sock_type,
                      FALSE, TRUE, NULL, &iut_s, &tst_s, &iut_listener,
                      SOCKTS_SOCK_FUNC_SOCKET);

    if (rpc_sock_type == RPC_SOCK_DGRAM)
        max_send_size = SOCKTS_MSG_DGRAM_MAX;
    else
        max_send_size = SOCKTS_MSG_STREAM_MAX;

    tapi_pat_sender_init(&sender_ctx);
    sender_ctx.gen_func = RPC_PATTERN_GEN_LCG;
    tapi_rand_gen_set(&sender_ctx.size,
                      max_send_size, max_send_size, 0);
    sender_ctx.duration_sec = TRANSMIT_TIME;
    sender_ctx.total_size = (uint64_t)opt_val * 2LLU;
    sender_ctx.time2wait = TIME2WAIT;

    tapi_pat_receiver_init(&receiver_ctx);
    receiver_ctx.gen_func = RPC_PATTERN_GEN_LCG;
    receiver_ctx.duration_sec = TRANSMIT_TIME;
    receiver_ctx.time2wait = TIME2WAIT;

    pat_arg = &sender_ctx.gen_arg;
    pat_arg->offset = 0;
    pat_arg->coef1 = rand_range(0, RAND_MAX);
    pat_arg->coef2 = rand_range(0, RAND_MAX) | 1;
    memcpy(&receiver_ctx.gen_arg, pat_arg, sizeof(*pat_arg));

    TEST_STEP("Send data from the Tester socket either until no more "
              "data can be sent or until twice the size of @c SO_RCVBUF "
              "on IUT socket was sent.");
    pco_tst->timeout = TE_SEC2MS(TRANSMIT_TIME + 1);
    RPC_AWAIT_ERROR(pco_tst);
    rc = rpc_pattern_sender(pco_tst, tst_s, &sender_ctx);
    if (rc < 0)
    {
        TEST_VERDICT("rpc_pattern_sender() failed with errno %r, this is "
                     "%s sending function failure",
                     RPC_ERRNO(pco_tst),
                     (sender_ctx.send_failed ? "" : "not"));
    }

    TEST_STEP("Receive all the data from the IUT socket.");
    pco_iut->timeout = TE_SEC2MS(TRANSMIT_TIME + 1);
    RPC_AWAIT_ERROR(pco_iut);
    rc = rpc_pattern_receiver(pco_iut, iut_s, &receiver_ctx);
    if (rc < 0)
    {
        TEST_VERDICT("rpc_pattern_receiver() failed with errno %r, this is "
                     "%s receiving function failure",
                     RPC_ERRNO(pco_iut),
                     (receiver_ctx.recv_failed ? "" : "not"));
    }

    if (rpc_sock_type == RPC_SOCK_STREAM &&
        sender_ctx.sent != receiver_ctx.received)
    {
        TEST_VERDICT("Number of bytes received does not match number "
                     "of bytes sent");
    }
    if (receiver_ctx.received == 0)
    {
        TEST_VERDICT("No data was received");
    }

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    CLEANUP_RPC_CLOSE(pco_iut, iut_listener);

    if (onload_run && cfg_backup_name != NULL)
    {
        /*
         * This is done to ensure that configuration is restored in
         * case of --ool=reuse_pco for which IUT RPC server is not
         * automatically restarted.
         */
        CLEANUP_CHECK_RC(cfg_restore_backup(cfg_backup_name));
        CLEANUP_CHECK_RC(rcf_rpc_server_restart(pco_iut));
    }

    TEST_END;
}
